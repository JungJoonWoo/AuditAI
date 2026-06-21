"""파이프라인 오케스트레이션 + runs/<run_id>/ artifact (계획 docs/05-p0-blockers.md §0.2).

평가 순서: S0 diff scope(G1) → detect_frameworks → G2 → S2 taint(CodeQL) → Track B inventory →
resolve_run_status → RunReport. CodeQL 미설치 시 S2 는 실행 안 됨(s2_completed=False) →
"빈 결과를 정상으로 착각" 하지 않고 정직하게 NOT_RUN/ANALYSIS_ERROR 로 보고한다.

workflow control 은 runner(이 모듈)가 소유한다. LLM 은 이 단계를 운전하지 않는다.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from .codeql import codeql_version, unvalidated_frameworks
from .candidates import scan_candidates
from .contracts import (
    AttributionState,
    CandidateInventoryItem,
    FindingReport,
    GateResult,
    RemovedSecurityControlCandidate,
    RiskInventoryItem,
    RunReport,
    TargetType,
    TRACK_B_DISCLOSURE,
    WeakenedControlCandidate,
    resolve_run_status,
)
from .kb import load_kb
from .gates import (
    declared_framework_deps,
    detect_framework_scope,
    gate_g1,
    gate_g2,
    gate_g2_detection_incomplete,
    gate_g3,
    gate_g4,
)
from .scope import (
    DiffScope,
    GitError,
    attribute_added_lines,
    build_diff_scope,
)
from .security_controls import detect_removed_controls, detect_weakened_controls

_RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def _safe_run_dir(runs_dir: Path, run_id: str) -> Path:
    """run_id 경로안전 + 디렉터리 원자적 생성 (codex: ../ 탈출/덮어쓰기 차단 + TOCTOU 제거).

    exists() 확인과 생성을 분리하면 동시 실행에서 충돌을 못 잡으므로(codex Q1 F9),
    `mkdir(exist_ok=False)` 로 검사+생성을 원자화한다.
    """
    if not _RUN_ID_RE.match(run_id):
        raise ValueError(f"invalid run_id: {run_id!r}")
    runs_dir = Path(runs_dir).resolve()
    out = (runs_dir / run_id).resolve()
    if runs_dir not in out.parents:
        raise ValueError(f"run_id escapes runs_dir: {run_id!r}")
    try:
        out.mkdir(parents=True, exist_ok=False)
    except FileExistsError:
        raise FileExistsError(f"run dir already exists (collision): {out}")
    return out


def _inventory_from_removed(c: RemovedSecurityControlCandidate) -> RiskInventoryItem:
    return RiskInventoryItem(
        item_id=c.candidate_id,
        inventory_kind=c.inventory_kind,
        priority=c.priority,
        file=c.file,
        line_or_deleted_line=f"{c.deleted_line_start}-{c.deleted_line_end}",
        evidence=c.deleted_code,
        why_it_matters=c.risk_reason,
    )


def _inventory_from_weakened(c: WeakenedControlCandidate) -> RiskInventoryItem:
    return RiskInventoryItem(
        item_id=c.candidate_id,
        inventory_kind=c.inventory_kind,
        priority=c.priority,
        file=c.file,
        line_or_deleted_line=f"{c.line_start}-{c.line_end}",
        evidence=c.after_code,
        why_it_matters=c.risk_reason,
    )


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _scope_report_md(
    scope: DiffScope, report: RunReport, version_mismatch: tuple[str, str] | None = None,
    disclosure_block: str = "",
) -> str:
    lines = [
        f"# Scope Selection Report — {report.run_id}",
        "",
        f"- target_type: {report.target_type.value}",
        f"- run_status: **{report.run_status.value}** (reliability={report.reliability.value})",
        f"- base..head: {scope.base_sha[:10]}..{scope.head_sha[:10]} (PR commits={scope.pr_commit_count})",
        f"- changed files: {len(scope.files)}",
    ]
    if version_mismatch:
        want, got = version_mismatch
        lines.append(
            f"- ⚠ validation matrix CodeQL 버전 불일치(matrix={want} vs installed={got}) → "
            "G2 검증 매트릭스 무시(NOT_RUN). 매트릭스 재검증 필요."
        )
    lines += ["", "## Gates"]
    for g in report.gate_results:
        lines.append(f"- {g.gate.value}: {g.status.value}" + (f" ({g.code.value})" if g.code else ""))
    lines += [
        "",
        "## Track B risk inventory (NOT auto-confirmed)",
        f"- items: {len(report.risk_inventory)}",
        "",
        disclosure_block or f"> {TRACK_B_DISCLOSURE}",  # gate_g4 가 검증한 동일 블록
    ]
    return "\n".join(lines) + "\n"


def run_pipeline(
    repo: str,
    base: str,
    head: str,
    *,
    run_id: str,
    target_type: TargetType,
    eval_targets: list[str],
    runs_dir: str | Path,
    validation_matrix: dict[str, bool] | None = None,
    validation_codeql_version: str | None = None,
    frameworks: set[str] | None = None,
    s2_findings: list[FindingReport] | None = None,
    run_codeql: bool = False,
    track_a_required: bool = True,
) -> RunReport:
    """전체 파이프라인 실행 + artifact 기록. RunReport 반환.

    validation_matrix: {framework: validated_bool} — G2 framework source model 검증 매트릭스
      (codeql.default_validation_matrix() 또는 --codeql-validation 입력). None 이면 G2 NOT_RUN.
    validation_codeql_version: 그 매트릭스가 검증된 CodeQL 버전. 설치된 CodeQL 버전과 다르면
      매트릭스 신뢰 불가 → G2 NOT_RUN 으로 강등(codex Q1r2 [상]: 버전 결합, 거짓 정직성 방지).
    frameworks: 명시 입력(없으면 diff+repo-wide grep 탐지).
    s2_findings: 외부 제공 S2(Track A) 결과. 제공되면(빈 리스트 포함) S2 완료로 간주.
    run_codeql: True 면 CodeQL CLI 가 있을 때 Track A taint 를 실제로 실행(P0-3b).
      s2_completed 는 **파생값**이다 — 외부 s2_findings 제공 또는 run_codeql 성공일 때만 True
      (codex Q1 F3: 사전 주장 + 런타임 실패로 빈 findings 가 NO_VULN 으로 오독되는 우회 제거).
    """
    if run_codeql and s2_findings is not None:
        raise ValueError("run_codeql=True 와 s2_findings 는 상호배타(단일 S2 소스만 지정)")
    out_dir = _safe_run_dir(Path(runs_dir), run_id)

    # 검증 매트릭스 버전 가드(codex Q1r3 R3-1, fail-closed): 매트릭스는 특정 CodeQL 버전 검증본.
    # 신뢰 조건 = 버전 명시 AND 설치 CodeQL 버전을 확인 AND 정확히 일치. 하나라도 어긋나면
    # 매트릭스를 폐기(None→G2 NOT_RUN). '버전 없는 매트릭스'/'설치버전 미상'을 신뢰 입력으로 쓰지 않는다.
    effective_matrix = validation_matrix
    version_mismatch: tuple[str, str] | None = None
    if validation_matrix is not None:
        installed_ver = codeql_version()
        if (validation_codeql_version is None or installed_ver is None
                or installed_ver != validation_codeql_version):
            effective_matrix = None
            version_mismatch = (validation_codeql_version or "<none>",
                                installed_ver or "<not-installed>")
    # 빈 매트릭스({})는 검증 산출물로 신뢰할 근거가 없음 → None(NOT_RUN) (codex Q1r4 R4-3).
    if effective_matrix is not None and not effective_matrix:
        effective_matrix = None

    if s2_findings is not None:
        findings: list[FindingReport] = list(s2_findings)
        s2_completed = True   # 외부 S2 결과 제공됨
    else:
        findings = []
        s2_completed = False  # run_codeql 성공 시에만 아래에서 True

    # --- S0 / G1 ---
    try:
        scope = build_diff_scope(repo, base, head)
        g1 = gate_g1(True)
        # S0 (codex MVP r2 C2/M1): added .py 라인을 head blame 으로 AI 귀속. blame 실패 파일은
        # UNKNOWN(completed=False) → resolver 가 clean 으로 빠지지 않게(fail-closed 입력).
        added_attr = attribute_added_lines(repo, scope)
    except GitError as e:
        g1 = gate_g1(False)
        status, rel = resolve_run_status(
            target_type=target_type, gate_results=[g1],
            s2_completed=False, finding_count=0, risk_inventory_count=0,
            track_a_required=track_a_required,  # codex Q2r3: 메타 보존(거짓 기록 방지)
        )
        report = RunReport(
            run_id=run_id, target_type=target_type, run_status=status, reliability=rel,
            s2_completed=False, track_a_required=track_a_required, gate_results=[g1],
            # codex MVP S0 M3: G1 실패 = 후속 단계 미실행 → 메타도 정직하게 not-run(완료 아님).
            s0_attribution_completed=False, s3_completed=False,
        )
        # 실패 경로도 **동일 7종 artifact 세트** (codex Q2 R2-1: diff 의존 4종도 빈 stub 으로 기록 —
        # acceptance #9 "artifact → runs/<id>/" 가 성공/실패 경로 모두에서 일관).
        _write(out_dir / "run_report.json", report.model_dump_json(indent=2))
        _write(out_dir / "gate_results.json",
               json.dumps([g1.model_dump(mode="json")], indent=2))
        _write(out_dir / "diff_scope.json",
               json.dumps({"error": str(e), "files": [], "note": "G1 fail — diff scope 산출 실패"},
                          indent=2))
        # codex MVP S0 M4: 성공 경로와 동일 스키마(소비자 안정) — 빈 값 + error.
        _write(out_dir / "ai_attribution.json", json.dumps(
            {"completed": False, "summary": [], "attributions": [], "error": str(e)}, indent=2))
        _write(out_dir / "deleted_security_controls.jsonl", "")
        _write(out_dir / "weakened_controls.jsonl", "")
        _write(out_dir / "scope_selection_report.md",
               f"# Scope Selection Report — {run_id}\n\n- run_status: **{status.value}**\n"
               f"- G1: {g1.status.value} ({g1.code.value if g1.code else ''})\n- error: {e}\n\n"
               f"> {TRACK_B_DISCLOSURE}\n")
        return report

    # --- 프레임워크 탐지 / G2 (codex Q1 F1/F4: 매트릭스 기반 per-framework) ---
    # codex Q1r4 R4-1: 명시 `frameworks` 입력은 탐지결과에 'union'(ADD 만, 숨김 불가)한다 —
    #   frameworks=set()/부분집합으로 G2 SKIPPED 를 강제하는 fail-open 차단. 탐지는 항상 실행.
    # codex Q1r3 R3-3: detect_framework_scope 의 repo-wide grep 장애는 fail-closed → G2 NOT_RUN.
    #
    # codex G2 over-flag 판정(2026-06): G2 스코프 = "변경 파일(AI-authored) framework" primary.
    #   - case A(framework 없는 변경 .py 없음): 변경 framework 로만 검증 — repo 다른 곳의 transitive
    #     import(FastAPI repo 내부 Starlette 등)으로 over-flag(false MODEL_MISSING) 하지 않는다.
    #   - case B(framework 없는 변경 .py 존재 = helper-only/혼합 PR): repo-wide + dep-fallback 로
    #     under-detection 방지 보강(그 helper 가 미검증 framework 라우트로 흘러갈 수 있으므로 — 보강이
    #     미검증 framework 를 잡으면 그때 NOT_RUN/MODEL_MISSING).
    detection_reason: str | None = None
    try:
        fscope = detect_framework_scope(repo, scope)
    except GitError:
        fscope = None
        detection_reason = "repo-wide framework detection failed (git grep/show)"
    if fscope is None:
        detected: set[str] = set()
    elif fscope.needs_repo_wide_fallback:
        # case B(frameworkless 변경 .py) 또는 불확실성(parse 실패/변수 동적 import, codex r2 #2):
        # 변경 framework + repo-wide 보강 + dep-fallback 활성. 단 불확실성은 '보강 트리거'일 뿐
        # (codex r3 #3) — 해소될 때만 차단: dep-fallback(declared-but-not-imported) → fail-closed NOT_RUN,
        # repo-wide 가 미검증 framework 탐지 → G2 hard fail MODEL_MISSING. 해소 안 되는 순수 변수 동적
        # import 는 MVP 미탐지(README ⑥/⑧).
        detected = fscope.changed | fscope.repo_wide
        declared = declared_framework_deps(repo, scope.head_sha)
        # 의존성 fallback(codex Q1r5 R5-1): 매니페스트 선언됐는데 어떤 import 로도 '탐지' 안 됨 →
        # 동적/난독화 import 가능성 → 탐지 미완료 fail-closed(false NO_VULN 금지).
        # codex Q1r6 R6-1: detected 와 비교(fw 아님) — 명시 frameworks 입력으로 신호를 지울 수 없게.
        if declared - detected:
            detection_reason = (
                f"declared framework dependency not detected in imports: {sorted(declared - detected)}"
            )
        # codex r7 #2: repo-wide 후보(framework 토큰 보유) 파일 parse 실패 → 확인 불가 → fail-closed.
        elif fscope.repo_wide_incomplete:
            detection_reason = "repo-wide framework detection incomplete (candidate file parse failed)"
    else:
        # case A: 모든 변경 .py 가 framework 귀속 + 불확실성 없음 → 변경 파일 framework 로만 스코프
        # (repo-wide/dep 무시 — transitive 의존 over-flag 방지).
        detected = fscope.changed
    fw = detected | (frameworks or set())
    if detection_reason is not None:
        g2 = gate_g2_detection_incomplete(target_type, detection_reason)
    else:
        unval = unvalidated_frameworks(fw, effective_matrix)  # matrix None/버전불일치 → None(NOT_RUN)
        g2 = gate_g2(frameworks=fw, unvalidated=unval, target_type=target_type)
    g3 = gate_g3(eval_targets)
    # G4(codex Q2 R2-6): 실제 report 에 들어갈 고지 블록을 gate 가 검증(형식 통과 아님). 같은
    # disclosure_block 을 _scope_report_md 에 그대로 임베드 → 게이트가 검증한 텍스트=실제 artifact.
    disclosure_block = f"> {TRACK_B_DISCLOSURE}"
    g4 = gate_g4(disclosure_block)
    gates: list[GateResult] = [g1, g2, g3, g4]

    # --- Track A taint (실제 CodeQL, P0-3b) ---
    if run_codeql:
        from .codeql import (
            codeql_available,
            filter_findings_to_ai_lines,
            run_track_a,
        )

        # codex Q5-5/6/Q5r2/Q5r3: CodeQL 단계 도달 시(G1 통과 후) 설치 여부·빌드/분석 실패와 무관하게
        # 진단 artifact 를 남긴다. (G1 실패는 CodeQL 미시도이므로 이 단계에 도달하지 않음.)
        codeql_status: dict = {}
        if codeql_available():
            raw = run_track_a(repo, str(out_dir / "codeql_db"), status=codeql_status)
            if raw is not None:
                # AI 귀속 라인 교차만 (01 C1 heuristic_positive_only). codex MVP S0: '모든 added'가 아니라
                # **AI-귀속 added 라인**(confirmed/probable)으로 정직화. UNKNOWN(귀속 불확실)은 fail-open
                # 방지를 위해 포함(scan), HUMAN-귀속 added 라인만 제외(AI 코드 only 약속). (UNKNOWN+KB sink
                # 의 정밀 fail-closed 카운트는 S1 단계에서 unknown_sink_candidate_count 로 배선.)
                ai_lines: dict[str, set[int]] = {}
                for f, lns in added_attr.ai_lines.items():
                    ai_lines.setdefault(f, set()).update(lns)
                for f, lns in added_attr.unknown_lines.items():
                    ai_lines.setdefault(f, set()).update(lns)
                findings = filter_findings_to_ai_lines(raw, ai_lines)
                s2_completed = True
        else:
            codeql_status = {"stage": "find", "error": "codeql not found (run_codeql requested)"}
        _write(out_dir / "codeql_status.json", json.dumps(codeql_status, indent=2))

    # --- S1 candidate discovery (known-KB AST seed scanner) ---
    # codex MVP r2 C2/S0 C1: UNKNOWN-귀속 KB sink → candidate_inventory + unknown_sink_candidate_count
    #   (fail-closed). AI-귀속 TAINT_PATH 후보는 S2(다음 단계) 대상이나, 아직 S2 미배선이라 evidence 전이라
    #   inventory 로 표면화(드롭 금지 — clean 오독 방지). S2 단계에서 evidence 경로로 전환.
    scan = scan_candidates(repo, scope, added_attr, load_kb())
    candidate_inventory: list[CandidateInventoryItem] = list(scan.candidate_inventory)
    for c in scan.taint_candidates:
        candidate_inventory.append(CandidateInventoryItem(
            candidate_id=c.candidate_id, candidate_type=c.candidate_type, file=c.file,
            line=c.sink_span.start_line if c.sink_span else 0, sink_span=c.sink_span,
            capability_id=c.capability_id, sink_spec_id=c.sink_spec_id,
            reason=f"taint_path candidate pending S2 evidence: {c.sink_spec_id}",
            ai_attribution_state=(c.ai_attribution_refs[0].attribution_state
                                  if c.ai_attribution_refs else AttributionState.PROBABLE_AI),
        ))

    # --- Track B inventory (diff 기반, CodeQL 불필요) ---
    removed = detect_removed_controls(repo, scope)
    weakened = detect_weakened_controls(repo, scope)
    risk_inventory = [_inventory_from_removed(c) for c in removed] + [
        _inventory_from_weakened(c) for c in weakened
    ]

    status, rel = resolve_run_status(
        target_type=target_type, gate_results=gates,
        s2_completed=s2_completed, finding_count=len(findings),
        risk_inventory_count=len(risk_inventory),
        track_a_required=track_a_required,
        s0_attribution_completed=added_attr.completed,
        unknown_sink_candidate_count=scan.unknown_sink_candidate_count,
        candidate_inventory_count=len(candidate_inventory),
    )
    report = RunReport(
        run_id=run_id, target_type=target_type, run_status=status, reliability=rel,
        s2_completed=s2_completed, track_a_required=track_a_required, gate_results=gates,
        findings=findings, risk_inventory=risk_inventory,
        s0_attribution_completed=added_attr.completed,
        unknown_sink_candidate_count=scan.unknown_sink_candidate_count,
        candidate_inventory=candidate_inventory,
    )

    # --- artifacts ---
    _write(out_dir / "diff_scope.json", scope.model_dump_json(indent=2))
    _write(
        out_dir / "ai_attribution.json",
        json.dumps(
            {
                "completed": added_attr.completed,
                "summary": [
                    {
                        "file": f.file,
                        "added": len(f.added_lines),
                        "ai": len(added_attr.ai_lines.get(f.file, set())),
                        "unknown": len(added_attr.unknown_lines.get(f.file, set())),
                        "human": len(added_attr.human_lines.get(f.file, set())),
                    }
                    for f in scope.files
                ],
                "attributions": [a.model_dump(mode="json") for a in added_attr.attributions],
            },
            indent=2,
        ),
    )
    _write(
        out_dir / "deleted_security_controls.jsonl",
        "\n".join(c.model_dump_json() for c in removed),
    )
    _write(
        out_dir / "weakened_controls.jsonl",
        "\n".join(c.model_dump_json() for c in weakened),
    )
    _write(
        out_dir / "candidates.jsonl",
        "\n".join(c.model_dump_json() for c in scan.candidates),
    )
    # codex S1 중: UNKNOWN inventory 가 candidates.jsonl 에 안 들어가므로 별도 artifact 로 보존.
    _write(
        out_dir / "candidate_inventory.jsonl",
        "\n".join(c.model_dump_json() for c in candidate_inventory),
    )
    _write(
        out_dir / "gate_results.json",
        json.dumps([g.model_dump(mode="json") for g in gates], indent=2),
    )
    _write(out_dir / "run_report.json", report.model_dump_json(indent=2))
    _write(out_dir / "scope_selection_report.md",
           _scope_report_md(scope, report, version_mismatch, disclosure_block))
    return report
