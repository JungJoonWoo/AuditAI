"""파이프라인 오케스트레이션 (run.py) 테스트 — verdict-C full switch 반영.

verdict-C(docs/CODEX_VERIFICATION_QUEUE s2integ): run_pipeline 은 S0→S4 를 `pipeline.run_stages` 에
위임하고 finding 은 **judged S4 finding** 만 권위로 둔다. 외부 direct findings(s2_findings)는 비권위
legacy artifact 로만 남고 status 에 영향을 주지 않는다.

테스트 결정성: 실 LLM CLI 가 PATH 에 있어도 호출하지 않도록 모든 케이스가 `engine=None` 을 주입한다
(S3 전원 SKIPPED → eligible 0 이면 영향 없음, eligible>0 이면 SEMANTIC_JUDGE_NOT_RUN 으로 fail-closed).
실 CodeQL 미설치 환경에선 S2 가 partial → s2_completed=False 이므로, 과거 s2_findings=[] 로 위장하던
'S2 완료' 는 더 이상 성립하지 않는다(검증 매트릭스/G2 hard-fail 은 s2 보다 precedence 가 높아 불변).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from auditai.codeql import codeql_available, codeql_version
from auditai.contracts import RunStatus, TargetType
from auditai.judge import FakeEngine
from auditai.run import run_pipeline
from auditai.scope import GitError


def _valid_judge_json(verdict="likely_risk"):
    return json.dumps({"verdict": verdict, "reason": "unsanitized input reaches sink",
                       "confidence": 0.7, "sanitizer_sufficient": False})


def test_pipeline_no_codeql_is_not_clean(diff_repo: Path, tmp_path: Path):
    """CodeQL 미설치(S2 미실행) → NO_VULN_FOUND 로 착각 금지. 단 Track B inventory 는 산출."""
    report = run_pipeline(
        str(diff_repo), "HEAD~1", "HEAD",
        run_id="r1", target_type=TargetType.SYNTHETIC,
        eval_targets=["owasp_sourced"], runs_dir=tmp_path, engine=None,
        # run_codeql 없음 → stage_s2 partial → s2_completed=False
    )
    # 빈 결과를 정상으로 보고하지 않는다
    assert report.run_status != RunStatus.NO_VULN_FOUND
    # diff_repo 는 framework 미사용 → G2 skip → s2 미완료 → ANALYSIS_ERROR
    assert report.run_status == RunStatus.ANALYSIS_ERROR
    # Track B: 삭제된 authz 가드가 inventory 에 있어야 함
    assert report.risk_inventory
    # artifacts 기록 확인 (RunReport 계열 + stage 경계 아티팩트)
    out = tmp_path / "r1"
    assert (out / "run_report.json").exists()
    assert (out / "diff_scope.json").exists()
    assert (out / "deleted_security_controls.jsonl").read_text(encoding="utf-8").strip()
    assert (out / "scope_selection_report.md").exists()
    # verdict-C: stage 경계 아티팩트도 영속화돼 단독 재개 가능
    assert (out / "s0_attribution.json").exists()
    assert (out / "s1_candidates.json").exists()


def test_pipeline_external_s2_findings_are_legacy_non_authoritative(diff_repo: Path, tmp_path: Path):
    """verdict-C(s2integ): 외부 direct findings(s2_findings)는 더 이상 RunReport.findings/status 를
    채우지 않는다 — legacy_codeql_findings.jsonl 비권위 artifact 로만 남고 s2_completed 도 안 켠다.

    (과거: s2_findings=[] → s2_completed=True → FINDINGS_PRESENT. 이제: track_a_required 기본 True 라
    s2 미완료 → ANALYSIS_ERROR; legacy findings 는 status 에 무관.)"""
    from auditai.contracts import FindingReport

    legacy = [FindingReport(finding_id="L1", title="legacy", severity="high", cwe="CWE-78",
                            file="app.py", line=3)]
    report = run_pipeline(
        str(diff_repo), "HEAD~1", "HEAD",
        run_id="r2", target_type=TargetType.SYNTHETIC,
        eval_targets=["owasp_sourced"], runs_dir=tmp_path, engine=None,
        s2_findings=legacy,  # 비권위 — status 영향 0
    )
    # finding 은 S4(judged)에서만 — legacy direct finding 은 RunReport.findings 에 안 들어감
    assert report.findings == []
    assert report.s2_completed is False           # legacy 가 s2_completed 를 켜지 않음
    assert report.run_status == RunStatus.ANALYSIS_ERROR
    # legacy artifact 는 비권위 진단으로 기록됨
    legacy_path = tmp_path / "r2" / "legacy_codeql_findings.jsonl"
    assert legacy_path.exists() and legacy_path.read_text(encoding="utf-8").strip()


def test_pipeline_track_b_only_surfaces_inventory(diff_repo: Path, tmp_path: Path):
    """track_a_required=False(Track-B-only) + Track B inventory + S1 후보 → FINDINGS_PRESENT(unreliable)."""
    report = run_pipeline(
        str(diff_repo), "HEAD~1", "HEAD",
        run_id="r2b", target_type=TargetType.SYNTHETIC,
        eval_targets=["owasp_sourced"], runs_dir=tmp_path, engine=None,
        track_a_required=False,
    )
    assert report.run_status == RunStatus.FINDINGS_PRESENT
    assert report.reliability.value == "unreliable"  # taint 미실행
    assert report.risk_inventory


def test_pipeline_phoenix_only_eval_fails(diff_repo: Path, tmp_path: Path):
    """G3: phoenix smoke 단독 eval → EVAL_TARGET_INSUFFICIENT (track_a_required=False 라 G3 까지 도달)."""
    report = run_pipeline(
        str(diff_repo), "HEAD~1", "HEAD",
        run_id="r3", target_type=TargetType.SMOKE,
        eval_targets=["phoenix_smoke"], runs_dir=tmp_path, engine=None,
        track_a_required=False,
    )
    assert report.run_status == RunStatus.EVAL_TARGET_INSUFFICIENT


def test_run_codeql_and_s2_findings_mutually_exclusive(diff_repo: Path, tmp_path: Path):
    """codex Q1 F3: run_codeql=True 와 외부 s2_findings 동시 지정은 모순 → ValueError."""
    with pytest.raises(ValueError):
        run_pipeline(
            str(diff_repo), "HEAD~1", "HEAD",
            run_id="rs", target_type=TargetType.SYNTHETIC,
            eval_targets=["owasp_sourced"], runs_dir=tmp_path,
            run_codeql=True, s2_findings=[], engine=None,
        )


def test_pipeline_framework_without_validation_hard_fails(fastapi_pr_repo: Path, tmp_path: Path):
    """codex Q1 F1/F2: FastAPI 자동탐지 + 검증 매트릭스 없음 → G2 NOT_RUN(hard fail).

    frameworks=set() 우회 없이 실제 detect_frameworks 경로로 G2 가 동작함을 증명(빈 결과 오독 금지).
    G2 hard-fail 은 s2 precedence 보다 높아 verdict-C 에서도 불변.
    """
    report = run_pipeline(
        str(fastapi_pr_repo), "HEAD~1", "HEAD",
        run_id="fwnoval", target_type=TargetType.SYNTHETIC,
        eval_targets=["owasp_sourced"], runs_dir=tmp_path, engine=None,
        validation_matrix=None,  # 검증 매트릭스 미제공
    )
    assert report.run_status == RunStatus.FRAMEWORK_SOURCE_VALIDATION_NOT_RUN


def test_pipeline_framework_unvalidated_model_missing(
    fastapi_pr_repo: Path, tmp_path: Path, monkeypatch
):
    """검증 매트릭스가 해당 프레임워크를 미검증(False)으로 표기 → FRAMEWORK_SOURCE_MODEL_MISSING."""
    monkeypatch.setattr("auditai.run.codeql_version", lambda *a, **k: "2.25.6")
    report = run_pipeline(
        str(fastapi_pr_repo), "HEAD~1", "HEAD",
        run_id="fwmiss", target_type=TargetType.SYNTHETIC,
        eval_targets=["owasp_sourced"], runs_dir=tmp_path, engine=None,
        validation_matrix={"fastapi": False},  # source model 미검증으로 표기
        validation_codeql_version="2.25.6",     # 버전 일치(가드 통과) → 매트릭스 적용
    )
    assert report.run_status == RunStatus.FRAMEWORK_SOURCE_MODEL_MISSING


def test_pipeline_explicit_empty_frameworks_cannot_bypass_g2(fastapi_pr_repo: Path, tmp_path: Path):
    """codex Q1r4 R4-1: frameworks=set() 명시 입력으로 G2 SKIPPED 를 강제할 수 없다(union, ADD만).

    탐지가 fastapi 를 잡으므로 매트릭스 없으면 NOT_RUN(hard fail) — 빈 S2 가 NO_VULN 으로 승격 금지."""
    report = run_pipeline(
        str(fastapi_pr_repo), "HEAD~1", "HEAD",
        run_id="emptyfw", target_type=TargetType.SYNTHETIC,
        eval_targets=["owasp_sourced"], runs_dir=tmp_path, engine=None,
        frameworks=set(),     # 빈 set 으로 탐지 우회 시도
    )
    assert report.run_status == RunStatus.FRAMEWORK_SOURCE_VALIDATION_NOT_RUN


def test_pipeline_declared_but_not_imported_is_fail_closed(
    declared_not_imported_repo: Path, tmp_path: Path
):
    """codex Q1r5 R5-1: framework 가 의존성에 선언됐는데 어떤 import 로도 못 찾음(난독화 동적 등)
    → 탐지 미완료 → fail-closed G2 NOT_RUN(빈 S2 가 NO_VULN 으로 승격 금지)."""
    report = run_pipeline(
        str(declared_not_imported_repo), "HEAD~1", "HEAD",
        run_id="declfc", target_type=TargetType.SYNTHETIC,
        eval_targets=["owasp_sourced"], runs_dir=tmp_path, engine=None,
    )
    assert report.run_status == RunStatus.FRAMEWORK_SOURCE_VALIDATION_NOT_RUN
    # codex Q1r8 R8-3: 진단 문구가 dep mismatch 원인을 정직히 기록(grep 장애와 구분)
    g2 = next(g for g in report.gate_results if g.gate.value == "G2")
    assert "declared framework dependency not detected" in g2.message


def test_pipeline_explicit_framework_cannot_clear_dep_fallback(
    declared_not_imported_repo: Path, tmp_path: Path, monkeypatch
):
    """codex Q1r6 R6-1: --framework 명시로 'declared but not imported' fail-closed 신호를 지울 수 없다."""
    monkeypatch.setattr("auditai.run.codeql_version", lambda *a, **k: "2.25.6")
    report = run_pipeline(
        str(declared_not_imported_repo), "HEAD~1", "HEAD",
        run_id="explbypass", target_type=TargetType.SYNTHETIC,
        eval_targets=["owasp_sourced"], runs_dir=tmp_path, engine=None,
        frameworks={"fastapi"},                     # 명시 입력으로 우회 시도
        validation_matrix={"fastapi": True}, validation_codeql_version="2.25.6",
    )
    assert report.run_status == RunStatus.FRAMEWORK_SOURCE_VALIDATION_NOT_RUN


def test_pipeline_matrix_without_version_not_trusted(
    fastapi_pr_repo: Path, tmp_path: Path, monkeypatch
):
    """codex Q1r3 R3-1: 버전 없는 매트릭스는 신뢰 입력 아님 → fail-closed G2 NOT_RUN."""
    monkeypatch.setattr("auditai.run.codeql_version", lambda *a, **k: "2.25.6")
    report = run_pipeline(
        str(fastapi_pr_repo), "HEAD~1", "HEAD",
        run_id="noverm", target_type=TargetType.SYNTHETIC,
        eval_targets=["owasp_sourced"], runs_dir=tmp_path, engine=None,
        validation_matrix={"fastapi": True},   # 검증됐다 주장하지만
        validation_codeql_version=None,         # 버전 미상 → 신뢰 불가
    )
    assert report.run_status == RunStatus.FRAMEWORK_SOURCE_VALIDATION_NOT_RUN


def test_pipeline_detection_failure_is_fail_closed(
    fastapi_pr_repo: Path, tmp_path: Path, monkeypatch
):
    """codex Q1r3 R3-3: repo-wide grep 실제 장애 → 탐지 미완료 → fail-closed G2 NOT_RUN(빈 결과 오독 금지)."""
    def _boom(*a, **k):
        raise GitError("simulated git grep failure")

    monkeypatch.setattr("auditai.run.detect_framework_scope", _boom)
    report = run_pipeline(
        str(fastapi_pr_repo), "HEAD~1", "HEAD",
        run_id="detfail", target_type=TargetType.SYNTHETIC,
        eval_targets=["owasp_sourced"], runs_dir=tmp_path, engine=None,
    )
    assert report.run_status == RunStatus.FRAMEWORK_SOURCE_VALIDATION_NOT_RUN


# --- G2 over-flag 판정 확정 설계: 파이프라인 레벨 G2 상태 ----------------------- #
def test_pipeline_internal_starlette_does_not_over_flag(
    fastapi_internal_starlette_repo: Path, tmp_path: Path, monkeypatch
):
    """codex G2 over-flag #1: 변경 파일이 fastapi(검증됨)만 import + repo 내부 starlette(transitive)
    → case A 스코프={fastapi} → G2 PASS, MODEL_MISSING over-flag 없음. (실 FastAPI repo 사용성 회복.)"""
    monkeypatch.setattr("auditai.run.codeql_version", lambda *a, **k: "2.25.6")
    report = run_pipeline(
        str(fastapi_internal_starlette_repo), "HEAD~1", "HEAD",
        run_id="noverflag", target_type=TargetType.SYNTHETIC,
        eval_targets=["owasp_sourced"], runs_dir=tmp_path, engine=None,
        validation_matrix={"fastapi": True},  # fastapi 검증, starlette 미등록(=미검증)
        validation_codeql_version="2.25.6",
        track_a_required=False,  # Track-B-only: S1 후보를 inventory 로 노출(s2 미실행이므로)
    )
    assert report.run_status != RunStatus.FRAMEWORK_SOURCE_MODEL_MISSING
    g2 = next(g for g in report.gate_results if g.gate.value == "G2")
    assert g2.status.value == "pass"  # starlette 무시, fastapi 검증됨 → PASS(over-flag 없음)
    # S1(known-KB AST seed)이 planted subprocess(shell=True)=CWE-78 sink 를 AI 라인에서 후보로 잡아
    # candidate_inventory 표면화 → FINDINGS_PRESENT. G2 over-flag 핵심은 'G2 PASS·MODEL_MISSING 아님'.
    assert report.run_status == RunStatus.FINDINGS_PRESENT
    assert report.candidate_inventory  # S1 sink 후보 존재


def test_pipeline_helper_only_keeps_repo_wide_model_missing(
    starlette_helper_only_repo: Path, tmp_path: Path, monkeypatch
):
    """codex G2 over-flag #2: helper-only PR(framework 없는 변경 .py) → repo-wide 가 미검증 starlette
    를 잡아 MODEL_MISSING(under-detection 차단 — G2 hard fail/unreliable 유지)."""
    monkeypatch.setattr("auditai.run.codeql_version", lambda *a, **k: "2.25.6")
    report = run_pipeline(
        str(starlette_helper_only_repo), "HEAD~1", "HEAD",
        run_id="helperonly", target_type=TargetType.SYNTHETIC,
        eval_targets=["owasp_sourced"], runs_dir=tmp_path, engine=None,
        validation_matrix={"fastapi": True},  # starlette 미검증
        validation_codeql_version="2.25.6",
    )
    assert report.run_status == RunStatus.FRAMEWORK_SOURCE_MODEL_MISSING


def test_pipeline_mixed_pr_keeps_repo_wide_model_missing(
    mixed_fastapi_helper_starlette_repo: Path, tmp_path: Path, monkeypatch
):
    """codex G2 over-flag #3(제안 구멍 차단): fastapi 변경 파일 + frameworkless helper 혼합 PR →
    "framework 없는 변경 .py 존재" 트리거로 case B 유지 → repo-wide starlette → MODEL_MISSING."""
    monkeypatch.setattr("auditai.run.codeql_version", lambda *a, **k: "2.25.6")
    report = run_pipeline(
        str(mixed_fastapi_helper_starlette_repo), "HEAD~1", "HEAD",
        run_id="mixedpr", target_type=TargetType.SYNTHETIC,
        eval_targets=["owasp_sourced"], runs_dir=tmp_path, engine=None,
        validation_matrix={"fastapi": True},  # starlette 미검증
        validation_codeql_version="2.25.6",
    )
    assert report.run_status == RunStatus.FRAMEWORK_SOURCE_MODEL_MISSING


def test_pipeline_var_dynamic_import_with_declared_dep_is_fail_closed(
    fastapi_var_dynamic_starlette_repo: Path, tmp_path: Path, monkeypatch
):
    """codex G2 over-flag r2 #2 / r3 #3: 변경 파일이 fastapi(검증됨) import + 변수 동적 import 로 미검증
    starlette 를 끌어옴(정적 미탐지) + starlette **declared** → dep-fallback 해소 → fail-closed NOT_RUN."""
    monkeypatch.setattr("auditai.run.codeql_version", lambda *a, **k: "2.25.6")
    report = run_pipeline(
        str(fastapi_var_dynamic_starlette_repo), "HEAD~1", "HEAD",
        run_id="vardynscan", target_type=TargetType.SYNTHETIC,
        eval_targets=["owasp_sourced"], runs_dir=tmp_path, engine=None,
        validation_matrix={"fastapi": True},  # fastapi 검증돼도
        validation_codeql_version="2.25.6",
    )
    assert report.run_status == RunStatus.FRAMEWORK_SOURCE_VALIDATION_NOT_RUN
    g2 = next(g for g in report.gate_results if g.gate.value == "G2")
    assert "declared framework dependency not detected" in g2.message


def test_pipeline_repo_wide_unparseable_candidate_is_fail_closed(
    helper_only_unparseable_candidate_repo: Path, tmp_path: Path, monkeypatch
):
    """codex G2 over-flag r7 #2: case B 에서 repo-wide 후보(framework 토큰 보유) 파일이 parse 불가 →
    repo_wide_incomplete → detection-incomplete → NOT_RUN(확인 불가를 빈 결과로 두지 않음)."""
    monkeypatch.setattr("auditai.run.codeql_version", lambda *a, **k: "2.25.6")
    report = run_pipeline(
        str(helper_only_unparseable_candidate_repo), "HEAD~1", "HEAD",
        run_id="unparsescan", target_type=TargetType.SYNTHETIC,
        eval_targets=["owasp_sourced"], runs_dir=tmp_path, engine=None,
        validation_matrix={"fastapi": True}, validation_codeql_version="2.25.6",
    )
    assert report.run_status == RunStatus.FRAMEWORK_SOURCE_VALIDATION_NOT_RUN
    g2 = next(g for g in report.gate_results if g.gate.value == "G2")
    assert "incomplete" in g2.message


def test_pipeline_unresolved_uncertain_is_not_self_fail_closed(
    fastapi_var_dynamic_no_dep_repo: Path, tmp_path: Path, monkeypatch
):
    """codex G2 over-flag r3 #3 ((B) 계약 잠금): 변수 동적 import 가 있어도 해소할 게 없으면 불확실성
    신호 자체는 NOT_RUN 을 만들지 않는다 — G2 는 fastapi(검증됨)만으로 PASS.

    verdict-C: S2 미실행이라 최종 status 는 ANALYSIS_ERROR(track_a_required 기본 True). G2 PASS 가 핵심."""
    monkeypatch.setattr("auditai.run.codeql_version", lambda *a, **k: "2.25.6")
    report = run_pipeline(
        str(fastapi_var_dynamic_no_dep_repo), "HEAD~1", "HEAD",
        run_id="vardynnodepscan", target_type=TargetType.SYNTHETIC,
        eval_targets=["owasp_sourced"], runs_dir=tmp_path, engine=None,
        validation_matrix={"fastapi": True}, validation_codeql_version="2.25.6",
    )
    g2 = next(g for g in report.gate_results if g.gate.value == "G2")
    assert g2.status.value == "pass"  # fastapi 검증됨, 해소할 미검증 framework 없음
    # S2 미실행(run_codeql 없음) → ANALYSIS_ERROR. (과거 s2_findings=[] 위장으로 NO_VULN 이던 자리)
    assert report.run_status == RunStatus.ANALYSIS_ERROR


def test_validation_matrix_codeql_version_mismatch_downgrades(
    fastapi_pr_repo: Path, tmp_path: Path, monkeypatch
):
    """codex Q1r2 [상]: 매트릭스 검증 버전 != 설치 CodeQL 버전 → 매트릭스 무시(NOT_RUN). 거짓 정직성 방지."""
    monkeypatch.setattr("auditai.run.codeql_version", lambda *a, **k: "9.9.9")
    report = run_pipeline(
        str(fastapi_pr_repo), "HEAD~1", "HEAD",
        run_id="vermis", target_type=TargetType.SYNTHETIC,
        eval_targets=["owasp_sourced"], runs_dir=tmp_path, engine=None,
        validation_matrix={"fastapi": True},   # fastapi 검증됨이라 주장하지만
        validation_codeql_version="2.25.6",     # 매트릭스는 2.25.6 기준 → 설치 9.9.9 와 불일치
    )
    assert report.run_status == RunStatus.FRAMEWORK_SOURCE_VALIDATION_NOT_RUN
    # 불일치 사유가 artifact 에 기록됨
    md = (tmp_path / "vermis" / "scope_selection_report.md").read_text(encoding="utf-8")
    assert "버전 불일치" in md and "2.25.6" in md


def test_validation_matrix_codeql_version_match_keeps_matrix(
    fastapi_pr_repo: Path, tmp_path: Path, monkeypatch
):
    """버전 일치 → 매트릭스 유지 → fastapi G2 PASS (s2 미실행이라 최종은 ANALYSIS_ERROR)."""
    from auditai.contracts import GateId, GateStatus

    monkeypatch.setattr("auditai.run.codeql_version", lambda *a, **k: "2.25.6")
    report = run_pipeline(
        str(fastapi_pr_repo), "HEAD~1", "HEAD",
        run_id="verok", target_type=TargetType.SYNTHETIC,
        eval_targets=["owasp_sourced"], runs_dir=tmp_path, engine=None,
        validation_matrix={"fastapi": True}, validation_codeql_version="2.25.6",
    )
    g2 = next(g for g in report.gate_results if g.gate == GateId.G2)
    assert g2.status == GateStatus.PASS                       # 매트릭스 적용됨
    assert report.run_status == RunStatus.ANALYSIS_ERROR      # 단 S2 미실행


def test_pipeline_run_codeql_not_installed_writes_status(diff_repo: Path, tmp_path: Path, monkeypatch):
    """codex Q5r2-2: run_codeql=True 인데 CodeQL 미설치여도 codeql_status.json 을 남긴다(진단).

    verdict-C: S2 는 pipeline.stage_s2 가 소유 → auditai.pipeline.codeql_available 을 patch."""
    monkeypatch.setattr("auditai.pipeline.codeql_available", lambda *a, **k: False)
    run_pipeline(str(diff_repo), "HEAD~1", "HEAD", run_id="noql",
                 target_type=TargetType.SYNTHETIC, eval_targets=["owasp_sourced"],
                 runs_dir=tmp_path, run_codeql=True, engine=None)
    status_path = tmp_path / "noql" / "codeql_status.json"
    assert status_path.exists()


def test_pipeline_run_codeql_failure_is_analysis_error(diff_repo: Path, tmp_path: Path, monkeypatch):
    """codex Q1r2 [중]: run_codeql=True 인데 CodeQL 미설치/실패 → s2 미완료 → ANALYSIS_ERROR.

    빈 findings 가 NO_VULN 으로 승격되지 않음을 회귀로 고정. (stage_s2 가 run_track_a_sarif→None 처리.)
    verdict-C: S2 는 pipeline.stage_s2 가 소유 → auditai.pipeline.codeql_available 을 patch."""
    monkeypatch.setattr("auditai.pipeline.codeql_available", lambda *a, **k: False)
    report = run_pipeline(
        str(diff_repo), "HEAD~1", "HEAD",
        run_id="ckfail", target_type=TargetType.SYNTHETIC,
        eval_targets=["owasp_sourced"], runs_dir=tmp_path,
        run_codeql=True, engine=None,  # diff_repo 는 framework 없음 → G2 SKIPPED → s2 미완료가 결정타
    )
    assert report.s2_completed is False
    assert report.run_status == RunStatus.ANALYSIS_ERROR


def test_run_id_path_safety(diff_repo: Path, tmp_path: Path):
    with pytest.raises(ValueError):
        run_pipeline(str(diff_repo), "HEAD~1", "HEAD", run_id="../escape",
                     target_type=TargetType.SYNTHETIC, eval_targets=["owasp_sourced"],
                     runs_dir=tmp_path, engine=None)
    # collision
    run_pipeline(str(diff_repo), "HEAD~1", "HEAD", run_id="dup",
                 target_type=TargetType.SYNTHETIC, eval_targets=["owasp_sourced"],
                 runs_dir=tmp_path, engine=None)
    with pytest.raises(FileExistsError):
        run_pipeline(str(diff_repo), "HEAD~1", "HEAD", run_id="dup",
                     target_type=TargetType.SYNTHETIC, eval_targets=["owasp_sourced"],
                     runs_dir=tmp_path, engine=None)


def test_pipeline_artifacts_valid_json(diff_repo: Path, tmp_path: Path):
    run_pipeline(
        str(diff_repo), "HEAD~1", "HEAD",
        run_id="r4", target_type=TargetType.SYNTHETIC,
        eval_targets=["owasp_sourced"], runs_dir=tmp_path, engine=None,
    )
    gr = json.loads((tmp_path / "r4" / "gate_results.json").read_text(encoding="utf-8"))
    assert any(g["gate"] == "G1" for g in gr)


_ALL_ARTIFACTS = ["run_report.json", "gate_results.json", "diff_scope.json", "ai_attribution.json",
                  "deleted_security_controls.jsonl", "weakened_controls.jsonl",
                  "scope_selection_report.md"]


def test_pipeline_success_writes_all_7_artifacts(diff_repo: Path, tmp_path: Path):
    run_pipeline(str(diff_repo), "HEAD~1", "HEAD", run_id="a7", target_type=TargetType.SYNTHETIC,
                 eval_targets=["owasp_sourced"], runs_dir=tmp_path, engine=None)
    for name in _ALL_ARTIFACTS:
        assert (tmp_path / "a7" / name).exists(), name


def test_pipeline_g1_fail_writes_all_7_artifacts(diff_repo: Path, tmp_path: Path):
    """codex Q2 R2-1: G1/S0 실패(잘못된 base ref) 경로도 7종 artifact 전부 기록(빈 stub 포함)."""
    run_pipeline(str(diff_repo), "no_such_ref_xyz", "HEAD", run_id="g1f",
                 target_type=TargetType.SYNTHETIC, eval_targets=["owasp_sourced"],
                 runs_dir=tmp_path, engine=None)
    for name in _ALL_ARTIFACTS:
        assert (tmp_path / "g1f" / name).exists(), f"G1-fail missing {name}"
    rep = json.loads((tmp_path / "g1f" / "run_report.json").read_text(encoding="utf-8"))
    assert rep["run_status"] == RunStatus.DIFF_SCOPE_MISSING.value


def test_pipeline_track_b_only_findings_present(diff_repo: Path, tmp_path: Path):
    """codex Q2 R2-2: track_a_required=False + Track B inventory → FINDINGS_PRESENT(unreliable)."""
    report = run_pipeline(str(diff_repo), "HEAD~1", "HEAD", run_id="tbo",
                          target_type=TargetType.SYNTHETIC, eval_targets=["owasp_sourced"],
                          runs_dir=tmp_path, track_a_required=False, engine=None)
    assert report.run_status == RunStatus.FINDINGS_PRESENT
    assert report.reliability.value == "unreliable"  # taint 미실행
    assert report.risk_inventory


def test_pipeline_track_b_only_no_inventory_is_analysis_error(git_repo: Path, tmp_path: Path):
    """track_a_required=False 라도 Track B 무소득 + S1 후보 0 + taint 미실행 → ANALYSIS_ERROR(clean 주장 금지)."""
    report = run_pipeline(str(git_repo), "HEAD~1", "HEAD", run_id="tbo0",
                          target_type=TargetType.SYNTHETIC, eval_targets=["owasp_sourced"],
                          runs_dir=tmp_path, track_a_required=False, engine=None)
    if not report.risk_inventory and not report.candidate_inventory:  # 통제제거/후보 없으면
        assert report.run_status == RunStatus.ANALYSIS_ERROR


def test_pipeline_g4_disclosure_in_actual_artifact(diff_repo: Path, tmp_path: Path):
    """codex Q2 R2-6: 생성된 scope_selection_report.md 에 Track B 고지 문구가 실제로 들어간다."""
    from auditai.contracts import TRACK_B_DISCLOSURE

    run_pipeline(str(diff_repo), "HEAD~1", "HEAD", run_id="g4d", target_type=TargetType.SYNTHETIC,
                 eval_targets=["owasp_sourced"], runs_dir=tmp_path, engine=None)
    md = (tmp_path / "g4d" / "scope_selection_report.md").read_text(encoding="utf-8")
    assert TRACK_B_DISCLOSURE in md
    g4 = json.loads((tmp_path / "g4d" / "gate_results.json").read_text(encoding="utf-8"))
    assert any(g["gate"] == "G4" and g["status"] == "pass" for g in g4)


def test_pipeline_synthetic_plumbing_alone_eval_insufficient(diff_repo: Path, tmp_path: Path):
    """codex Q2 R2-3: synthetic_python(plumbing) 단독 eval → 효과입증 없음 → EVAL_TARGET_INSUFFICIENT.

    track_a_required=False 라야 s2 미완료(ANALYSIS_ERROR)보다 먼저 G3 까지 도달한다(verdict-C)."""
    report = run_pipeline(str(diff_repo), "HEAD~1", "HEAD", run_id="plumb",
                          target_type=TargetType.SYNTHETIC, eval_targets=["synthetic_python"],
                          runs_dir=tmp_path, track_a_required=False, engine=None)
    assert report.run_status == RunStatus.EVAL_TARGET_INSUFFICIENT


def test_pipeline_track_b_only_does_not_bypass_g3(diff_repo: Path, tmp_path: Path):
    """codex Q2r2: Track-B-only(track_a_required=False)에서도 G3 FAIL 은 inventory 보다 우선.

    synthetic_python(plumbing) 단독 + Track B inventory 있어도 → EVAL_TARGET_INSUFFICIENT(G3 우회 금지)."""
    report = run_pipeline(str(diff_repo), "HEAD~1", "HEAD", run_id="tbg3",
                          target_type=TargetType.SYNTHETIC, eval_targets=["synthetic_python"],
                          runs_dir=tmp_path, track_a_required=False, engine=None)
    assert report.risk_inventory  # diff_repo 는 삭제 가드 있음
    assert report.run_status == RunStatus.EVAL_TARGET_INSUFFICIENT


# --- verdict-C: S3 wiring (FakeEngine) + end-to-end stage 아티팩트 + resume -------- #
def test_pipeline_s3_no_engine_eligible_zero_no_semantic_judge(diff_repo: Path, tmp_path: Path):
    """engine=None + (CodeQL 없어 evidence 없음 → eligible 0) → SEMANTIC_JUDGE_NOT_RUN 아님.

    eligible 0 이면 S3 미판정이 있어도 무관(미전송 task 0). diff_repo 는 s2 미완료가 결정타(ANALYSIS_ERROR)."""
    report = run_pipeline(str(diff_repo), "HEAD~1", "HEAD", run_id="s3none",
                          target_type=TargetType.SYNTHETIC, eval_targets=["owasp_sourced"],
                          runs_dir=tmp_path, engine=None)
    assert report.llm_eligible_count == 0
    assert report.run_status != RunStatus.SEMANTIC_JUDGE_NOT_RUN


def test_pipeline_produces_stage_artifacts_end_to_end(diff_repo: Path, tmp_path: Path):
    """verdict-C end-to-end: run_pipeline 이 S0..S4 경계 아티팩트 + RunReport 를 모두 산출한다."""
    report = run_pipeline(str(diff_repo), "HEAD~1", "HEAD", run_id="e2e",
                          target_type=TargetType.SYNTHETIC, eval_targets=["owasp_sourced"],
                          runs_dir=tmp_path, engine=None)
    out = tmp_path / "e2e"
    for name in ("s0_attribution.json", "s1_candidates.json", "s2_evidence.json",
                 "s2_5_gate.json", "s3_judgements.json", "s4_findings.json", "run_report.json"):
        assert (out / name).exists(), name
    # s4 finding draft MD 도 렌더됨(judged finding 0 이어도 valid-empty)
    assert (out / "findings_report.md").exists()
    assert report.findings == report.findings  # RunReport.findings = S4 findings


def test_pipeline_resume_s2_5_through_s4_from_saved_artifacts(diff_repo: Path, tmp_path: Path):
    """§6.1 resume: 저장된 s1/s2 아티팩트로 S2.5→S3→S4 를 단독 재개(stage 함수 직접 호출).

    run_pipeline 으로 한 번 돌려 s1/s2 아티팩트를 남긴 뒤, FakeEngine 으로 S2.5/S3/S4 를 이어서 실행.
    eligible 후보가 없어도(diff_repo+no-codeql) 단계가 깨끗이 valid-empty 로 흘러감을 검증."""
    from auditai import pipeline
    from auditai.artifacts import (
        S1Artifact, S2Artifact, load_stage_artifact, write_stage_artifact, StageStatus,
    )
    from auditai.judge import FakeEngine

    run_pipeline(str(diff_repo), "HEAD~1", "HEAD", run_id="rsm",
                 target_type=TargetType.SYNTHETIC, eval_targets=["owasp_sourced"],
                 runs_dir=tmp_path, engine=None)
    out = tmp_path / "rsm"
    s1 = load_stage_artifact(out / "s1_candidates.json", S1Artifact)
    s2 = load_stage_artifact(out / "s2_evidence.json", S2Artifact)
    # 저장 아티팩트만으로 S2.5→S3→S4 재개
    s25 = pipeline.stage_s2_5(s1, s2)
    s3 = pipeline.stage_s3(s25, FakeEngine(_valid_judge_json()))
    s4 = pipeline.stage_s4(s3, s1, s2)
    # diff_repo + no codeql → evidence 0 → eligible 0 → judged 0 → findings 0 (valid-empty)
    assert s25.eligible_count == 0
    assert s4.findings == []
    # 재개 산출도 다시 영속화 가능(자기기술 아티팩트)
    resume_dir = tmp_path / "rsm_resume"
    resume_dir.mkdir()
    write_stage_artifact(resume_dir / "s4_findings.json", s4)
    again = load_stage_artifact(resume_dir / "s4_findings.json", type(s4))
    assert again.stage == "S4"


def test_pipeline_resume_with_evidence_yields_judged_finding(tmp_path: Path):
    """§6.1 resume + verdict-C: 저장된 s1(taint 후보)+s2(evidence) 로 S2.5→S3(FakeEngine)→S4 재개 →
    judged FindingReport 1건(vulnerability_confirmed=False). 실 CodeQL 없이 evidence 를 골든 입력으로."""
    from auditai import pipeline
    from auditai.artifacts import S1Artifact, S2Artifact, StageStatus
    from auditai.contracts import (
        CandidateSource, CandidateType, EvidenceKind, FindingCandidate, FlowEvidence,
        LocationSpan, Track,
    )
    from auditai.judge import FakeEngine

    cand = FindingCandidate(
        candidate_id="c1", candidate_type=CandidateType.TAINT_PATH, track=Track.A,
        repo="r", commit_sha="h", file="api.py", sink_loc="api.py:10",
        sink_span=LocationSpan(file="api.py", start_line=10, end_line=10, start_col=4, end_col=24),
        capability_id="sql_execution", sink_spec_id="sink.sqlite3.cursor.execute",
        candidate_source=CandidateSource.AST, evidence_kind=EvidenceKind.REQUIRES_CODEQL_VALIDATION,
        recall_reason="KB sink (CWE-89)", source_nearby=True, code_snippet="cur.execute(q)",
    )
    s1 = S1Artifact(status=StageStatus.OK, repo="r", commit_sha="h", candidates=[cand])
    ev = FlowEvidence(
        candidate_id="c1", source_to_sink_flow_exists=True, static_path_confirmed=True,
        approximation_kind="generic_codeql_ai_sink_intersection", confidence=0.6,
        evidence_backend_version="2.25.6", sink="api.py:10", engine="codeql",
        flow_path=["api.py:5", "api.py:10"],
    )
    s2 = S2Artifact(status=StageStatus.OK, repo="r", commit_sha="h", s2_completed=True, evidence=[ev])
    s25 = pipeline.stage_s2_5(s1, s2)
    assert s25.eligible_count == 1
    s3 = pipeline.stage_s3(s25, FakeEngine(_valid_judge_json()))
    assert s3.s3_completed is True and s3.judged_count == 1
    s4 = pipeline.stage_s4(s3, s1, s2)
    assert len(s4.findings) == 1
    f = s4.findings[0]
    assert f.vulnerability_confirmed is False
    assert f.title.startswith("Potential ") or f.title.startswith("Needs manual review")


def test_pipeline_stage_error_is_analysis_error(diff_repo: Path, tmp_path: Path, monkeypatch):
    """verdict-C(codex QA #2): downstream stage 크래시(s0 OK, stage_error.json) → ANALYSIS_ERROR.

    s0 는 성공해 scope 가 있으므로 일반 집계로 떨어지되, analysis_incomplete=True 가 최상위 precedence
    로 ANALYSIS_ERROR 를 강제한다(빈/부분 결과를 FINDINGS/NO_VULN 으로 오독 금지)."""
    from auditai import pipeline

    def _boom(*a, **k):
        raise RuntimeError("stage exploded")

    # stage_s1 이 터지면 run_stages 가 _abort('s1') → stage_error.json 기록 후 arts 반환(s0 만).
    monkeypatch.setattr(pipeline, "stage_s1", _boom)
    report = run_pipeline(str(diff_repo), "HEAD~1", "HEAD", run_id="serr",
                          target_type=TargetType.SYNTHETIC, eval_targets=["owasp_sourced"],
                          runs_dir=tmp_path, engine=None)
    assert report.run_status == RunStatus.ANALYSIS_ERROR
    assert report.analysis_incomplete is True
    assert (tmp_path / "serr" / "stage_error.json").exists()
    # 일반 집계 경로도 RunReport 7종 artifact 보장
    for name in _ALL_ARTIFACTS:
        assert (tmp_path / "serr" / name).exists(), name


def test_pipeline_stage_error_overrides_track_b_findings(diff_repo: Path, tmp_path: Path, monkeypatch):
    """codex QA #2(CRITICAL fail-open 회귀): track_a_required=False + Track B inventory 가 있어도
    stage 크래시가 우선 → FINDINGS_PRESENT 로 새지 않고 ANALYSIS_ERROR(크래시 precedence 최상위)."""
    from auditai import pipeline

    def _boom(*a, **k):
        raise RuntimeError("s1 exploded mid-pipeline")

    monkeypatch.setattr(pipeline, "stage_s1", _boom)
    report = run_pipeline(str(diff_repo), "HEAD~1", "HEAD", run_id="serrtb",
                          target_type=TargetType.SYNTHETIC, eval_targets=["owasp_sourced"],
                          runs_dir=tmp_path, engine=None, track_a_required=False)
    assert report.risk_inventory  # diff_repo 는 Track B 삭제 가드 있음 (과거엔 이게 FINDINGS_PRESENT 로 오염)
    assert report.run_status == RunStatus.ANALYSIS_ERROR  # 크래시가 inventory 보다 우선
    assert report.analysis_incomplete is True


@pytest.mark.skipif(not codeql_available(), reason="CodeQL CLI not installed")
def test_pipeline_judged_false_positive_does_not_pollute_status(fastapi_pr_repo: Path, tmp_path: Path):
    """codex QA #1(CRITICAL 회귀): S2 완료 + S3 가 후보를 false_positive 로 판정 → S4 findings 비고,
    그 후보가 candidate_inventory 로 **다시** surface 돼 FINDINGS_PRESENT 로 오염되면 안 된다.

    s2_completed=True 면 TAINT 후보 운명은 S2.5→S3→S4 가 확정(verdict-C: S4 권위). false_positive judged
    후보는 inventory 로 안 가고 → NO_VULN_FOUND. (실 CodeQL + FakeEngine(false_positive).)"""
    report = run_pipeline(
        str(fastapi_pr_repo), "HEAD~1", "HEAD",
        run_id="fpclean", target_type=TargetType.SYNTHETIC,
        eval_targets=["owasp_sourced"], runs_dir=tmp_path,
        validation_matrix={"fastapi": True}, validation_codeql_version=codeql_version(),
        run_codeql=True, engine=FakeEngine(_valid_judge_json(verdict="false_positive")),
    )
    assert report.s2_completed
    assert report.findings == []  # false_positive 는 S4 draft 제외
    # 핵심: false_positive 로 판정된 TAINT 후보가 candidate_inventory 로 새지 않음 → FINDINGS_PRESENT 아님.
    assert report.run_status != RunStatus.FINDINGS_PRESENT
    # eligible 후보가 전원 judged(skip 0) 였다면 SEMANTIC_JUDGE_NOT_RUN 도 아님 → NO_VULN_FOUND.
    if report.judgement_skipped_count == 0 and report.llm_eligible_count > 0:
        assert report.run_status == RunStatus.NO_VULN_FOUND


@pytest.mark.skipif(not codeql_available(), reason="CodeQL CLI not installed")
def test_pipeline_real_codeql_track_a(fastapi_pr_repo: Path, tmp_path: Path):
    """P0-3b end-to-end(verdict-C 정직 경로): S0 diff → FastAPI 자동탐지 → 검증 매트릭스로 G2 PASS →
    실제 CodeQL S2 evidence → S2.5 eligible → S3(FakeEngine) judged → S4 FindingReport → FINDINGS_PRESENT.

    실 LLM 미호출(FakeEngine 주입). engine 주입으로 S3 가 judged 를 산출해야 FINDINGS_PRESENT 가 된다
    (engine=None 이면 SEMANTIC_JUDGE_NOT_RUN — verdict-C fail-closed)."""
    report = run_pipeline(
        str(fastapi_pr_repo), "HEAD~1", "HEAD",
        run_id="ckql", target_type=TargetType.SYNTHETIC,
        eval_targets=["owasp_sourced"], runs_dir=tmp_path,
        validation_matrix={"fastapi": True},
        validation_codeql_version=codeql_version(),
        run_codeql=True, engine=FakeEngine(_valid_judge_json()),
    )
    assert report.s2_completed
    # CodeQL 이 planted subprocess(shell=True) 를 잡고 evidence→eligible→judged 면 FINDINGS_PRESENT.
    assert report.run_status in (RunStatus.FINDINGS_PRESENT, RunStatus.SEMANTIC_JUDGE_NOT_RUN)
    status = json.loads((tmp_path / "ckql" / "codeql_status.json").read_text(encoding="utf-8"))
    assert status.get("codeql_version") and status.get("returncode") == 0


# --- S0 파이프라인 회귀 (codex MVP S0 M5) ---------------------------------- #
def test_pipeline_s0_attribution_incomplete_is_fail_closed(diff_repo: Path, tmp_path: Path, monkeypatch):
    """S0 blame 귀속 미완(completed=False) → report 가 ANALYSIS_ERROR + s0_attribution_completed=False.

    verdict-C: S0 는 pipeline.stage_s0 → attribute_added_lines 가 partial 산출. (auditai.pipeline 을 patch.)"""
    from auditai.scope import AddedLineAttribution

    def _incomplete(repo, scope, cfg=None):
        return AddedLineAttribution(completed=False)

    monkeypatch.setattr("auditai.pipeline.attribute_added_lines", _incomplete)
    report = run_pipeline(
        str(diff_repo), "HEAD~1", "HEAD",
        run_id="s0fail", target_type=TargetType.SYNTHETIC,
        eval_targets=["owasp_sourced"], runs_dir=tmp_path, engine=None,
    )
    assert report.run_status == RunStatus.ANALYSIS_ERROR
    assert report.s0_attribution_completed is False


def test_pipeline_s0_attribution_complete_threads_true(diff_repo: Path, tmp_path: Path):
    """정상 경로: S0 완료 → report.s0_attribution_completed=True (배선 확인)."""
    report = run_pipeline(
        str(diff_repo), "HEAD~1", "HEAD",
        run_id="s0ok", target_type=TargetType.SYNTHETIC,
        eval_targets=["owasp_sourced"], runs_dir=tmp_path, engine=None,
    )
    assert report.s0_attribution_completed is True
