"""파이프라인 오케스트레이션 (run.py) 테스트."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from auditai.codeql import codeql_available, codeql_version
from auditai.contracts import RunStatus, TargetType
from auditai.run import run_pipeline
from auditai.scope import GitError


def test_pipeline_no_codeql_is_not_clean(diff_repo: Path, tmp_path: Path):
    """CodeQL 미설치(S2 미실행) → NO_VULN_FOUND 로 착각 금지. 단 Track B inventory 는 산출."""
    report = run_pipeline(
        str(diff_repo), "HEAD~1", "HEAD",
        run_id="r1", target_type=TargetType.SYNTHETIC,
        eval_targets=["owasp_sourced"], runs_dir=tmp_path,
        # s2_findings/run_codeql 모두 없음 → s2_completed=False
    )
    # 빈 결과를 정상으로 보고하지 않는다
    assert report.run_status != RunStatus.NO_VULN_FOUND
    # diff_repo 는 framework 미사용 → G2 skip → s2 미완료 → ANALYSIS_ERROR
    assert report.run_status == RunStatus.ANALYSIS_ERROR
    # Track B: 삭제된 authz 가드가 inventory 에 있어야 함
    assert report.risk_inventory
    # artifacts 기록 확인
    out = tmp_path / "r1"
    assert (out / "run_report.json").exists()
    assert (out / "diff_scope.json").exists()
    assert (out / "deleted_security_controls.jsonl").read_text(encoding="utf-8").strip()
    assert (out / "scope_selection_report.md").exists()


def test_pipeline_external_s2_clean(diff_repo: Path, tmp_path: Path):
    """외부 S2 결과 제공(빈 리스트) + framework 미사용 + Track B 있으면 FINDINGS_PRESENT(inventory)."""
    report = run_pipeline(
        str(diff_repo), "HEAD~1", "HEAD",
        run_id="r2", target_type=TargetType.SYNTHETIC,
        eval_targets=["owasp_sourced"], runs_dir=tmp_path,
        s2_findings=[],  # 외부 S2 완료(빈 결과) → s2_completed=True
    )
    # Track B inventory(삭제 가드) 존재 → FINDINGS_PRESENT
    assert report.run_status == RunStatus.FINDINGS_PRESENT
    assert report.s2_completed
    assert report.risk_inventory


def test_pipeline_phoenix_only_eval_fails(diff_repo: Path, tmp_path: Path):
    """G3: phoenix smoke 단독 eval → EVAL_TARGET_INSUFFICIENT."""
    report = run_pipeline(
        str(diff_repo), "HEAD~1", "HEAD",
        run_id="r3", target_type=TargetType.SMOKE,
        eval_targets=["phoenix_smoke"], runs_dir=tmp_path,
        s2_findings=[],
    )
    assert report.run_status == RunStatus.EVAL_TARGET_INSUFFICIENT


def test_run_codeql_and_s2_findings_mutually_exclusive(diff_repo: Path, tmp_path: Path):
    """codex Q1 F3: run_codeql=True 와 외부 s2_findings 동시 지정은 모순 → ValueError."""
    import pytest

    with pytest.raises(ValueError):
        run_pipeline(
            str(diff_repo), "HEAD~1", "HEAD",
            run_id="rs", target_type=TargetType.SYNTHETIC,
            eval_targets=["owasp_sourced"], runs_dir=tmp_path,
            run_codeql=True, s2_findings=[],
        )


def test_pipeline_framework_without_validation_hard_fails(fastapi_pr_repo: Path, tmp_path: Path):
    """codex Q1 F1/F2: FastAPI 자동탐지 + 검증 매트릭스 없음 → G2 NOT_RUN(hard fail).

    frameworks=set() 우회 없이 실제 detect_frameworks 경로로 G2 가 동작함을 증명(빈 결과 오독 금지).
    """
    report = run_pipeline(
        str(fastapi_pr_repo), "HEAD~1", "HEAD",
        run_id="fwnoval", target_type=TargetType.SYNTHETIC,
        eval_targets=["owasp_sourced"], runs_dir=tmp_path,
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
        eval_targets=["owasp_sourced"], runs_dir=tmp_path,
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
        eval_targets=["owasp_sourced"], runs_dir=tmp_path,
        frameworks=set(),     # 빈 set 으로 탐지 우회 시도
        s2_findings=[],        # S2 완료(빈 결과) 라도
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
        eval_targets=["owasp_sourced"], runs_dir=tmp_path,
        s2_findings=[],  # S2 완료(빈 결과) 라도
    )
    assert report.run_status == RunStatus.FRAMEWORK_SOURCE_VALIDATION_NOT_RUN
    # codex Q1r8 R8-3: 진단 문구가 dep mismatch 원인을 정직히 기록(grep 장애와 구분)
    g2 = next(g for g in report.gate_results if g.gate.value == "G2")
    assert "declared framework dependency not detected" in g2.message


def test_pipeline_explicit_framework_cannot_clear_dep_fallback(
    declared_not_imported_repo: Path, tmp_path: Path, monkeypatch
):
    """codex Q1r6 R6-1: --framework 명시로 'declared but not imported' fail-closed 신호를 지울 수 없다.

    fastapi 가 dep 선언됐지만 import 미탐지 → 사용자가 frameworks={fastapi}+유효 매트릭스를 줘도
    detection-incomplete(NOT_RUN) 유지(빈 S2 가 NO_VULN 으로 승격 금지)."""
    monkeypatch.setattr("auditai.run.codeql_version", lambda *a, **k: "2.25.6")
    report = run_pipeline(
        str(declared_not_imported_repo), "HEAD~1", "HEAD",
        run_id="explbypass", target_type=TargetType.SYNTHETIC,
        eval_targets=["owasp_sourced"], runs_dir=tmp_path,
        frameworks={"fastapi"},                     # 명시 입력으로 우회 시도
        validation_matrix={"fastapi": True}, validation_codeql_version="2.25.6",
        s2_findings=[],
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
        eval_targets=["owasp_sourced"], runs_dir=tmp_path,
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
        eval_targets=["owasp_sourced"], runs_dir=tmp_path,
        s2_findings=[],  # S2 완료라도(빈 결과) 탐지 미완료면 NO_VULN 금지
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
        eval_targets=["owasp_sourced"], runs_dir=tmp_path,
        validation_matrix={"fastapi": True},  # fastapi 검증, starlette 미등록(=미검증)
        validation_codeql_version="2.25.6",
        s2_findings=[],  # S2 완료(빈 결과)
    )
    assert report.run_status != RunStatus.FRAMEWORK_SOURCE_MODEL_MISSING
    g2 = next(g for g in report.gate_results if g.gate.value == "G2")
    assert g2.status.value == "pass"  # starlette 무시, fastapi 검증됨 → PASS(over-flag 없음)
    # S1(known-KB AST seed)이 planted subprocess(shell=True)=CWE-78 sink 를 AI 라인에서 후보로 잡아
    # candidate_inventory 표면화 → FINDINGS_PRESENT(이전엔 탐지기 없어 NO_VULN 이었음). G2 over-flag 핵심은
    # 여전히 'G2 PASS·MODEL_MISSING 아님'으로 검증됨.
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
        eval_targets=["owasp_sourced"], runs_dir=tmp_path,
        validation_matrix={"fastapi": True},  # starlette 미검증
        validation_codeql_version="2.25.6",
        s2_findings=[],
    )
    assert report.run_status == RunStatus.FRAMEWORK_SOURCE_MODEL_MISSING


def test_pipeline_mixed_pr_keeps_repo_wide_model_missing(
    mixed_fastapi_helper_starlette_repo: Path, tmp_path: Path, monkeypatch
):
    """codex G2 over-flag #3(제안 구멍 차단): fastapi 변경 파일 + frameworkless helper 혼합 PR →
    "framework 없는 변경 .py 존재" 트리거로 case B 유지 → repo-wide starlette → MODEL_MISSING.
    (잘못된 "변경 framework 비었나" 트리거였다면 fallback 이 꺼져 false NO_VULN 가능했음.)"""
    monkeypatch.setattr("auditai.run.codeql_version", lambda *a, **k: "2.25.6")
    report = run_pipeline(
        str(mixed_fastapi_helper_starlette_repo), "HEAD~1", "HEAD",
        run_id="mixedpr", target_type=TargetType.SYNTHETIC,
        eval_targets=["owasp_sourced"], runs_dir=tmp_path,
        validation_matrix={"fastapi": True},  # starlette 미검증
        validation_codeql_version="2.25.6",
        s2_findings=[],
    )
    assert report.run_status == RunStatus.FRAMEWORK_SOURCE_MODEL_MISSING


def test_pipeline_var_dynamic_import_with_declared_dep_is_fail_closed(
    fastapi_var_dynamic_starlette_repo: Path, tmp_path: Path, monkeypatch
):
    """codex G2 over-flag r2 #2 / r3 #3: 변경 파일이 fastapi(검증됨) import + 변수 동적 import 로 미검증
    starlette 를 끌어옴(정적 미탐지) + starlette **declared**. 불확실성 신호가 case A 라도 dep-fallback
    을 켜고, **declared-but-not-imported starlette 가 dep-fallback 으로 해소되어** fail-closed NOT_RUN.
    (불확실성 신호 자체가 아니라 매니페스트 선언이 fail-closed 를 만든다 — r3 #3 계약 명확화.)"""
    monkeypatch.setattr("auditai.run.codeql_version", lambda *a, **k: "2.25.6")
    report = run_pipeline(
        str(fastapi_var_dynamic_starlette_repo), "HEAD~1", "HEAD",
        run_id="vardynscan", target_type=TargetType.SYNTHETIC,
        eval_targets=["owasp_sourced"], runs_dir=tmp_path,
        validation_matrix={"fastapi": True},  # fastapi 검증돼도
        validation_codeql_version="2.25.6",
        s2_findings=[],  # S2 완료(빈 결과) 라도
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
        eval_targets=["owasp_sourced"], runs_dir=tmp_path,
        validation_matrix={"fastapi": True}, validation_codeql_version="2.25.6",
        s2_findings=[],
    )
    assert report.run_status == RunStatus.FRAMEWORK_SOURCE_VALIDATION_NOT_RUN
    g2 = next(g for g in report.gate_results if g.gate.value == "G2")
    assert "incomplete" in g2.message


def test_pipeline_unresolved_uncertain_is_not_self_fail_closed(
    fastapi_var_dynamic_no_dep_repo: Path, tmp_path: Path, monkeypatch
):
    """codex G2 over-flag r3 #3 ((B) 계약 잠금): 변수 동적 import 가 있어도 매니페스트 선언/정적 repo
    사용으로 해소할 게 없으면 불확실성 신호 자체는 NOT_RUN 을 만들지 않는다 — G2 는 fastapi(검증됨)만으로
    PASS. (불확실성=보강 트리거이지 차단 신호 아님; 미상 framework 순수 변수 동적은 MVP 미탐지 한계.)"""
    monkeypatch.setattr("auditai.run.codeql_version", lambda *a, **k: "2.25.6")
    report = run_pipeline(
        str(fastapi_var_dynamic_no_dep_repo), "HEAD~1", "HEAD",
        run_id="vardynnodepscan", target_type=TargetType.SYNTHETIC,
        eval_targets=["owasp_sourced"], runs_dir=tmp_path,
        validation_matrix={"fastapi": True}, validation_codeql_version="2.25.6",
        s2_findings=[],
    )
    g2 = next(g for g in report.gate_results if g.gate.value == "G2")
    assert g2.status.value == "pass"  # fastapi 검증됨, 해소할 미검증 framework 없음
    assert report.run_status == RunStatus.NO_VULN_FOUND


def test_validation_matrix_codeql_version_mismatch_downgrades(
    fastapi_pr_repo: Path, tmp_path: Path, monkeypatch
):
    """codex Q1r2 [상]: 매트릭스 검증 버전 != 설치 CodeQL 버전 → 매트릭스 무시(NOT_RUN). 거짓 정직성 방지."""
    monkeypatch.setattr("auditai.run.codeql_version", lambda *a, **k: "9.9.9")
    report = run_pipeline(
        str(fastapi_pr_repo), "HEAD~1", "HEAD",
        run_id="vermis", target_type=TargetType.SYNTHETIC,
        eval_targets=["owasp_sourced"], runs_dir=tmp_path,
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
        eval_targets=["owasp_sourced"], runs_dir=tmp_path,
        validation_matrix={"fastapi": True}, validation_codeql_version="2.25.6",
    )
    g2 = next(g for g in report.gate_results if g.gate == GateId.G2)
    assert g2.status == GateStatus.PASS                       # 매트릭스 적용됨
    assert report.run_status == RunStatus.ANALYSIS_ERROR      # 단 S2 미실행


def test_pipeline_run_codeql_not_installed_writes_status(diff_repo: Path, tmp_path: Path, monkeypatch):
    """codex Q5r2-2: run_codeql=True 인데 CodeQL 미설치여도 codeql_status.json 을 남긴다(진단)."""
    monkeypatch.setattr("auditai.codeql.codeql_available", lambda *a, **k: False)
    run_pipeline(str(diff_repo), "HEAD~1", "HEAD", run_id="noql",
                 target_type=TargetType.SYNTHETIC, eval_targets=["owasp_sourced"],
                 runs_dir=tmp_path, run_codeql=True)
    status = json.loads((tmp_path / "noql" / "codeql_status.json").read_text(encoding="utf-8"))
    assert "not found" in (status.get("error") or "")


def test_pipeline_run_codeql_failure_is_analysis_error(diff_repo: Path, tmp_path: Path, monkeypatch):
    """codex Q1r2 [중]: run_codeql=True 인데 run_track_a→None(CodeQL 실패) → s2 미완료 → ANALYSIS_ERROR.

    빈 findings 가 NO_VULN 으로 승격되지 않음을 회귀로 고정(F3 의 런타임 실패 경로)."""
    monkeypatch.setattr("auditai.codeql.codeql_available", lambda *a, **k: True)
    monkeypatch.setattr("auditai.codeql.run_track_a", lambda *a, **k: None)  # 실행 실패
    report = run_pipeline(
        str(diff_repo), "HEAD~1", "HEAD",
        run_id="ckfail", target_type=TargetType.SYNTHETIC,
        eval_targets=["owasp_sourced"], runs_dir=tmp_path,
        run_codeql=True,  # diff_repo 는 framework 없음 → G2 SKIPPED → s2 미완료가 결정타
    )
    assert report.s2_completed is False
    assert report.run_status == RunStatus.ANALYSIS_ERROR


def test_run_id_path_safety(diff_repo: Path, tmp_path: Path):
    import pytest

    with pytest.raises(ValueError):
        run_pipeline(str(diff_repo), "HEAD~1", "HEAD", run_id="../escape",
                     target_type=TargetType.SYNTHETIC, eval_targets=["owasp_sourced"],
                     runs_dir=tmp_path)
    # collision
    run_pipeline(str(diff_repo), "HEAD~1", "HEAD", run_id="dup",
                 target_type=TargetType.SYNTHETIC, eval_targets=["owasp_sourced"],
                 runs_dir=tmp_path)
    with pytest.raises(FileExistsError):
        run_pipeline(str(diff_repo), "HEAD~1", "HEAD", run_id="dup",
                     target_type=TargetType.SYNTHETIC, eval_targets=["owasp_sourced"],
                     runs_dir=tmp_path)


def test_pipeline_artifacts_valid_json(diff_repo: Path, tmp_path: Path):
    run_pipeline(
        str(diff_repo), "HEAD~1", "HEAD",
        run_id="r4", target_type=TargetType.SYNTHETIC,
        eval_targets=["owasp_sourced"], runs_dir=tmp_path,
    )
    gr = json.loads((tmp_path / "r4" / "gate_results.json").read_text(encoding="utf-8"))
    assert any(g["gate"] == "G1" for g in gr)


_ALL_ARTIFACTS = ["run_report.json", "gate_results.json", "diff_scope.json", "ai_attribution.json",
                  "deleted_security_controls.jsonl", "weakened_controls.jsonl",
                  "scope_selection_report.md"]


def test_pipeline_success_writes_all_7_artifacts(diff_repo: Path, tmp_path: Path):
    run_pipeline(str(diff_repo), "HEAD~1", "HEAD", run_id="a7", target_type=TargetType.SYNTHETIC,
                 eval_targets=["owasp_sourced"], runs_dir=tmp_path)
    for name in _ALL_ARTIFACTS:
        assert (tmp_path / "a7" / name).exists(), name


def test_pipeline_g1_fail_writes_all_7_artifacts(diff_repo: Path, tmp_path: Path):
    """codex Q2 R2-1: G1 실패(잘못된 base ref) 경로도 7종 artifact 전부 기록(빈 stub 포함)."""
    run_pipeline(str(diff_repo), "no_such_ref_xyz", "HEAD", run_id="g1f",
                 target_type=TargetType.SYNTHETIC, eval_targets=["owasp_sourced"], runs_dir=tmp_path)
    for name in _ALL_ARTIFACTS:
        assert (tmp_path / "g1f" / name).exists(), f"G1-fail missing {name}"
    rep = json.loads((tmp_path / "g1f" / "run_report.json").read_text(encoding="utf-8"))
    assert rep["run_status"] == RunStatus.DIFF_SCOPE_MISSING.value


def test_pipeline_track_b_only_findings_present(diff_repo: Path, tmp_path: Path):
    """codex Q2 R2-2: track_a_required=False + Track B inventory → FINDINGS_PRESENT(unreliable)."""
    report = run_pipeline(str(diff_repo), "HEAD~1", "HEAD", run_id="tbo",
                          target_type=TargetType.SYNTHETIC, eval_targets=["owasp_sourced"],
                          runs_dir=tmp_path, track_a_required=False)
    assert report.run_status == RunStatus.FINDINGS_PRESENT
    assert report.reliability.value == "unreliable"  # taint 미실행
    assert report.risk_inventory


def test_pipeline_track_b_only_no_inventory_is_analysis_error(git_repo: Path, tmp_path: Path):
    """track_a_required=False 라도 Track B 무소득 + taint 미실행 → ANALYSIS_ERROR(clean 주장 금지)."""
    # git_repo: 보안통제 제거 없는 일반 변경(inventory 0 기대)
    report = run_pipeline(str(git_repo), "HEAD~1", "HEAD", run_id="tbo0",
                          target_type=TargetType.SYNTHETIC, eval_targets=["owasp_sourced"],
                          runs_dir=tmp_path, track_a_required=False)
    if not report.risk_inventory:  # git_repo 에 통제제거 없으면
        assert report.run_status == RunStatus.ANALYSIS_ERROR


def test_pipeline_g4_disclosure_in_actual_artifact(diff_repo: Path, tmp_path: Path):
    """codex Q2 R2-6: 생성된 scope_selection_report.md 에 Track B 고지 문구가 실제로 들어간다."""
    from auditai.contracts import TRACK_B_DISCLOSURE

    run_pipeline(str(diff_repo), "HEAD~1", "HEAD", run_id="g4d", target_type=TargetType.SYNTHETIC,
                 eval_targets=["owasp_sourced"], runs_dir=tmp_path)
    md = (tmp_path / "g4d" / "scope_selection_report.md").read_text(encoding="utf-8")
    assert TRACK_B_DISCLOSURE in md
    g4 = json.loads((tmp_path / "g4d" / "gate_results.json").read_text(encoding="utf-8"))
    assert any(g["gate"] == "G4" and g["status"] == "pass" for g in g4)


def test_pipeline_synthetic_plumbing_alone_eval_insufficient(diff_repo: Path, tmp_path: Path):
    """codex Q2 R2-3: synthetic_python(plumbing) 단독 eval → 효과입증 없음 → EVAL_TARGET_INSUFFICIENT."""
    report = run_pipeline(str(diff_repo), "HEAD~1", "HEAD", run_id="plumb",
                          target_type=TargetType.SYNTHETIC, eval_targets=["synthetic_python"],
                          runs_dir=tmp_path, s2_findings=[])  # s2 완료라 G3 까지 도달
    assert report.run_status == RunStatus.EVAL_TARGET_INSUFFICIENT


def test_pipeline_track_b_only_does_not_bypass_g3(diff_repo: Path, tmp_path: Path):
    """codex Q2r2: Track-B-only(track_a_required=False)에서도 G3 FAIL 은 inventory 보다 우선.

    synthetic_python(plumbing) 단독 + Track B inventory 있어도 → EVAL_TARGET_INSUFFICIENT(G3 우회 금지)."""
    report = run_pipeline(str(diff_repo), "HEAD~1", "HEAD", run_id="tbg3",
                          target_type=TargetType.SYNTHETIC, eval_targets=["synthetic_python"],
                          runs_dir=tmp_path, track_a_required=False)
    assert report.risk_inventory  # diff_repo 는 삭제 가드 있음
    assert report.run_status == RunStatus.EVAL_TARGET_INSUFFICIENT


@pytest.mark.skipif(not codeql_available(), reason="CodeQL CLI not installed")
def test_pipeline_real_codeql_track_a(fastapi_pr_repo: Path, tmp_path: Path):
    """P0-3b end-to-end(정직 경로): S0 diff → FastAPI 자동탐지 → 검증 매트릭스로 G2 PASS →
    실제 CodeQL Track A → AI-라인 필터 → FINDINGS_PRESENT. (frameworks=set() 우회 없음 — codex Q1 F2)."""
    report = run_pipeline(
        str(fastapi_pr_repo), "HEAD~1", "HEAD",
        run_id="ckql", target_type=TargetType.SYNTHETIC,
        eval_targets=["owasp_sourced"], runs_dir=tmp_path,
        validation_matrix={"fastapi": True},  # FastAPI source model 검증됨(동봉 매트릭스와 동일)
        validation_codeql_version=codeql_version(),  # 설치 버전과 일치(버전 가드 통과)
        run_codeql=True,
    )
    assert report.s2_completed
    assert report.run_status == RunStatus.FINDINGS_PRESENT
    assert any("78" in f.cwe or "command" in f.title.lower() for f in report.findings), \
        "AI가 추가한 subprocess shell=True 를 Track A 가 잡아야 함"
    # codex Q5-5/6: CodeQL 실행 진단 artifact(stage/returncode/version) 기록
    status = json.loads((tmp_path / "ckql" / "codeql_status.json").read_text(encoding="utf-8"))
    assert status.get("codeql_version") and status.get("returncode") == 0


@pytest.mark.skipif(not codeql_available(), reason="CodeQL CLI not installed")
def test_track_a_efficacy_owasp_classes(owasp_efficacy_repo: Path, tmp_path: Path):
    """효과 회귀: AI 가 추가한 6개 OWASP 클래스(FastAPI source + 인식 sink)를 Track A 가 전부 탐지.

    실측 특성화(CODEX_VERIFICATION_QUEUE Q2 효과 발견) 잠금 — source+sink 인식 시 6/6.
    탐지 갭(비framework=source 없음 / duck-typed sink)은 별개 한계로 문서화됨."""
    report = run_pipeline(
        str(owasp_efficacy_repo), "HEAD~1", "HEAD",
        run_id="owaspscan", target_type=TargetType.SYNTHETIC,
        eval_targets=["owasp_sourced"], runs_dir=tmp_path,
        validation_matrix={"fastapi": True}, validation_codeql_version=codeql_version(),
        run_codeql=True,
    )
    assert report.run_status == RunStatus.FINDINGS_PRESENT
    cwes = {c for f in report.findings for c in [f.cwe] if c.startswith("CWE-")}
    for expected in ("CWE-78", "CWE-89", "CWE-22", "CWE-502", "CWE-918", "CWE-94"):
        assert expected in cwes, f"{expected} 미탐지 (탐지된: {sorted(cwes)})"


# --- S0 파이프라인 회귀 (codex MVP S0 M5) ---------------------------------- #
def test_pipeline_s0_attribution_incomplete_is_fail_closed(diff_repo: Path, tmp_path: Path, monkeypatch):
    """run_pipeline 에서 S0 blame 귀속 미완(completed=False) → report 가 ANALYSIS_ERROR + s0_attribution_completed=False.
    (단위 resolver/scope 테스트만으로는 배선 결함을 못 잡으므로 파이프라인 통합 검증.)"""
    from auditai.scope import AddedLineAttribution

    def _incomplete(repo, scope, cfg=None):
        return AddedLineAttribution(completed=False)

    monkeypatch.setattr("auditai.run.attribute_added_lines", _incomplete)
    report = run_pipeline(
        str(diff_repo), "HEAD~1", "HEAD",
        run_id="s0fail", target_type=TargetType.SYNTHETIC,
        eval_targets=["owasp_sourced"], runs_dir=tmp_path,
        s2_findings=[],  # S2 완료(빈 결과)라도 S0 미완이면 clean 금지
    )
    assert report.run_status == RunStatus.ANALYSIS_ERROR
    assert report.s0_attribution_completed is False


def test_pipeline_s0_attribution_complete_threads_true(diff_repo: Path, tmp_path: Path):
    """정상 경로: S0 완료 → report.s0_attribution_completed=True (배선 확인)."""
    report = run_pipeline(
        str(diff_repo), "HEAD~1", "HEAD",
        run_id="s0ok", target_type=TargetType.SYNTHETIC,
        eval_targets=["owasp_sourced"], runs_dir=tmp_path,
        s2_findings=[],
    )
    assert report.s0_attribution_completed is True
