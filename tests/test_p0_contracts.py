"""P0 contracts — RunStatus 상태기계 / Gates / Track B inventory 불변식 (계획 05)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from auditai.contracts import (
    AttributionState,
    CandidateInventoryItem,
    CandidateType,
    CodeQLTaintResult,
    DeletionAttribution,
    DeletionAttributionSource,
    FindingReport,
    FlowEvidence,
    GateFailureCode,
    GateId,
    GateResult,
    GateStatus,
    InventoryKind,
    JudgeRunState,
    Reliability,
    RemovedSecurityControlCandidate,
    RiskInventoryItem,
    RunReport,
    RunStatus,
    SecurityControlKind,
    TargetType,
    WeakenedControlCandidate,
    resolve_run_status,
)


def _gate(gate, status, code=None):
    return GateResult(gate=gate, status=status, code=code)


G1_PASS = _gate(GateId.G1, GateStatus.PASS)
G2_PASS = _gate(GateId.G2, GateStatus.PASS)
G2_SKIP = _gate(GateId.G2, GateStatus.SKIPPED)


def _resolve(gates, *, s2=True, findings=0, inv=0, tt=TargetType.SYNTHETIC, track_a_required=True,
             s0_done=True, unknown_sinks=0, s3_done=True, eligible=0, judged=0, skipped=0,
             cand_inv=0):
    return resolve_run_status(
        target_type=tt,
        gate_results=gates,
        s2_completed=s2,
        finding_count=findings,
        risk_inventory_count=inv,
        track_a_required=track_a_required,
        s0_attribution_completed=s0_done,
        unknown_sink_candidate_count=unknown_sinks,
        s3_completed=s3_done,
        llm_eligible_count=eligible,
        judged_count=judged,
        judgement_skipped_count=skipped,
        candidate_inventory_count=cand_inv,
    )


# --- precedence (계획 §0.2) ------------------------------------------------- #
def test_g1_fail_dominates():
    st, rel = _resolve([_gate(GateId.G1, GateStatus.FAIL, GateFailureCode.G1_DIFF), G2_PASS])
    assert st == RunStatus.DIFF_SCOPE_MISSING
    assert rel == Reliability.UNRELIABLE


def test_g2_not_run_hard_fail():
    st, _ = _resolve([G1_PASS, _gate(GateId.G2, GateStatus.FAIL, GateFailureCode.G2_SOURCE_NOT_RUN)])
    assert st == RunStatus.FRAMEWORK_SOURCE_VALIDATION_NOT_RUN


def test_g2_source_zero_hard_fail():
    st, _ = _resolve([G1_PASS, _gate(GateId.G2, GateStatus.FAIL, GateFailureCode.G2_SOURCE_ZERO)])
    assert st == RunStatus.FRAMEWORK_SOURCE_MODEL_MISSING


def test_s2_failure_is_analysis_error():
    st, _ = _resolve([G1_PASS, G2_PASS], s2=False)
    assert st == RunStatus.ANALYSIS_ERROR


def test_g3_eval_fail():
    st, _ = _resolve([G1_PASS, G2_PASS, _gate(GateId.G3, GateStatus.FAIL, GateFailureCode.G3_EVAL)])
    assert st == RunStatus.EVAL_TARGET_INSUFFICIENT


def test_g4_authz_fail():
    st, _ = _resolve([G1_PASS, G2_PASS, _gate(GateId.G4, GateStatus.FAIL, GateFailureCode.G4_AUTHZ)])
    assert st == RunStatus.AUTHZ_SCOPE_UNDECLARED


# --- codex Q2 R2-2 + Q2r2: Track-B-only(track_a_required=False) precedence ----- #
def test_track_b_only_inventory_findings_unreliable():
    st, rel = _resolve([G1_PASS, G2_PASS], s2=False, inv=1, track_a_required=False)
    assert st == RunStatus.FINDINGS_PRESENT and rel == Reliability.UNRELIABLE


def test_track_b_only_no_inventory_analysis_error():
    st, _ = _resolve([G1_PASS, G2_PASS], s2=False, inv=0, track_a_required=False)
    assert st == RunStatus.ANALYSIS_ERROR  # taint 없이 clean 주장 금지


def test_track_b_only_g3_fail_not_bypassed():
    # codex Q2r2: inventory 있어도 G3 FAIL 이 우선 (precedence 유지)
    g3f = _gate(GateId.G3, GateStatus.FAIL, GateFailureCode.G3_EVAL)
    st, _ = _resolve([G1_PASS, G2_PASS, g3f], s2=False, inv=1, track_a_required=False)
    assert st == RunStatus.EVAL_TARGET_INSUFFICIENT


def test_track_b_only_g4_fail_not_bypassed():
    g4f = _gate(GateId.G4, GateStatus.FAIL, GateFailureCode.G4_AUTHZ)
    st, _ = _resolve([G1_PASS, G2_PASS, g4f], s2=False, inv=1, track_a_required=False)
    assert st == RunStatus.AUTHZ_SCOPE_UNDECLARED


def test_track_a_required_default_s2_incomplete_is_error():
    # 기본(track_a_required=True): inventory 있어도 s2 미완료면 ANALYSIS_ERROR (API 보수 동작 보존)
    st, _ = _resolve([G1_PASS, G2_PASS], s2=False, inv=1)
    assert st == RunStatus.ANALYSIS_ERROR


def test_smoke_degraded_no_findings():
    st, rel = _resolve(
        [G1_PASS, _gate(GateId.G2, GateStatus.DEGRADED, GateFailureCode.G2_SOURCE_NOT_RUN)],
        tt=TargetType.SMOKE,
    )
    assert st == RunStatus.COMPLETED_DEGRADED
    assert rel == Reliability.UNRELIABLE


def test_smoke_degraded_with_findings():
    st, rel = _resolve(
        [G1_PASS, _gate(GateId.G2, GateStatus.DEGRADED, GateFailureCode.G2_SOURCE_NOT_RUN)],
        findings=1,
        tt=TargetType.SMOKE,
    )
    assert st == RunStatus.FINDINGS_PRESENT
    assert rel == Reliability.UNRELIABLE


def test_non_smoke_degraded_escalates_to_hard_fail():
    """codex p0code1: degraded 는 smoke 에서만. synthetic 이면 hard fail 승격."""
    st, _ = _resolve(
        [G1_PASS, _gate(GateId.G2, GateStatus.DEGRADED, GateFailureCode.G2_SOURCE_ZERO)],
        tt=TargetType.KNOWN_CVE,
    )
    assert st == RunStatus.FRAMEWORK_SOURCE_MODEL_MISSING


def test_clean_no_vuln():
    st, rel = _resolve([G1_PASS, G2_PASS])
    assert st == RunStatus.NO_VULN_FOUND
    assert rel == Reliability.RELIABLE


def test_findings_present_reliable():
    st, rel = _resolve([G1_PASS, G2_PASS], inv=2)
    assert st == RunStatus.FINDINGS_PRESENT
    assert rel == Reliability.RELIABLE


def test_g2_skipped_proceeds():
    st, _ = _resolve([G1_PASS, G2_SKIP])
    assert st == RunStatus.NO_VULN_FOUND


# --- 전체 5단계 MVP fail-closed (codex MVP r2 C1/C2/M2) --------------------- #
def test_s3_not_run_with_eligible_is_semantic_judge_not_run():
    """eligible 후보 있는데 S3 미실행 → SEMANTIC_JUDGE_NOT_RUN(NO_VULN 오독 금지)."""
    st, rel = _resolve([G1_PASS, G2_PASS], eligible=1, s3_done=False)
    assert st == RunStatus.SEMANTIC_JUDGE_NOT_RUN
    assert rel == Reliability.UNRELIABLE


def test_s3_partial_judging_is_semantic_judge_not_run():
    """eligible 2 인데 1 만 judged(1 skipped) → 전원 판정 아님 → SEMANTIC_JUDGE_NOT_RUN."""
    st, _ = _resolve([G1_PASS, G2_PASS], eligible=2, judged=1, skipped=1)
    assert st == RunStatus.SEMANTIC_JUDGE_NOT_RUN


def test_s3_all_judged_clean_is_no_vuln():
    """eligible 전원 judged + finding 0 → NO_VULN_FOUND(정상 clean)."""
    st, rel = _resolve([G1_PASS, G2_PASS], eligible=2, judged=2, s3_done=True)
    assert st == RunStatus.NO_VULN_FOUND
    assert rel == Reliability.RELIABLE


def test_s3_no_eligible_clean_is_no_vuln():
    """eligible 0(후보 없음/비대상) → S3 미실행이어도 clean 정상(빈 결과지만 오독 아님)."""
    st, _ = _resolve([G1_PASS, G2_PASS], eligible=0, s3_done=False)
    assert st == RunStatus.NO_VULN_FOUND


def test_s0_attribution_incomplete_is_analysis_error():
    """S0 blame 귀속 미완 → AI-라인 기반 불확실 → ANALYSIS_ERROR(clean 금지)."""
    st, _ = _resolve([G1_PASS, G2_PASS], s0_done=False)
    assert st == RunStatus.ANALYSIS_ERROR


def test_unknown_sink_candidate_is_analysis_error():
    """AI 귀속 UNKNOWN 인 KB sink 존재 → clean 주장 금지(codex r2 C2)."""
    st, _ = _resolve([G1_PASS, G2_PASS], unknown_sinks=1)
    assert st == RunStatus.ANALYSIS_ERROR


def test_candidate_inventory_blocks_no_vuln():
    """judged finding 0 이어도 candidate_inventory(Track A′/heuristic)>0 → FINDINGS_PRESENT(clean 금지)."""
    st, rel = _resolve([G1_PASS, G2_PASS], cand_inv=2)
    assert st == RunStatus.FINDINGS_PRESENT
    assert rel == Reliability.RELIABLE


def test_unknown_sink_precedes_g3_g4():
    """codex S1 r2: UNKNOWN sink fail-closed 가 G3/G4 fail 보다 우선(분석 완료성 먼저)."""
    g3f = _gate(GateId.G3, GateStatus.FAIL, GateFailureCode.G3_EVAL)
    g4f = _gate(GateId.G4, GateStatus.FAIL, GateFailureCode.G4_AUTHZ)
    assert _resolve([G1_PASS, G2_PASS, g3f], unknown_sinks=1)[0] == RunStatus.ANALYSIS_ERROR
    assert _resolve([G1_PASS, G2_PASS, g4f], unknown_sinks=1)[0] == RunStatus.ANALYSIS_ERROR


def test_unknown_sink_track_b_only_is_analysis_error():
    """codex S1 r2: track-B-only(s2 미완)에서도 UNKNOWN sink → FINDINGS_PRESENT 아니라 ANALYSIS_ERROR."""
    st, _ = _resolve([G1_PASS, G2_PASS], s2=False, inv=1, track_a_required=False, unknown_sinks=1)
    assert st == RunStatus.ANALYSIS_ERROR


def test_s3_failclosed_precedes_g3g4():
    """fail-closed 위치: S0/S3 미완은 G3/G4 fail 보다 먼저(분석 완료성이 우선)."""
    # eligible+미실행 인데 G3 도 fail → SEMANTIC_JUDGE_NOT_RUN 가 먼저
    st, _ = _resolve([G1_PASS, G2_PASS, _gate(GateId.G3, GateStatus.FAIL, GateFailureCode.G3_EVAL)],
                     eligible=1, s3_done=False)
    assert st == RunStatus.SEMANTIC_JUDGE_NOT_RUN


# --- codex p0code1: 빈 게이트/누락/중복 (빈 결과 오독 금지) ------------------ #
def test_empty_gates_not_no_vuln():
    st, _ = _resolve([])
    assert st == RunStatus.DIFF_SCOPE_MISSING  # G1 없음 ≠ 통과


def test_missing_g2_is_not_run():
    st, _ = _resolve([G1_PASS])  # G2 없음
    assert st == RunStatus.FRAMEWORK_SOURCE_VALIDATION_NOT_RUN


def test_duplicate_gate_rejected():
    with pytest.raises(ValueError):
        _resolve([G1_PASS, G2_PASS, G2_PASS])


# --- GateResult schema (codex p0code1) ------------------------------------- #
def test_gateresult_fail_requires_code():
    with pytest.raises(ValidationError):
        GateResult(gate=GateId.G2, status=GateStatus.FAIL)  # code 없음


def test_gateresult_pass_forbids_code():
    with pytest.raises(ValidationError):
        GateResult(gate=GateId.G2, status=GateStatus.PASS, code=GateFailureCode.G2_SOURCE_ZERO)


# --- RunReport 불변식 ------------------------------------------------------- #
def _valid_no_vuln_report(**kw):
    base = dict(
        run_id="r1",
        target_type=TargetType.SYNTHETIC,
        run_status=RunStatus.NO_VULN_FOUND,
        reliability=Reliability.RELIABLE,
        s2_completed=True,
        gate_results=[G1_PASS, G2_PASS],
    )
    base.update(kw)
    return RunReport(**base)


def test_no_vuln_report_valid():
    r = _valid_no_vuln_report()
    assert r.run_status == RunStatus.NO_VULN_FOUND


def test_no_vuln_report_requires_gates():
    """codex p0code1: 빈 gate_results 로 NO_VULN_FOUND 통과 금지."""
    with pytest.raises(ValidationError):
        _valid_no_vuln_report(gate_results=[])


def test_no_vuln_report_requires_reliable():
    with pytest.raises(ValidationError):
        _valid_no_vuln_report(reliability=Reliability.UNRELIABLE)


def test_no_vuln_report_rejects_nonempty_inventory():
    item = RiskInventoryItem(
        item_id="TB-1",
        inventory_kind=InventoryKind.REMOVED_SECURITY_CONTROL,
        file="a.py",
        line_or_deleted_line="10-14",
    )
    with pytest.raises(ValidationError):
        _valid_no_vuln_report(risk_inventory=[item])


def test_findings_present_empty_rejected():
    """codex p0code1: FINDINGS_PRESENT 인데 findings/inventory 둘 다 비면 모순."""
    with pytest.raises(ValidationError):
        RunReport(
            run_id="r1",
            target_type=TargetType.SYNTHETIC,
            run_status=RunStatus.FINDINGS_PRESENT,
            reliability=Reliability.RELIABLE,
            s2_completed=True,
            gate_results=[G1_PASS, G2_PASS],
        )


def test_degraded_report_requires_smoke_and_g2_degraded():
    with pytest.raises(ValidationError):
        RunReport(
            run_id="r1",
            target_type=TargetType.SYNTHETIC,  # smoke 아님
            run_status=RunStatus.COMPLETED_DEGRADED,
            reliability=Reliability.UNRELIABLE,
            s2_completed=True,
            gate_results=[G1_PASS, G2_PASS],
        )


def test_degraded_report_valid():
    r = RunReport(
        run_id="r1",
        target_type=TargetType.SMOKE,
        run_status=RunStatus.COMPLETED_DEGRADED,
        reliability=Reliability.UNRELIABLE,
        s2_completed=True,
        gate_results=[G1_PASS, _gate(GateId.G2, GateStatus.DEGRADED, GateFailureCode.G2_SOURCE_NOT_RUN)],
    )
    assert r.reliability == Reliability.UNRELIABLE


def test_runreport_duplicate_gate_rejected():
    with pytest.raises(ValidationError):
        _valid_no_vuln_report(gate_results=[G1_PASS, G2_PASS, G2_PASS])


# --- Track B candidate 불변식 ---------------------------------------------- #
def _rsc(**kw):
    base = dict(
        candidate_id="RSC-1",
        repo="r",
        base_sha="b",
        head_sha="h",
        file="app.py",
        deleted_line_start=10,
        deleted_line_end=14,
        deleted_code="if not user.is_admin: raise PermissionError",
        security_control_kind=SecurityControlKind.AUTHZ_CHECK,
        ai_attribution=DeletionAttribution.CONFIRMED_AI,
        deletion_attribution_source=DeletionAttributionSource.SINGLE_COMMIT_PR,
    )
    base.update(kw)
    return RemovedSecurityControlCandidate(**base)


def _weak(**kw):
    base = dict(
        candidate_id="WC-1",
        repo="r",
        base_sha="b",
        head_sha="h",
        file="app.py",
        line_start=10,
        line_end=10,
        weakening_kind="verify_disabled",
        ai_attribution=DeletionAttribution.CONFIRMED_AI,
        deletion_attribution_source=DeletionAttributionSource.SINGLE_COMMIT_PR,
    )
    base.update(kw)
    return WeakenedControlCandidate(**base)


def test_rsc_valid():
    c = _rsc()
    assert c.risk_track.value == "track_b"
    assert c.auto_confirmed is False
    assert c.requires_manual_review is True


def test_rsc_squash_cannot_be_confirmed():
    with pytest.raises(ValidationError):
        _rsc(
            deletion_attribution_source=DeletionAttributionSource.PR_METADATA_ONLY,
            ai_attribution=DeletionAttribution.CONFIRMED_AI,
        )


def test_rsc_squash_probable_metadata_ok():
    c = _rsc(
        deletion_attribution_source=DeletionAttributionSource.PR_METADATA_ONLY,
        ai_attribution=DeletionAttribution.PROBABLE_AI_FROM_PR_METADATA,
    )
    assert c.ai_attribution == DeletionAttribution.PROBABLE_AI_FROM_PR_METADATA


def test_rsc_never_auto_confirmed():
    with pytest.raises(ValidationError):
        _rsc(auto_confirmed=True)


def test_rsc_requires_manual_review():
    with pytest.raises(ValidationError):
        _rsc(requires_manual_review=False)


def test_rsc_wrong_inventory_kind_rejected():
    with pytest.raises(ValidationError):
        _rsc(inventory_kind=InventoryKind.WEAKENED_CONTROL)


def test_weakened_squash_cannot_be_confirmed():
    """codex p0code1: WeakenedControl 도 동일 squash 강등."""
    with pytest.raises(ValidationError):
        _weak(
            deletion_attribution_source=DeletionAttributionSource.PR_METADATA_ONLY,
            ai_attribution=DeletionAttribution.CONFIRMED_AI,
        )


def test_weakened_never_auto_confirmed():
    with pytest.raises(ValidationError):
        _weak(auto_confirmed=True)


def test_risk_inventory_requires_manual_review():
    with pytest.raises(ValidationError):
        RiskInventoryItem(
            item_id="TB-1",
            inventory_kind=InventoryKind.REMOVED_SECURITY_CONTROL,
            file="a.py",
            line_or_deleted_line="10",
            requires_manual_review=False,
        )


def test_track_b_disclosure_text():
    from auditai.contracts import TRACK_B_DISCLOSURE

    assert "not automatically confirmed" in TRACK_B_DISCLOSURE
    assert "Manual review is required" in TRACK_B_DISCLOSURE


# --- hard-fail RunStatus 도 gate-evidence 로 잠금 (codex p0code2) ------------ #
G1_FAIL = _gate(GateId.G1, GateStatus.FAIL, GateFailureCode.G1_DIFF)
G2_ZERO = _gate(GateId.G2, GateStatus.FAIL, GateFailureCode.G2_SOURCE_ZERO)
G2_NOTRUN = _gate(GateId.G2, GateStatus.FAIL, GateFailureCode.G2_SOURCE_NOT_RUN)
G3_FAIL = _gate(GateId.G3, GateStatus.FAIL, GateFailureCode.G3_EVAL)
G4_FAIL = _gate(GateId.G4, GateStatus.FAIL, GateFailureCode.G4_AUTHZ)


def _report(status, reliability, gates, *, tt=TargetType.SYNTHETIC, s2=True, findings=None, inv=None,
            s0_done=True, s3_done=True):
    return RunReport(
        run_id="r",
        target_type=tt,
        run_status=status,
        reliability=reliability,
        s2_completed=s2,
        gate_results=gates,
        findings=findings or [],
        risk_inventory=inv or [],
        s0_attribution_completed=s0_done,
        s3_completed=s3_done,
    )


def test_diff_scope_missing_requires_g1_fail():
    _report(RunStatus.DIFF_SCOPE_MISSING, Reliability.UNRELIABLE, [G1_FAIL])
    with pytest.raises(ValidationError):
        _report(RunStatus.DIFF_SCOPE_MISSING, Reliability.UNRELIABLE, [G1_PASS, G2_PASS])


def test_model_missing_requires_g2_zero():
    _report(RunStatus.FRAMEWORK_SOURCE_MODEL_MISSING, Reliability.UNRELIABLE, [G1_PASS, G2_ZERO])
    with pytest.raises(ValidationError):
        _report(
            RunStatus.FRAMEWORK_SOURCE_MODEL_MISSING, Reliability.UNRELIABLE, [G1_PASS, G2_NOTRUN]
        )


def test_not_run_requires_g2_missing_or_notrun():
    _report(RunStatus.FRAMEWORK_SOURCE_VALIDATION_NOT_RUN, Reliability.UNRELIABLE, [G1_PASS])
    _report(
        RunStatus.FRAMEWORK_SOURCE_VALIDATION_NOT_RUN, Reliability.UNRELIABLE, [G1_PASS, G2_NOTRUN]
    )
    with pytest.raises(ValidationError):
        _report(
            RunStatus.FRAMEWORK_SOURCE_VALIDATION_NOT_RUN, Reliability.UNRELIABLE, [G1_PASS, G2_ZERO]
        )


def test_hard_fail_must_not_be_reliable():
    with pytest.raises(ValidationError):
        _report(RunStatus.DIFF_SCOPE_MISSING, Reliability.RELIABLE, [G1_FAIL])


def test_eval_insufficient_requires_g3_fail():
    _report(RunStatus.EVAL_TARGET_INSUFFICIENT, Reliability.UNRELIABLE, [G1_PASS, G2_PASS, G3_FAIL])
    with pytest.raises(ValidationError):
        _report(RunStatus.EVAL_TARGET_INSUFFICIENT, Reliability.UNRELIABLE, [G1_PASS, G2_PASS])


def test_authz_undeclared_requires_g4_fail():
    _report(RunStatus.AUTHZ_SCOPE_UNDECLARED, Reliability.UNRELIABLE, [G1_PASS, G2_PASS, G4_FAIL])
    with pytest.raises(ValidationError):
        _report(RunStatus.AUTHZ_SCOPE_UNDECLARED, Reliability.UNRELIABLE, [G1_PASS, G2_PASS])


# --- resolver ↔ RunReport round-trip (codex 역방향 모순 우려) --------------- #
@pytest.mark.parametrize(
    "gates,s2,findings,inv,tt",
    [
        ([G1_PASS, G2_PASS], True, 0, 0, TargetType.SYNTHETIC),  # NO_VULN_FOUND
        ([G1_PASS, G2_SKIP], True, 0, 0, TargetType.SYNTHETIC),  # NO_VULN (G2 skip)
        ([G1_PASS, G2_PASS], True, 0, 2, TargetType.SYNTHETIC),  # FINDINGS_PRESENT
        ([G1_FAIL, G2_PASS], True, 0, 0, TargetType.SYNTHETIC),  # DIFF_SCOPE_MISSING
        ([G1_PASS, G2_ZERO], True, 0, 0, TargetType.KNOWN_CVE),  # MODEL_MISSING
        ([G1_PASS, G2_NOTRUN], True, 0, 0, TargetType.KNOWN_CVE),  # NOT_RUN
        (
            [G1_PASS, _gate(GateId.G2, GateStatus.DEGRADED, GateFailureCode.G2_SOURCE_NOT_RUN)],
            True, 0, 0, TargetType.SMOKE,
        ),  # COMPLETED_DEGRADED
        ([G1_PASS, G2_PASS], False, 0, 0, TargetType.SYNTHETIC),  # ANALYSIS_ERROR
        ([G1_PASS, G2_PASS, G3_FAIL], True, 0, 0, TargetType.SYNTHETIC),  # EVAL_TARGET_INSUFFICIENT
        ([G1_PASS, G2_PASS, G4_FAIL], True, 0, 0, TargetType.SYNTHETIC),  # AUTHZ_SCOPE_UNDECLARED
    ],
)
def test_resolver_output_builds_valid_report(gates, s2, findings, inv, tt):
    """resolver 가 낸 (status, reliability) + 동일 gates 로 만든 RunReport 는 항상 valid."""
    st, rel = resolve_run_status(
        target_type=tt,
        gate_results=gates,
        s2_completed=s2,
        finding_count=findings,
        risk_inventory_count=inv,
    )
    f = (
        [FindingReport(finding_id="f", title="t", severity="high", cwe="CWE-78", file="a.py", line=1)]
        if findings
        else []
    )
    rinv = (
        [
            RiskInventoryItem(
                item_id="t",
                inventory_kind=InventoryKind.REMOVED_SECURITY_CONTROL,
                file="a.py",
                line_or_deleted_line="1",
            )
        ]
        if inv
        else []
    )
    # 예외 없이 생성되면 resolver↔RunReport 정합
    _report(st, rel, gates, tt=tt, s2=s2, findings=f, inv=rinv)


# --- codex p0code3 추가: 위임으로 닫힌 모순들 직접 확인 --------------------- #
def test_gate_code_must_match_gate():
    """G2 에 G3 code 같은 잘못된 대응 거부."""
    with pytest.raises(ValidationError):
        GateResult(gate=GateId.G2, status=GateStatus.FAIL, code=GateFailureCode.G3_EVAL)


def test_findings_present_with_g3_fail_is_contradiction():
    """resolver 는 G3 fail 을 EVAL 로 먼저 반환 → FINDINGS_PRESENT 선언은 모순."""
    inv = [
        RiskInventoryItem(
            item_id="t",
            inventory_kind=InventoryKind.REMOVED_SECURITY_CONTROL,
            file="a.py",
            line_or_deleted_line="1",
        )
    ]
    with pytest.raises(ValidationError):
        _report(RunStatus.FINDINGS_PRESENT, Reliability.RELIABLE, [G1_PASS, G2_PASS, G3_FAIL], inv=inv)


def test_smoke_findings_reliability_must_be_unreliable():
    """smoke + G2 degraded + findings → resolver 는 UNRELIABLE. RELIABLE 선언 거부."""
    g2deg = _gate(GateId.G2, GateStatus.DEGRADED, GateFailureCode.G2_SOURCE_NOT_RUN)
    inv = [
        RiskInventoryItem(
            item_id="t",
            inventory_kind=InventoryKind.REMOVED_SECURITY_CONTROL,
            file="a.py",
            line_or_deleted_line="1",
        )
    ]
    with pytest.raises(ValidationError):
        _report(
            RunStatus.FINDINGS_PRESENT, Reliability.RELIABLE, [G1_PASS, g2deg],
            tt=TargetType.SMOKE, inv=inv,
        )


def test_out_of_mvp_scope_constraints():
    # ok (분석 안 함): s0/s3 도 미실행(False) 이어야 (codex MVP step1 r2 M3)
    _report(RunStatus.OUT_OF_MVP_SCOPE, Reliability.UNRELIABLE, [], s2=False, s0_done=False, s3_done=False)
    with pytest.raises(ValidationError):
        _report(RunStatus.OUT_OF_MVP_SCOPE, Reliability.RELIABLE, [], s2=False,
                s0_done=False, s3_done=False)  # reliable 금지
    # s0/s3 가 실행됨(True)인데 OUT_OF_MVP → 모순 거부
    with pytest.raises(ValidationError):
        _report(RunStatus.OUT_OF_MVP_SCOPE, Reliability.UNRELIABLE, [], s2=False)  # s0/s3 default True
    inv = [
        RiskInventoryItem(
            item_id="t",
            inventory_kind=InventoryKind.REMOVED_SECURITY_CONTROL,
            file="a.py",
            line_or_deleted_line="1",
        )
    ]
    with pytest.raises(ValidationError):
        _report(RunStatus.OUT_OF_MVP_SCOPE, Reliability.UNRELIABLE, [], s2=False, inv=inv)  # 결과 금지


def test_out_of_mvp_requires_s2_not_completed():
    """codex p0code5: out-of-scope 면 분석을 안 했으니 s2_completed=False 여야."""
    with pytest.raises(ValidationError):
        _report(RunStatus.OUT_OF_MVP_SCOPE, Reliability.UNRELIABLE, [], s2=True)


def test_out_of_mvp_rejects_gates():
    """codex p0code4: gate 돌렸으면 out-of-scope 아님 (escape hatch 차단)."""
    with pytest.raises(ValidationError):
        _report(RunStatus.OUT_OF_MVP_SCOPE, Reliability.UNRELIABLE, [G1_PASS, G2_PASS], s2=False)


# --- codex p0code4: gate status 매트릭스 ----------------------------------- #
def test_g1_cannot_be_skipped():
    """G1(diff scope)은 절대 skip 불가."""
    with pytest.raises(ValidationError):
        GateResult(gate=GateId.G1, status=GateStatus.SKIPPED)


def test_g1_cannot_be_degraded():
    with pytest.raises(ValidationError):
        GateResult(gate=GateId.G1, status=GateStatus.DEGRADED, code=GateFailureCode.G1_DIFF)


def test_degraded_only_for_g2():
    """DEGRADED 는 G2 전용 (G3/G4 degraded 금지)."""
    with pytest.raises(ValidationError):
        GateResult(gate=GateId.G3, status=GateStatus.DEGRADED, code=GateFailureCode.G3_EVAL)
    with pytest.raises(ValidationError):
        GateResult(gate=GateId.G4, status=GateStatus.DEGRADED, code=GateFailureCode.G4_AUTHZ)


def test_g3_g4_cannot_be_skipped():
    with pytest.raises(ValidationError):
        GateResult(gate=GateId.G3, status=GateStatus.SKIPPED)


# --- 전체 5단계 MVP 신규 모델 (codex MVP r2) ------------------------------- #
def test_judge_run_state_values():
    assert {s.value for s in JudgeRunState} == {"judged", "skipped", "failed"}


def test_candidate_inventory_never_auto_confirmed():
    with pytest.raises(ValidationError):
        CandidateInventoryItem(
            candidate_id="S1-1", candidate_type=CandidateType.STATIC_PATTERN_RISK,
            file="a.py", line=10, ai_attribution_state=AttributionState.CONFIRMED_AI,
            auto_confirmed=True,
        )


def test_candidate_inventory_valid():
    item = CandidateInventoryItem(
        candidate_id="S1-1", candidate_type=CandidateType.STATIC_PATTERN_RISK,
        file="a.py", line=10, capability_id="command_execution",
        ai_attribution_state=AttributionState.UNKNOWN_DUE_TO_HISTORY_LOSS,
        reason="sink without source",
    )
    assert item.requires_manual_review is True and item.auto_confirmed is False


def test_codeql_taint_result_basic():
    r = CodeQLTaintResult(
        result_id="R0-F0001", rule_id="py/command-line-injection", cwe="CWE-78",
        primary_file="api.py", primary_start_line=10, primary_end_line=10,
        sink_file="api.py", sink_start_line=10, sink_end_line=10,
    )
    assert r.cwe == "CWE-78" and r.sink_start_line == 10


def test_flow_evidence_approximation_kind():
    """근사 표기: approximation_kind set + static_path_confirmed True + confidence<1."""
    ev = FlowEvidence(
        candidate_id="S1-1", source_to_sink_flow_exists=True, static_path_confirmed=True,
        approximation_kind="generic_codeql_ai_sink_intersection", confidence=0.6,
        evidence_backend_version="2.25.6",
    )
    assert ev.approximation_kind == "generic_codeql_ai_sink_intersection"
    assert ev.confidence < 1.0
    # 기본은 None(split-config 정밀 의미, 현재 미산출)
    ev2 = FlowEvidence(candidate_id="x", source_to_sink_flow_exists=False, static_path_confirmed=False)
    assert ev2.approximation_kind is None


def test_runreport_semantic_judge_not_run_roundtrips():
    """eligible>0 + S3 미실행 → SEMANTIC_JUDGE_NOT_RUN 보고서가 resolver 와 일치(검증 통과)."""
    r = RunReport(
        run_id="r1", target_type=TargetType.SYNTHETIC,
        run_status=RunStatus.SEMANTIC_JUDGE_NOT_RUN, reliability=Reliability.UNRELIABLE,
        s2_completed=True, gate_results=[G1_PASS, G2_PASS],
        llm_eligible_count=1, s3_completed=False, judged_count=0,
    )
    assert r.run_status == RunStatus.SEMANTIC_JUDGE_NOT_RUN


def test_runreport_candidate_inventory_makes_findings_present():
    inv = CandidateInventoryItem(
        candidate_id="S1-1", candidate_type=CandidateType.STATIC_PATTERN_RISK,
        file="a.py", line=10, ai_attribution_state=AttributionState.CONFIRMED_AI,
    )
    r = RunReport(
        run_id="r1", target_type=TargetType.SYNTHETIC,
        run_status=RunStatus.FINDINGS_PRESENT, reliability=Reliability.RELIABLE,
        s2_completed=True, gate_results=[G1_PASS, G2_PASS], candidate_inventory=[inv],
    )
    assert r.run_status == RunStatus.FINDINGS_PRESENT


# --- codex MVP step1 불변식 강화 (M2/M3/M4/Minor) --------------------------- #
def _mvp_report(**kw):
    base = dict(
        run_id="r1", target_type=TargetType.SYNTHETIC,
        run_status=RunStatus.NO_VULN_FOUND, reliability=Reliability.RELIABLE,
        s2_completed=True, gate_results=[G1_PASS, G2_PASS],
    )
    base.update(kw)
    return RunReport(**base)


def test_judge_counts_cannot_exceed_eligible():
    """M2: judged/skipped 가 eligible 초과하거나 합이 초과하면 거부(모순 차단)."""
    with pytest.raises(ValidationError):
        _mvp_report(run_status=RunStatus.NO_VULN_FOUND, llm_eligible_count=1, judged_count=2)
    with pytest.raises(ValidationError):
        _mvp_report(llm_eligible_count=1, judgement_skipped_count=2)
    with pytest.raises(ValidationError):
        _mvp_report(llm_eligible_count=2, judged_count=1, judgement_skipped_count=2)


def test_negative_counts_rejected():
    with pytest.raises(ValidationError):
        _mvp_report(llm_eligible_count=-1)


def test_unknown_candidate_inventory_forces_analysis_error():
    """M3: candidate_inventory 에 UNKNOWN 귀속 후보가 있으면 count 필드가 0 이어도 derive 로
    fail-closed(ANALYSIS_ERROR) — FINDINGS_PRESENT 로 둔갑 불가."""
    unk = CandidateInventoryItem(
        candidate_id="S1-u", candidate_type=CandidateType.STATIC_PATTERN_RISK,
        file="a.py", line=10, ai_attribution_state=AttributionState.UNKNOWN_DUE_TO_HISTORY_LOSS,
    )
    # FINDINGS_PRESENT 로 만들려 하면 resolver 는 ANALYSIS_ERROR 를 기대 → mismatch 거부
    with pytest.raises(ValidationError):
        _mvp_report(run_status=RunStatus.FINDINGS_PRESENT, candidate_inventory=[unk],
                    unknown_sink_candidate_count=0)
    # 올바르게 ANALYSIS_ERROR 로 만들면 통과
    r = _mvp_report(run_status=RunStatus.ANALYSIS_ERROR, reliability=Reliability.UNRELIABLE,
                    candidate_inventory=[unk], unknown_sink_candidate_count=0)
    assert r.run_status == RunStatus.ANALYSIS_ERROR


def test_approximation_kind_invariants():
    """M4: approximation_kind set 이면 confirmed=True+flow=True+confidence<1+backend_version 필수."""
    # 정상
    ok = FlowEvidence(candidate_id="c", source_to_sink_flow_exists=True, static_path_confirmed=True,
                      approximation_kind="generic_codeql_ai_sink_intersection", confidence=0.6,
                      evidence_backend_version="2.25.6")
    assert ok.approximation_kind is not None
    # static_path_confirmed=False 인데 approximation_kind set → 거부
    with pytest.raises(ValidationError):
        FlowEvidence(candidate_id="c", source_to_sink_flow_exists=True, static_path_confirmed=False,
                     approximation_kind="generic_codeql_ai_sink_intersection", confidence=0.6,
                     evidence_backend_version="2.25.6")
    # confidence=1.0 → 거부
    with pytest.raises(ValidationError):
        FlowEvidence(candidate_id="c", source_to_sink_flow_exists=True, static_path_confirmed=True,
                     approximation_kind="generic_codeql_ai_sink_intersection", confidence=1.0,
                     evidence_backend_version="2.25.6")
    # backend_version 없음 → 거부
    with pytest.raises(ValidationError):
        FlowEvidence(candidate_id="c", source_to_sink_flow_exists=True, static_path_confirmed=True,
                     approximation_kind="generic_codeql_ai_sink_intersection", confidence=0.6)


def test_candidate_inventory_requires_manual_review():
    with pytest.raises(ValidationError):
        CandidateInventoryItem(
            candidate_id="S1-1", candidate_type=CandidateType.STATIC_PATTERN_RISK,
            file="a.py", line=10, ai_attribution_state=AttributionState.CONFIRMED_AI,
            requires_manual_review=False,
        )


def test_codeql_taint_result_columns():
    """M5: sink column 필드로 exact-overlap 표현 가능."""
    r = CodeQLTaintResult(
        result_id="R0-F1", rule_id="py/code-injection", cwe="CWE-94",
        primary_file="a.py", primary_start_line=5, primary_end_line=5,
        primary_start_col=12, primary_end_col=20,
        sink_file="a.py", sink_start_line=5, sink_end_line=5,
        sink_start_col=12, sink_end_col=20,
    )
    assert r.sink_start_col == 12 and r.sink_end_col == 20


# --- codex MVP step1 r2 (M2/M3) -------------------------------------------- #
def test_static_path_confirmed_requires_approximation_kind_in_mvp():
    """M2: MVP 에서 static_path_confirmed=True 인데 approximation_kind=None → 거부(정밀 위장 차단)."""
    with pytest.raises(ValidationError):
        FlowEvidence(candidate_id="c", source_to_sink_flow_exists=True, static_path_confirmed=True,
                     approximation_kind=None, confidence=1.0)


def test_location_span_and_candidate_sink_span():
    """M3: LocationSpan + CandidateInventoryItem.sink_span 으로 양쪽 span 표현."""
    from auditai.contracts import LocationSpan

    span = LocationSpan(file="a.py", start_line=10, end_line=10, start_col=4, end_col=22)
    item = CandidateInventoryItem(
        candidate_id="S1-1", candidate_type=CandidateType.STATIC_PATTERN_RISK,
        file="a.py", line=10, sink_span=span,
        ai_attribution_state=AttributionState.CONFIRMED_AI,
    )
    assert item.sink_span.start_col == 4 and item.sink_span.end_col == 22


def test_out_of_mvp_rejects_nonzero_counts():
    """M3: OUT_OF_MVP 인데 MVP count 가 채워지면 거부(분석 안 함 marker 일관)."""
    with pytest.raises(ValidationError):
        RunReport(
            run_id="r", target_type=TargetType.SYNTHETIC,
            run_status=RunStatus.OUT_OF_MVP_SCOPE, reliability=Reliability.UNRELIABLE,
            s2_completed=False, gate_results=[], s0_attribution_completed=False, s3_completed=False,
            llm_eligible_count=1,  # 분석 안 했는데 count > 0 → 모순
        )
