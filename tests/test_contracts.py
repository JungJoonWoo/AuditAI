"""데이터 계약 불변식 테스트 (codex 보존 계약)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from auditai.contracts import (
    CandidateSource,
    CandidateType,
    EvidenceKind,
    FindingCandidate,
    FindingReport,
    FlowEvidence,
    HumanReviewState,
    PathLeg,
    PathNode,
    SemanticJudgement,
    Track,
    Verdict,
    compute_llm_eligible,
)


def _candidate(**kw) -> FindingCandidate:
    base = dict(
        candidate_id="c1",
        candidate_type=CandidateType.TAINT_PATH,
        track=Track.A,
        repo="r",
        commit_sha="abc",
        file="app.py",
        candidate_source=CandidateSource.CODEQL,
        evidence_kind=EvidenceKind.CODEQL_TAINT,
    )
    base.update(kw)
    return FindingCandidate(**base)


def test_candidate_track_type_match():
    _candidate()  # taint_path + A ok


def test_candidate_track_type_mismatch_rejected():
    with pytest.raises(ValidationError):
        _candidate(candidate_type=CandidateType.AUTHZ_CANDIDATE, track=Track.A)


def test_authz_candidate_requires_track_b():
    _candidate(candidate_type=CandidateType.AUTHZ_CANDIDATE, track=Track.B)


def test_semantic_judgement_never_confirmed():
    with pytest.raises(ValidationError):
        SemanticJudgement(
            candidate_id="c1",
            verdict=Verdict.STATIC_PATH_TRIAGED_POSITIVE,
            reason="x",
            static_path_confirmed=True,
            vulnerability_confirmed=True,  # 금지
        )


def test_semantic_judgement_defaults():
    j = SemanticJudgement(
        candidate_id="c1",
        verdict=Verdict.NEEDS_MANUAL_REVIEW,
        reason="x",
        static_path_confirmed=True,
    )
    assert j.vulnerability_confirmed is False
    assert j.human_review_state == HumanReviewState.NOT_REVIEWED


def test_verdict_enum_has_no_confirmed_finding():
    assert "confirmed_finding" not in {v.value for v in Verdict}


def test_finding_report_never_confirmed():
    with pytest.raises(ValidationError):
        FindingReport(
            finding_id="f1",
            title="t",
            severity="high",
            cwe="CWE-78",
            file="app.py",
            line=5,
            vulnerability_confirmed=True,
        )


def test_candidate_has_no_llm_eligible_field():
    """codex C2-Q2: llm_eligible 은 S1 후보 필드가 아님(이중 진실원 제거) → extra forbid."""
    with pytest.raises(ValidationError):
        _candidate(llm_eligible=True)


def test_compute_llm_eligible_gate():
    """S2.5 게이트 산식 (청사진 §3.3) — 단일 진실원 LlmGateDecision."""
    taint = _candidate(evidence_kind=EvidenceKind.CODEQL_TAINT)  # candidate_id="c1"
    authz = _candidate(
        candidate_type=CandidateType.AUTHZ_CANDIDATE,
        track=Track.B,
        evidence_kind=EvidenceKind.AUTHZ_PATTERN,
    )
    flow_ok = FlowEvidence(
        candidate_id="c1", source_to_sink_flow_exists=True, static_path_confirmed=True,
        approximation_kind="generic_codeql_ai_sink_intersection", confidence=0.6,
        evidence_backend_version="2.25.6",
    )
    flow_no_static = FlowEvidence(
        candidate_id="c1", source_to_sink_flow_exists=True, static_path_confirmed=False
    )
    assert compute_llm_eligible(taint, flow_ok).llm_eligible is True
    assert compute_llm_eligible(taint, None).llm_eligible is False
    assert compute_llm_eligible(taint, flow_no_static).llm_eligible is False
    assert compute_llm_eligible(authz, flow_ok).llm_eligible is False  # inventory-only


def test_compute_llm_eligible_id_mismatch_raises():
    """codex C2-Q2: 다른 후보의 evidence 로 판정 금지."""
    taint = _candidate(evidence_kind=EvidenceKind.CODEQL_TAINT)  # candidate_id="c1"
    other = FlowEvidence(
        candidate_id="OTHER", source_to_sink_flow_exists=True, static_path_confirmed=True,
        approximation_kind="generic_codeql_ai_sink_intersection", confidence=0.6,
        evidence_backend_version="2.25.6",
    )
    with pytest.raises(ValueError):
        compute_llm_eligible(taint, other)


def test_flow_evidence_static_path_requires_flow():
    """codex Q5: static_path_confirmed=True 인데 flow 없음 → 모순."""
    with pytest.raises(ValidationError):
        FlowEvidence(
            candidate_id="c1",
            source_to_sink_flow_exists=False,
            static_path_confirmed=True,
        )


def test_s3_only_track_a():
    """codex Q6: S3 는 Track A taint_path 만 판정."""
    with pytest.raises(ValidationError):
        SemanticJudgement(
            candidate_id="c1",
            verdict=Verdict.SUSPICIOUS,
            reason="x",
            static_path_confirmed=True,
            track=Track.B,
        )


def test_extra_fields_forbidden():
    """codex Q6: confirmed_finding 같은 잉여/금지 필드는 침묵 무시되지 않고 거부."""
    with pytest.raises(ValidationError):
        SemanticJudgement(
            candidate_id="c1",
            verdict=Verdict.SUSPICIOUS,
            reason="x",
            static_path_confirmed=True,
            confirmed_finding=True,  # 금지 필드
        )


def test_flow_evidence_path_legs():
    ev = FlowEvidence(
        candidate_id="c1",
        source_to_sink_flow_exists=True,
        static_path_confirmed=True,
        approximation_kind="generic_codeql_ai_sink_intersection",
        confidence=0.6,
        evidence_backend_version="2.25.6",
        path_nodes=[
            PathNode(
                engine="codeql", node_id="n1", file="app.py", start_line=1, end_line=1,
                role="source", path_leg=PathLeg.SOURCE_TO_AI, sequence=0, path_id="p1",
            ),
            PathNode(
                engine="codeql", node_id="n2", file="app.py", start_line=5, end_line=5,
                role="sink", path_leg=PathLeg.AI_TO_SINK, sequence=1, path_id="p1",
            ),
        ],
    )
    legs = {n.path_leg for n in ev.path_nodes}
    assert legs == {PathLeg.SOURCE_TO_AI, PathLeg.AI_TO_SINK}
