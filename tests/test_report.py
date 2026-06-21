"""S4 — Finding Draft (report.py) 테스트.

검증: judged→finding, false_positive/skipped/failed 제외, title 접두 강제,
vulnerability_confirmed=False 불변, 빈 judged→S4Artifact status ok(valid-empty), MD 렌더 smoke,
S1/S2 evidence 보강(file/line/cwe/severity/path/snippets).
"""

from __future__ import annotations

import pytest

from auditai.artifacts import S1Artifact, S2Artifact, S3Artifact, StageStatus
from auditai.contracts import (
    CandidateSource,
    CandidateType,
    CodeQLTaintResult,
    EvidenceKind,
    FindingCandidate,
    FlowEvidence,
    HumanReviewState,
    JudgeOutcome,
    JudgeRunState,
    LocationSpan,
    PathNode,
    PathLeg,
    SemanticJudgement,
    Track,
    Verdict,
)
from auditai.report import (
    _normalize_cwe,
    build_findings,
    render_findings_md,
)


# --------------------------------------------------------------------------- #
# 헬퍼 — 입력 아티팩트 구성
# --------------------------------------------------------------------------- #
def _judgement(cid: str, verdict: Verdict, **kw) -> SemanticJudgement:
    return SemanticJudgement(
        candidate_id=cid, verdict=verdict, reason=kw.pop("reason", "user input reaches sink"),
        static_path_confirmed=kw.pop("static_path_confirmed", True), **kw
    )


def _judged(cid: str, verdict: Verdict, **kw) -> JudgeOutcome:
    return JudgeOutcome(
        candidate_id=cid, state=JudgeRunState.JUDGED,
        judgement=_judgement(cid, verdict, **kw), engine="fake", model="fake-model",
    )


def _skipped(cid: str) -> JudgeOutcome:
    return JudgeOutcome(candidate_id=cid, state=JudgeRunState.SKIPPED, skip_reason="budget_exceeded")


def _failed(cid: str) -> JudgeOutcome:
    return JudgeOutcome(candidate_id=cid, state=JudgeRunState.FAILED, skip_reason="parse_failed: x")


def _s3(outcomes: list[JudgeOutcome]) -> S3Artifact:
    ids = [o.candidate_id for o in outcomes]
    return S3Artifact.build(status=StageStatus.OK, repo="acme/app", commit_sha="deadbeef",
                            outcomes=outcomes, eligible_candidate_ids=ids)


def _candidate(cid: str, *, line: int = 42, cwe: str = "CWE-78") -> FindingCandidate:
    return FindingCandidate(
        candidate_id=cid, candidate_type=CandidateType.TAINT_PATH, track=Track.A,
        repo="acme/app", commit_sha="deadbeef", file="app/api.py",
        sink_span=LocationSpan(file="app/api.py", start_line=line, end_line=line),
        capability_id="cap.os_command", candidate_source=CandidateSource.AST,
        evidence_kind=EvidenceKind.REQUIRES_CODEQL_VALIDATION,
        code_snippet="subprocess.run(cmd, shell=True)",
        recall_reason=f"sink matches KB {cwe}",
    )


def _s1(cands: list[FindingCandidate]) -> S1Artifact:
    return S1Artifact(status=StageStatus.OK, repo="acme/app", commit_sha="deadbeef",
                      candidates=cands)


def _evidence(cid: str) -> FlowEvidence:
    return FlowEvidence(
        candidate_id=cid, source_to_sink_flow_exists=True, static_path_confirmed=True,
        approximation_kind="generic_codeql_ai_sink_intersection", confidence=0.6,
        evidence_backend_version="2.25.6", sink="app/api.py:42",
        flow_path=["src: request.query[cmd]", "sink: subprocess.run"],
        path_nodes=[
            PathNode(engine="codeql", node_id="n1", file="app/api.py", start_line=10, end_line=10,
                     role="source", code="cmd = request.query['cmd']", path_leg=PathLeg.SOURCE_TO_AI,
                     sequence=0, path_id="p1"),
            PathNode(engine="codeql", node_id="n2", file="app/api.py", start_line=42, end_line=42,
                     role="sink", code="subprocess.run(cmd, shell=True)",
                     path_leg=PathLeg.AI_TO_SINK, sequence=1, path_id="p1"),
        ],
    )


def _s2(cid: str) -> S2Artifact:
    return S2Artifact(
        status=StageStatus.OK, repo="acme/app", commit_sha="deadbeef", s2_completed=True,
        codeql_version="2.25.6", evidence=[_evidence(cid)],
        taint_results=[CodeQLTaintResult(
            result_id="R0-F0001", rule_id="py/command-injection", cwe="CWE-78",
            severity="error", primary_file="app/api.py", primary_start_line=42,
            primary_end_line=42, sink_file="app/api.py", sink_start_line=42, sink_end_line=42,
        )],
    )


# --------------------------------------------------------------------------- #
# 포함 / 제외 규칙 (docs/06 §4.1 #7)
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("verdict", [
    Verdict.STATIC_PATH_TRIAGED_POSITIVE, Verdict.LIKELY_RISK,
    Verdict.SUSPICIOUS, Verdict.NEEDS_MANUAL_REVIEW,
])
def test_judged_draftable_verdict_becomes_finding(verdict):
    s4 = build_findings(_s3([_judged("c1", verdict)]))
    assert len(s4.findings) == 1
    assert s4.findings[0].finding_id == "S4-c1"


def test_false_positive_excluded():
    s4 = build_findings(_s3([_judged("c1", Verdict.FALSE_POSITIVE)]))
    assert s4.findings == []
    assert s4.status == StageStatus.OK  # 제외돼 비어도 정상(valid-empty)


def test_skipped_and_failed_excluded():
    s4 = build_findings(_s3([_skipped("c1"), _failed("c2")]))
    assert s4.findings == []
    assert s4.status == StageStatus.OK


def test_mixed_only_draftable_judged_included():
    outcomes = [
        _judged("good1", Verdict.LIKELY_RISK),
        _judged("fp", Verdict.FALSE_POSITIVE),     # 제외
        _skipped("skip"),                          # 제외
        _failed("fail"),                           # 제외
        _judged("good2", Verdict.SUSPICIOUS),
    ]
    s4 = build_findings(_s3(outcomes))
    assert {f.finding_id for f in s4.findings} == {"S4-good1", "S4-good2"}


# --------------------------------------------------------------------------- #
# title 접두 강제 (codex r1 M5)
# --------------------------------------------------------------------------- #
def test_title_prefix_potential_for_risk_verdicts():
    for verdict in (Verdict.STATIC_PATH_TRIAGED_POSITIVE, Verdict.LIKELY_RISK, Verdict.SUSPICIOUS):
        s4 = build_findings(_s3([_judged("c1", verdict)]))
        assert s4.findings[0].title.startswith("Potential ")


def test_title_prefix_needs_manual_review():
    s4 = build_findings(_s3([_judged("c1", Verdict.NEEDS_MANUAL_REVIEW)]))
    assert s4.findings[0].title.startswith("Needs manual review")


def test_every_draft_title_has_required_prefix():
    """모든 draft finding title 은 두 접두 중 하나로 시작(확정 finding 처럼 보임 금지)."""
    outcomes = [_judged(f"c{i}", v) for i, v in enumerate(_DRAFT_VERDICTS_ORDER)]
    s4 = build_findings(_s3(outcomes))
    for f in s4.findings:
        assert f.title.startswith("Potential ") or f.title.startswith("Needs manual review")


_DRAFT_VERDICTS_ORDER = [
    Verdict.STATIC_PATH_TRIAGED_POSITIVE, Verdict.LIKELY_RISK,
    Verdict.SUSPICIOUS, Verdict.NEEDS_MANUAL_REVIEW,
]


# --------------------------------------------------------------------------- #
# vulnerability_confirmed=False 불변 (전 경로)
# --------------------------------------------------------------------------- #
def test_vulnerability_confirmed_always_false():
    outcomes = [_judged(f"c{i}", v) for i, v in enumerate(_DRAFT_VERDICTS_ORDER)]
    s4 = build_findings(_s3(outcomes), _s1([_candidate(f"c{i}") for i in range(len(outcomes))]))
    assert s4.findings  # 비어있지 않음
    for f in s4.findings:
        assert f.vulnerability_confirmed is False
        assert f.human_review_state == HumanReviewState.NOT_REVIEWED


# --------------------------------------------------------------------------- #
# 빈 judged → valid-empty (status ok, NOT error)
# --------------------------------------------------------------------------- #
def test_empty_judged_is_valid_empty_ok():
    s4 = build_findings(_s3([]))
    assert s4.status == StageStatus.OK
    assert s4.findings == []
    assert s4.errors == []  # 실패 빈 결과(error) 아님


def test_all_excluded_is_still_ok_not_error():
    s4 = build_findings(_s3([_judged("c1", Verdict.FALSE_POSITIVE), _skipped("c2")]))
    assert s4.status == StageStatus.OK and s4.findings == []


# --------------------------------------------------------------------------- #
# S1/S2 evidence 보강
# --------------------------------------------------------------------------- #
def test_pulls_file_line_cwe_from_s1():
    s4 = build_findings(_s3([_judged("c1", Verdict.LIKELY_RISK)]),
                        _s1([_candidate("c1", line=42, cwe="CWE-78")]))
    f = s4.findings[0]
    assert f.file == "app/api.py" and f.line == 42 and f.cwe == "CWE-78"


def test_pulls_path_and_snippets_and_severity_from_s2():
    s4 = build_findings(
        _s3([_judged("c1", Verdict.LIKELY_RISK, sanitizer_sufficient=False)]),
        _s1([_candidate("c1")]), _s2("c1"),
    )
    f = s4.findings[0]
    assert f.source_to_sink_path == ["src: request.query[cmd]", "sink: subprocess.run"]
    assert any("subprocess.run" in s for s in f.evidence_snippets)
    assert f.severity == "error" and f.cwe == "CWE-78"
    assert f.why_sanitizer_insufficient  # sanitizer_sufficient=False → 사유 채움


def test_missing_s1_s2_is_fail_closed_not_crash():
    """후보/evidence 없어도 draft 는 산출(빈 evidence 를 무해로 보지 않음)."""
    s4 = build_findings(_s3([_judged("orphan", Verdict.SUSPICIOUS)]))
    f = s4.findings[0]
    assert f.finding_id == "S4-orphan"
    assert f.file == "" and f.line == 0 and f.cwe == "CWE-unknown"
    assert f.vulnerability_confirmed is False


def test_no_snippet_falls_back_to_candidate_code():
    """S2 없을 때 evidence_snippets 는 후보 code_snippet 으로 fallback."""
    s4 = build_findings(_s3([_judged("c1", Verdict.LIKELY_RISK)]), _s1([_candidate("c1")]))
    f = s4.findings[0]
    assert f.evidence_snippets == ["subprocess.run(cmd, shell=True)"]


# --------------------------------------------------------------------------- #
# 메타 / input_refs
# --------------------------------------------------------------------------- #
def test_artifact_meta_carried_through():
    s4 = build_findings(_s3([_judged("c1", Verdict.LIKELY_RISK)]), _s1([_candidate("c1")]), _s2("c1"))
    assert s4.repo == "acme/app" and s4.commit_sha == "deadbeef"
    assert "S3:S3" in s4.input_refs and "S1:S1" in s4.input_refs and "S2:S2" in s4.input_refs


# --------------------------------------------------------------------------- #
# _normalize_cwe 단위
# --------------------------------------------------------------------------- #
def test_normalize_cwe():
    assert _normalize_cwe("external/cwe/cwe-078") == "CWE-78"
    assert _normalize_cwe("CWE-89") == "CWE-89"
    assert _normalize_cwe("sink matches KB CWE-022 path") == "CWE-22"
    assert _normalize_cwe(None) == "CWE-unknown"
    assert _normalize_cwe("no cwe here") == "CWE-unknown"


# --------------------------------------------------------------------------- #
# MD 렌더 smoke
# --------------------------------------------------------------------------- #
def test_render_md_smoke_with_findings():
    s4 = build_findings(
        _s3([_judged("c1", Verdict.LIKELY_RISK, sanitizer_sufficient=False,
                     exploitability_hint="RCE via shell", recommended_next_action="parameterize")]),
        _s1([_candidate("c1")]), _s2("c1"),
    )
    md = render_findings_md(s4)
    assert "# AuditAI Finding Draft" in md
    assert "Potential" in md
    assert "app/api.py:42" in md
    assert "vulnerability_confirmed" in md
    assert "false" in md.lower()  # confirmed=false 표기


def test_render_md_smoke_empty_valid_empty():
    md = render_findings_md(build_findings(_s3([])))
    assert "# AuditAI Finding Draft" in md
    assert "valid-empty" in md or "0" in md  # 빈 결과를 정상으로 표기


def test_render_md_renders_title_with_pipe_safely():
    """title 등에 파이프가 있어도 렌더가 깨지지 않는다(escape)."""
    s4 = build_findings(_s3([_judged("c1", Verdict.SUSPICIOUS, reason="a | b reaches sink")]))
    md = render_findings_md(s4)
    assert "# AuditAI Finding Draft" in md  # smoke: 렌더 성공
    # 표 헤더(7컬럼) 와 데이터 행의 파이프 수가 같아야 컬럼이 안 깨짐
    rows = [ln for ln in md.splitlines() if ln.startswith("| ") and ln.endswith(" |")]
    header = next(ln for ln in rows if "title" in ln)
    data = next(ln for ln in rows if "S4-c1" in ln or "Potential" in ln)
    assert header.count("|") == data.count("|")
