"""S4 — Finding Draft (docs/06 §5 + §6.1). judged 판정 → 사람 검토용 FindingReport draft.

정직한 범위: 이건 **확정 finding 이 아니라** 사람 검토를 위한 draft 다. 전 경로에서 불변:
- `vulnerability_confirmed=False` (FindingReport validator 가 강제; 여기서도 항상 False 로 둔다).
- `human_review_state=not_reviewed`.
- title 은 항상 **"Potential "** 또는 **"Needs manual review"** 접두 (codex r1 M5) — 확정 finding 으로
  오해되지 않게.

제외 규칙 (docs/06 §4.1 #7, fail-closed): judged outcome 만, 그 중에서도 verdict 가
{static_path_triaged_positive, likely_risk, suspicious, needs_manual_review} 인 것만 draft 한다.
- verdict == false_positive → 제외.
- state != judged(skipped/failed) → 제외 (미판정을 finding 으로도, 무해로도 둔갑 금지 — 미판정은
  resolve_run_status 의 SEMANTIC_JUDGE_NOT_RUN 으로 별도 표면화된다).

MD 렌더(`render_findings_md`)는 s4_findings.json 에서 파생되는 **사람용 표시물**일 뿐, 다음 단계의
기계 핸드오프 입력이 아니다 (docs/06 §6.1 #6).
"""

from __future__ import annotations

import re

from .artifacts import S1Artifact, S2Artifact, S3Artifact, S4Artifact, StageStatus
from .contracts import (
    FindingCandidate,
    FindingReport,
    FlowEvidence,
    HumanReviewState,
    JudgeOutcome,
    JudgeRunState,
    SemanticJudgement,
    Verdict,
)

# S4 finding draft 에 포함하는 verdict (docs/06 §5). false_positive 는 제외.
_DRAFT_VERDICTS: frozenset[Verdict] = frozenset(
    {
        Verdict.STATIC_PATH_TRIAGED_POSITIVE,
        Verdict.LIKELY_RISK,
        Verdict.SUSPICIOUS,
        Verdict.NEEDS_MANUAL_REVIEW,
    }
)

# title 접두 (codex r1 M5): needs_manual_review 는 "Needs manual review", 그 외 draft 대상은 "Potential ".
_NEEDS_REVIEW_PREFIX = "Needs manual review"
_POTENTIAL_PREFIX = "Potential "

_CWE_RE = re.compile(r"CWE-0*\d+", re.IGNORECASE)


def _normalize_cwe(raw: str | None) -> str:
    """'CWE-078' → 'CWE-78'(선행 0 제거, MITRE 표기). 추출 불가 시 'CWE-unknown'(fail-closed)."""
    if not raw:
        return "CWE-unknown"
    m = _CWE_RE.search(raw)
    if not m:
        return "CWE-unknown"
    num = m.group(0).split("-", 1)[1].lstrip("0") or "0"
    return f"CWE-{num}"


def _candidate_line(cand: FindingCandidate) -> int:
    """후보 sink 라인. sink_span 우선, 없으면 sink_loc('file:line')에서, 그래도 없으면 0."""
    if cand.sink_span is not None:
        return cand.sink_span.start_line
    for loc in (cand.sink_loc, cand.source_loc):
        if loc and ":" in loc:
            tail = loc.rsplit(":", 1)[1]
            if tail.isdigit():
                return int(tail)
    return 0


def _verdict_title_prefix(verdict: Verdict) -> str:
    return _NEEDS_REVIEW_PREFIX if verdict == Verdict.NEEDS_MANUAL_REVIEW else _POTENTIAL_PREFIX


def _build_title(verdict: Verdict, cwe: str, capability_id: str | None) -> str:
    """확정처럼 보이지 않는 title (codex r1 M5: 'Potential '/'Needs manual review' 접두 강제)."""
    subject = capability_id or cwe or "security risk"
    prefix = _verdict_title_prefix(verdict)
    if prefix == _NEEDS_REVIEW_PREFIX:
        # "Needs manual review: <subject> (<verdict>)"
        return f"{_NEEDS_REVIEW_PREFIX}: {subject} ({verdict.value})"
    # "Potential <subject> (<verdict>)"
    return f"{_POTENTIAL_PREFIX}{subject} ({verdict.value})"


def _evidence_snippets(cand: FindingCandidate | None, ev: FlowEvidence | None) -> list[str]:
    """evidence_snippets: S2 evidence path node 코드 우선, 없으면 후보 code_snippet."""
    snippets: list[str] = []
    if ev is not None:
        for node in ev.path_nodes:
            if node.code:
                snippets.append(f"{node.file}:{node.start_line} {node.code}".strip())
    if not snippets and cand is not None and cand.code_snippet:
        snippets.append(cand.code_snippet)
    return snippets


def _source_to_sink_path(ev: FlowEvidence | None) -> list[str]:
    """S2 evidence 의 flow_path(사람 가독 codeFlow 요약). evidence 없으면 빈 리스트."""
    return list(ev.flow_path) if ev is not None else []


def _why_sanitizer_insufficient(sj: SemanticJudgement) -> str:
    """sanitizer_sufficient 가 명시적으로 False 일 때만 사유 채움(추측 금지)."""
    if sj.sanitizer_sufficient is False:
        base = "LLM triage: sanitizer/guard insufficient or absent for this flow."
        return f"{base} {sj.reason}".strip() if sj.reason else base
    return ""


def _build_one(
    outcome: JudgeOutcome,
    cand: FindingCandidate | None,
    ev: FlowEvidence | None,
    severity: str,
    cwe_hint: str,
) -> FindingReport:
    """judged outcome 1개 → FindingReport draft. vulnerability_confirmed=False 불변."""
    sj = outcome.judgement
    assert sj is not None  # 호출부가 judged 만 넘긴다(state==JUDGED → judgement 존재)
    cwe = _normalize_cwe(cwe_hint or (cand.recall_reason if cand is not None else None))
    capability_id = cand.capability_id if cand is not None else None
    file = cand.file if cand is not None else ""
    line = _candidate_line(cand) if cand is not None else 0
    missing = list(sj.missing_evidence)
    note = (
        "NOT a confirmed vulnerability — human review required. "
        "vulnerability_confirmed=False, human_review_state=not_reviewed."
    )
    return FindingReport(
        finding_id=f"S4-{outcome.candidate_id}",
        title=_build_title(sj.verdict, cwe, capability_id),
        severity=severity or "unknown",
        cwe=cwe,
        file=file,
        line=line,
        source_to_sink_path=_source_to_sink_path(ev),
        evidence_snippets=_evidence_snippets(cand, ev),
        why_sanitizer_insufficient=_why_sanitizer_insufficient(sj),
        impact=sj.exploitability_hint,
        safe_reproduction_idea="",  # exploit 생성 금지 — draft 단계는 비움
        remediation=sj.recommended_next_action,
        confidence=sj.confidence,
        responsible_disclosure_note=note + (f" missing_evidence={missing}" if missing else ""),
        vulnerability_confirmed=False,  # 불변(전 경로) — FindingReport validator 도 강제
        human_review_state=HumanReviewState.NOT_REVIEWED,
    )


def _draftable(outcome: JudgeOutcome) -> bool:
    """draft 포함 여부 (docs/06 §4.1 #7): judged + verdict ∈ _DRAFT_VERDICTS."""
    if outcome.state != JudgeRunState.JUDGED or outcome.judgement is None:
        return False
    return outcome.judgement.verdict in _DRAFT_VERDICTS


def build_findings(
    s3: S3Artifact,
    s1: S1Artifact | None = None,
    s2: S2Artifact | None = None,
) -> S4Artifact:
    """S3 judged 판정 → S4Artifact(FindingReport[]). 빈 결과는 valid-empty(status=ok).

    포함: judged + verdict ∈ {static_path_triaged_positive, likely_risk, suspicious,
    needs_manual_review}. 제외: false_positive, skipped/failed (docs/06 §4.1 #7).
    file/line/cwe/capability 는 S1 후보에서, source_to_sink_path/snippets/severity/cwe 는 S2
    evidence(FlowEvidence/CodeQLTaintResult)에서 best-effort 보강. 누락돼도 fail-closed 로 draft 한다
    (빈 evidence 를 무해로 보지 않음).
    """
    cand_by_id: dict[str, FindingCandidate] = {}
    if s1 is not None:
        cand_by_id = {c.candidate_id: c for c in s1.candidates}
    ev_by_id: dict[str, FlowEvidence] = {}
    sev_by_id: dict[str, str] = {}
    cwe_by_id: dict[str, str] = {}
    if s2 is not None:
        ev_by_id = {e.candidate_id: e for e in s2.evidence}
        # CodeQLTaintResult 는 candidate_id 가 없으나 sink/severity/cwe 를 보유 — sink('file:line')로
        # FlowEvidence.sink 와 매칭해 severity/cwe 를 후보별로 보강(매칭 실패 시 빈 값 → fail-closed).
        for e in s2.evidence:
            for r in s2.taint_results:
                if r.sink_file and e.sink == f"{r.sink_file}:{r.sink_start_line}":
                    sev_by_id[e.candidate_id] = r.severity
                    cwe_by_id[e.candidate_id] = r.cwe
                    break

    findings: list[FindingReport] = []
    for outcome in s3.outcomes:
        if not _draftable(outcome):
            continue
        cid = outcome.candidate_id
        findings.append(
            _build_one(
                outcome,
                cand_by_id.get(cid),
                ev_by_id.get(cid),
                sev_by_id.get(cid, ""),
                cwe_by_id.get(cid, ""),
            )
        )

    input_refs: list[str] = [f"S3:{s3.stage}"]
    if s1 is not None:
        input_refs.append(f"S1:{s1.stage}")
    if s2 is not None:
        input_refs.append(f"S2:{s2.stage}")

    return S4Artifact(
        status=StageStatus.OK,  # 빈 findings 도 정상 빈 결과(valid-empty) — 실패 아님
        repo=s3.repo,
        commit_sha=s3.commit_sha,
        input_refs=input_refs,
        findings=findings,
    )


# --------------------------------------------------------------------------- #
# MD 렌더 (파생물 — 기계 핸드오프 입력 아님, docs/06 §6.1 #6)
# --------------------------------------------------------------------------- #
def _md_escape(text: str) -> str:
    """MD 표/본문에 안전하게 넣기 위한 최소 escape(파이프/개행)."""
    return text.replace("|", "\\|").replace("\n", " ").strip()


def render_findings_md(s4: S4Artifact) -> str:
    """S4Artifact → findings_report.md 내용(사람 검토 draft). 파생 표시물(다음 단계 입력 아님)."""
    lines: list[str] = []
    lines.append("# AuditAI Finding Draft (human review required)")
    lines.append("")
    lines.append(
        "> 주의: 아래 항목은 **확정 취약점이 아니다**. 모두 `vulnerability_confirmed=False` 이며 "
        "사람 검토(`human_review_state=not_reviewed`)가 필요한 draft 다."
    )
    lines.append("")
    lines.append(f"- repo: `{s4.repo or '(unknown)'}`")
    lines.append(f"- commit: `{s4.commit_sha or '(unknown)'}`")
    lines.append(f"- status: `{s4.status.value}`")
    lines.append(f"- findings(draft): **{len(s4.findings)}**")
    lines.append("")

    if not s4.findings:
        lines.append("_판정 가능한 finding draft 가 없습니다 (valid-empty)._")
        lines.append("")
        return "\n".join(lines)

    lines.append("| # | title | severity | cwe | file:line | confidence | confirmed |")
    lines.append("|---|-------|----------|-----|-----------|------------|-----------|")
    for i, f in enumerate(s4.findings, 1):
        lines.append(
            f"| {i} | {_md_escape(f.title)} | {_md_escape(f.severity)} | "
            f"{_md_escape(f.cwe)} | `{_md_escape(f.file)}:{f.line}` | "
            f"{f.confidence:.2f} | {str(f.vulnerability_confirmed).lower()} |"
        )
    lines.append("")

    for i, f in enumerate(s4.findings, 1):
        lines.append(f"## {i}. {f.title}")
        lines.append("")
        lines.append(f"- finding_id: `{f.finding_id}`")
        lines.append(f"- location: `{f.file}:{f.line}`")
        lines.append(f"- severity / cwe: `{f.severity}` / `{f.cwe}`")
        lines.append(f"- confidence: `{f.confidence:.2f}`")
        lines.append(
            f"- vulnerability_confirmed: `{str(f.vulnerability_confirmed).lower()}` · "
            f"human_review_state: `{f.human_review_state.value}`"
        )
        if f.source_to_sink_path:
            lines.append("- source → sink path:")
            for step in f.source_to_sink_path:
                lines.append(f"  - {_md_escape(step)}")
        if f.evidence_snippets:
            lines.append("- evidence:")
            for snip in f.evidence_snippets:
                lines.append(f"  - `{_md_escape(snip)}`")
        if f.why_sanitizer_insufficient:
            lines.append(f"- why sanitizer insufficient: {_md_escape(f.why_sanitizer_insufficient)}")
        if f.impact:
            lines.append(f"- impact (hint): {_md_escape(f.impact)}")
        if f.remediation:
            lines.append(f"- remediation: {_md_escape(f.remediation)}")
        if f.responsible_disclosure_note:
            lines.append(f"- note: {_md_escape(f.responsible_disclosure_note)}")
        lines.append("")

    return "\n".join(lines)
