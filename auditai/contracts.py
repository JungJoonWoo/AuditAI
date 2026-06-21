"""AuditAI 데이터 계약 (청사진 docs/03-blueprint.md §7).

파이프라인 단계 간 주고받는 모든 구조를 Pydantic v2 모델로 고정한다.
codex 검증으로 굳힌 핵심 불변식:
- 등급: `confirmed_finding` 금지. 항상 vulnerability_confirmed=False + human_review_state.
- llm_eligible = (candidate_type==taint_path) AND flow_exists AND static_path_confirmed.
  (compute_llm_eligible() 가 S2.5 최종 산출자. 모델 validator 는 비-taint→False 를 강제.)
- static_path_confirmed 는 S2/S2.5 산출(FlowEvidence). SemanticJudgement는 read-only echo.
- 후보 3타입 분리: taint_path(LLM 대상) / static_pattern_risk·authz_candidate(inventory만).
- 모든 모델 extra="forbid" — 오타/금지필드(예: confirmed_finding) 입력을 침묵 무시하지 않음.
"""

from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, computed_field, model_validator


class StrictModel(BaseModel):
    """공통 베이스 — 알 수 없는 필드 거부(codex Q6), alias 채움 허용."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)


# --------------------------------------------------------------------------- #
# Enums
# --------------------------------------------------------------------------- #
class AttributionState(str, Enum):
    CONFIRMED_AI = "confirmed_ai"  # author/committer 가 Claude (anthropic 이메일/claude[bot])
    PROBABLE_AI = "probable_ai"  # name-only claude 또는 Co-authored-by 트레일러 (저신뢰 버킷)
    HUMAN = "human"
    UNKNOWN_DUE_TO_HISTORY_LOSS = "unknown_due_to_history_loss"


class LossMode(str, Enum):
    SQUASH = "squash"
    REBASE = "rebase"
    AMEND = "amend"
    CHERRY_PICK = "cherry_pick"
    CONFLICT_RESOLUTION = "conflict_resolution"
    REFORMAT = "reformat"
    GENERATED = "generated"
    VENDORED = "vendored"
    FILE_MOVE = "file_move"


class CandidateType(str, Enum):
    TAINT_PATH = "taint_path"  # source->sink taint, Track A, LLM 대상
    STATIC_PATTERN_RISK = "static_pattern_risk"  # config/smell, Track A', inventory만
    AUTHZ_CANDIDATE = "authz_candidate"  # authz/IDOR, Track B, inventory만


class Track(str, Enum):
    A = "A"
    A_PRIME = "A_prime"
    B = "B"


class CandidateSource(str, Enum):
    SEMGREP = "semgrep"
    CODEQL = "codeql"
    AST = "ast"


class EvidenceKind(str, Enum):
    CODEQL_TAINT = "codeql_taint"
    REQUIRES_CODEQL_VALIDATION = "requires_codeql_validation"
    PATTERN_ONLY = "pattern_only"
    AUTHZ_PATTERN = "authz_pattern"


class Verdict(str, Enum):
    """S3 LLM 판정 (codex bp1-7: confirmed_finding 금지)."""

    STATIC_PATH_TRIAGED_POSITIVE = "static_path_triaged_positive"
    LIKELY_RISK = "likely_risk"
    SUSPICIOUS = "suspicious"
    FALSE_POSITIVE = "false_positive"
    NEEDS_MANUAL_REVIEW = "needs_manual_review"


class JudgeRunState(str, Enum):
    """S3 판정 '실행 상태' — verdict(판정 내용)와 다른 축 (codex MVP r2 M4).

    `judgement_skipped`/`failed` 를 `Verdict.FALSE_POSITIVE` 와 같은 축에 두면 미판정을 무해로
    오독할 수 있으므로 분리한다. judged 일 때만 verdict(SemanticJudgement)를 채운다.
    """

    JUDGED = "judged"      # LLM 이 유효 Verdict 산출
    SKIPPED = "skipped"    # eligible 이나 미전송(예산초과/CLI 미설치·미인증)
    FAILED = "failed"      # 전송했으나 parse/CLI 실패(repair 후도) — 절대 false_positive 로 강등 금지


class HumanReviewState(str, Enum):
    NOT_REVIEWED = "not_reviewed"
    IN_REVIEW = "in_review"
    REVIEWED_CONFIRMED = "reviewed_confirmed"
    REVIEWED_REJECTED = "reviewed_rejected"


class PathLeg(str, Enum):
    SOURCE_TO_AI = "source_to_ai"
    AI_TO_SINK = "ai_to_sink"


# --------------------------------------------------------------------------- #
# S0 — AI 라인 귀속
# --------------------------------------------------------------------------- #
class AILineAttribution(StrictModel):
    """S0 산출. file 경로는 forward-slash repo-relative (codex bp1-4)."""

    file: str
    line_range: tuple[int, int]
    commit: str
    attribution_state: AttributionState
    ai_confidence: float = Field(ge=0.0, le=1.0)
    label_source: str = Field(default="blame")
    loss_modes: list[LossMode] = Field(default_factory=list)
    manual_label: AttributionState | None = None

    @property
    def is_ai(self) -> bool:
        return self.attribution_state in (
            AttributionState.CONFIRMED_AI,
            AttributionState.PROBABLE_AI,
        )


# --------------------------------------------------------------------------- #
# Security KB
# --------------------------------------------------------------------------- #
# CodeQL data-extension 으로 export 가능한 모델 계열 (codex A9/Q9). 그 외 금지.
CODEQL_MODEL_FAMILIES = (
    "sourceModel",
    "sinkModel",
    "typeModel",
    "summaryModel",
    "barrierModel",
    "barrierGuardModel",
)


class EngineMappings(StrictModel):
    semgrep: str | None = None
    codeql: str | None = Field(
        default=None,
        description="허용 계열만: " + "|".join(CODEQL_MODEL_FAMILIES),
    )
    prompt_context: str | None = None

    @model_validator(mode="after")
    def _codeql_family_allowlist(self) -> EngineMappings:
        if self.codeql is not None:
            head = self.codeql.split(":", 1)[0].split()[0].strip()
            if head not in CODEQL_MODEL_FAMILIES:
                raise ValueError(
                    f"engine_mappings.codeql must start with one of {CODEQL_MODEL_FAMILIES}, "
                    f"got {head!r}"
                )
        return self


class KBMeta(StrictModel):
    owner: str
    version: str
    test_fixture: str = Field(min_length=1)  # codex Q4r2: 빈 fixture 금지(존재검증은 loader)
    expected_tp_fp: str
    provenance: list[str] = Field(default_factory=lambda: ["manual_seed"])
    engine_mappings: EngineMappings = Field(default_factory=EngineMappings)


class Capability(StrictModel):
    id: str
    name: str
    cwe: str
    description: str
    severity_hint: str
    examples: list[str] = Field(default_factory=list)
    terminal_impact: str
    meta: KBMeta


class ApiSignature(StrictModel):
    id: str
    language: str
    package: str | None = None
    module: str
    qualified_name: str
    receiver_type: str | None = None
    method_name: str | None = None
    capability_id: str
    argument_roles: dict[str, str] = Field(default_factory=dict)
    dangerous_conditions: list[dict] = Field(default_factory=list)
    confidence: str
    meta: KBMeta


class SourceSpec(StrictModel):
    id: str
    language: str
    framework: str | None = None
    qualified_name_or_pattern: str
    source_kind: str
    arg_or_return_role: str
    confidence: str
    meta: KBMeta


class SinkSpec(StrictModel):
    id: str
    api_signature_id: str | None = None
    sink_kind: str
    dangerous_argument: str
    required_conditions: list[dict] = Field(default_factory=list)
    capability_id: str
    cwe: str
    confidence: str
    meta: KBMeta


class SanitizerSpec(StrictModel):
    """이름만 보고 FP 제거 금지 — candidate 표시용, 충분성은 S3 LLM 판정."""

    id: str
    language: str
    qualified_name_or_pattern: str
    sanitizer_kind: str
    applies_to_capability: str
    strength: str
    limitations: str = ""
    confidence: str
    meta: KBMeta


class PropagatorSpec(StrictModel):
    id: str
    language: str
    qualified_name_or_pattern: str
    from_role: str = Field(alias="from")
    to_role: str = Field(alias="to")
    propagation_kind: str
    confidence: str
    meta: KBMeta


# --------------------------------------------------------------------------- #
# S1 — 후보 (finding 아님)
# --------------------------------------------------------------------------- #
class LocationSpan(StrictModel):
    """exact-overlap 상관용 구조화 위치 (codex MVP step1 r2 M3). col 없으면 line 단위 비교.

    codex MVP S0 M2: 1-based 좌표·순서 강제(잘못된 범위는 exact-overlap 입력으로 부적합)."""

    file: str
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    start_col: int | None = Field(default=None, ge=1)
    end_col: int | None = Field(default=None, ge=1)

    @model_validator(mode="after")
    def _ordered(self) -> LocationSpan:
        if self.end_line < self.start_line:
            raise ValueError("end_line must be >= start_line")
        if (self.start_col is not None and self.end_col is not None
                and self.start_line == self.end_line and self.end_col < self.start_col):
            raise ValueError("end_col must be >= start_col on the same line")
        return self


class FindingCandidate(StrictModel):
    """S1 출력. 후보지 finding 아님. llm_eligible 최종 확정은 S2.5 compute_llm_eligible()."""

    candidate_id: str
    candidate_type: CandidateType
    track: Track
    repo: str
    commit_sha: str
    file: str
    source_loc: str | None = None
    sink_loc: str | None = None
    sink_span: LocationSpan | None = None  # codex MVP step1 r2 M3: S2 exact-overlap 용(없으면 reject)
    ai_attribution_refs: list[AILineAttribution] = Field(default_factory=list)
    code_snippet: str = ""
    capability_id: str | None = None
    sink_spec_id: str | None = None
    source_nearby: bool = False
    sanitizer_candidates: list[str] = Field(default_factory=list)
    candidate_source: CandidateSource
    rule_id: str | None = None
    query_id: str | None = None
    evidence_kind: EvidenceKind
    evidence_required: bool = True
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0)
    recall_reason: str = ""
    next_stage: str = "flow_validation"
    # llm_eligible 은 S1 후보 필드가 아니다 (codex C2-Q2: 이중 진실원 제거).
    # 최종 판정은 S2.5 의 compute_llm_eligible() → LlmGateDecision 한 곳에서만.

    @model_validator(mode="after")
    def _track_matches_type(self) -> FindingCandidate:
        expected = {
            CandidateType.TAINT_PATH: Track.A,
            CandidateType.STATIC_PATTERN_RISK: Track.A_PRIME,
            CandidateType.AUTHZ_CANDIDATE: Track.B,
        }[self.candidate_type]
        if self.track != expected:
            raise ValueError(
                f"track {self.track} mismatches candidate_type {self.candidate_type} "
                f"(expected {expected})"
            )
        return self


# --------------------------------------------------------------------------- #
# S2/S2.5 — Flow evidence
# --------------------------------------------------------------------------- #
class PathNode(StrictModel):
    engine: str
    node_id: str
    file: str
    start_line: int
    end_line: int
    start_col: int | None = None  # codex MVP step1 M5: 같은 줄 다중 call exact-overlap 용
    end_col: int | None = None
    role: str
    code: str = ""
    kind: str = ""
    path_leg: PathLeg
    sequence: int
    path_id: str


class FlowEvidence(StrictModel):
    """S2/S2.5 산출. static_path_confirmed 는 여기서 확정 (codex bp2-1)."""

    candidate_id: str
    source_to_sink_flow_exists: bool
    static_path_confirmed: bool = Field(
        description="MVP approximation (codex MVP r2 C3/M3): true split-config aiOnFlow QL 은 V1.5. "
                    "MVP 는 approximation_kind 가 set 일 때 'generic-suite CodeQL taint codeFlow 가 후보의 "
                    "AI-귀속 sink 와 exact 교차' 라는 근사로 이 값을 산출한다(confidence<1). approximation_kind "
                    "가 None 이면 split-config 의미(현재 미산출). 근사일 때 report 문구에서 'confirmed' 금지."
    )
    approximation_kind: Literal["generic_codeql_ai_sink_intersection"] | None = Field(
        default=None,
        description="static_path_confirmed 의 산출 backend/근사 종류 (codex MVP S0 Minor: 확장 지점). "
                    "'generic_codeql_ai_sink_intersection'=MVP 근사(generic suite codeFlow ∩ AI sink). "
                    "None=split-config aiOnFlow 정밀(V1.5, 현재 미산출). MVP 에선 정밀 경로가 없으므로 "
                    "static_path_confirmed=True + None 조합은 거부된다(정밀 위장 금지). V1.5 에서 split-config "
                    "구현 시 새 리터럴 값(예: 'split_config_ai_on_flow')을 추가해 confidence=1.0 허용.",
    )
    source: str | None = None
    sink: str | None = None
    flow_path: list[str] = Field(default_factory=list)
    path_nodes: list[PathNode] = Field(default_factory=list)
    entrypoint: str | None = None
    call_chain: list[str] = Field(default_factory=list)
    control_guards: list[str] = Field(default_factory=list)
    sanitizer_candidates: list[str] = Field(default_factory=list)
    barrier_candidates: list[str] = Field(default_factory=list)
    unresolved_edges: list[str] = Field(default_factory=list)
    engine: str = "codeql"
    engine_artifacts: list[str] = Field(default_factory=list)
    query_id: str | None = None
    evidence_backend_version: str | None = None
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)

    @model_validator(mode="after")
    def _static_path_implies_flow(self) -> FlowEvidence:
        # codex Q5: static_path_confirmed=True 인데 flow 가 없으면 모순
        if self.static_path_confirmed and not self.source_to_sink_flow_exists:
            raise ValueError(
                "static_path_confirmed=True requires source_to_sink_flow_exists=True"
            )
        # codex MVP step1 r2 M2: MVP 에서 static_path_confirmed=True 는 **반드시 근사**다 — split-config
        # 정밀 aiOnFlow 는 아직 산출하지 못하므로 approximation_kind=None + True(정밀 confirmed 위장)를 금지.
        # (정밀 의미가 생기면 evidence_backend_kind 같은 명시 필드를 두고 이 제약을 완화.)
        if self.static_path_confirmed and self.approximation_kind is None:
            raise ValueError(
                "MVP: static_path_confirmed=True 는 approximation_kind 필수 "
                "(split-config 정밀 static_path 미산출 — None+True 는 근사를 정밀로 위장)"
            )
        # codex MVP step1 M4: 근사 evidence 는 정직하게 표기 — approximation_kind 가 set 이면
        # static_path_confirmed=True(근사로 산출) + flow_exists=True + confidence<1 + backend_version 필수.
        if self.approximation_kind is not None:
            if not self.static_path_confirmed or not self.source_to_sink_flow_exists:
                raise ValueError(
                    "approximation_kind set requires static_path_confirmed=True and "
                    "source_to_sink_flow_exists=True (근사로 산출된 값)"
                )
            if self.confidence >= 1.0:
                raise ValueError("approximation_kind set requires confidence < 1.0 (근사는 확정 아님)")
            if not self.evidence_backend_version:
                raise ValueError("approximation_kind set requires evidence_backend_version")
        return self


class CodeQLTaintResult(StrictModel):
    """SARIF→S2 evidence 중간모델 (codex MVP r1 M1/r2 M2). `FindingReport` 를 evidence 로 재사용 금지.

    codeFlow 의 마지막 sink node 와 primary location 을 모두 보존해, 후보 sink 와의 **exact-overlap 상관**
    + **primary sink ≠ 마지막 threadFlow sink → ambiguous reject** 를 가능하게 한다(오귀속 차단).
    """

    result_id: str  # raw SARIF result identity (예: "R{run}-F{seq}")
    rule_id: str
    cwe: str = ""
    severity: str = ""
    primary_file: str
    primary_start_line: int
    primary_end_line: int
    primary_start_col: int | None = None
    primary_end_col: int | None = None
    sink_file: str | None = None  # 마지막 threadFlow node(=sink); 없으면 primary 가 sink
    sink_start_line: int | None = None
    sink_end_line: int | None = None
    sink_start_col: int | None = None  # codex MVP step1 M5: AST call span exact-overlap 용
    sink_end_col: int | None = None
    flow_path: list[str] = Field(default_factory=list)  # 사람 가독 codeFlow 요약
    path_nodes: list[PathNode] = Field(default_factory=list)


class LlmGateDecision(StrictModel):
    """S2.5 게이트의 단일 진실원 (codex C2-Q2). FindingCandidate 에 llm_eligible 를 두지 않는다."""

    candidate_id: str
    llm_eligible: bool
    reason: str | None = None


def compute_llm_eligible(
    candidate: FindingCandidate, evidence: FlowEvidence | None
) -> LlmGateDecision:
    """S2.5 최종 게이트 (청사진 §3.3). 산식을 한 곳에서만 계산하고 결과를 모델로 반환.

    codex C2-Q2: candidate 와 evidence 의 candidate_id 일치를 강제(타 후보 evidence 오용 차단).
    """
    cid = candidate.candidate_id
    if evidence is not None and evidence.candidate_id != cid:
        raise ValueError(
            f"evidence.candidate_id {evidence.candidate_id} != candidate.candidate_id {cid}"
        )
    if candidate.candidate_type != CandidateType.TAINT_PATH:
        return LlmGateDecision(
            candidate_id=cid,
            llm_eligible=False,
            reason=f"inventory-only candidate_type={candidate.candidate_type.value}",
        )
    if evidence is None:
        return LlmGateDecision(candidate_id=cid, llm_eligible=False, reason="no flow evidence")
    if not evidence.source_to_sink_flow_exists:
        return LlmGateDecision(candidate_id=cid, llm_eligible=False, reason="no source->sink flow")
    if not evidence.static_path_confirmed:
        return LlmGateDecision(
            candidate_id=cid, llm_eligible=False, reason="static_path not confirmed"
        )
    return LlmGateDecision(candidate_id=cid, llm_eligible=True, reason=None)


# --------------------------------------------------------------------------- #
# S3 — LLM semantic judge
# --------------------------------------------------------------------------- #
class SemanticJudgement(StrictModel):
    """S3 출력. confirmed_finding 금지, 항상 vulnerability_confirmed=False, Track A 만."""

    candidate_id: str
    verdict: Verdict
    reason: str
    sanitizer_sufficient: bool | None = None
    authz_relevant: bool = False
    exploitability_hint: str = ""
    missing_evidence: list[str] = Field(default_factory=list)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    recommended_next_action: str = ""
    static_path_confirmed: bool  # read-only echo from FlowEvidence (codex bp2-1)
    vulnerability_confirmed: bool = False
    human_review_state: HumanReviewState = HumanReviewState.NOT_REVIEWED
    track: Track = Track.A

    @model_validator(mode="after")
    def _invariants(self) -> SemanticJudgement:
        if self.vulnerability_confirmed is not False:
            raise ValueError("vulnerability_confirmed must be False before human review")
        if self.track != Track.A:
            raise ValueError("S3 only judges Track A taint_path candidates (codex Q6)")
        return self


# --------------------------------------------------------------------------- #
# S3 — LLM judge CLI 멀티엔진 (신규 모델, codex s3plan2 §4.1)
# --------------------------------------------------------------------------- #
class JudgeOutput(StrictModel):
    """LLM 이 실제로 산출하는 부분집합(JSON 파싱 대상). codex s3plan2 #4: LLM 은
    `static_path_confirmed`(evidence echo)·`vulnerability_confirmed`(강제 False)·`track` 을
    **정하지 못한다** — 이 모델에 그 필드가 없어, 파서가 LLM 의 해당 키를 무시/거부한다."""

    verdict: Verdict
    reason: str = ""
    sanitizer_sufficient: bool | None = None
    exploitability_hint: str = ""
    missing_evidence: list[str] = Field(default_factory=list)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    recommended_next_action: str = ""


class JudgeTask(StrictModel):
    """S3 입력 단위(1 eligible 후보 = 1 task). prompt 는 judge.py 가 candidate+evidence+KB 로 구성.
    `static_path_confirmed` 는 evidence echo 로, assemble 시 SemanticJudgement 로 그대로 전달."""

    candidate_id: str
    prompt: str = Field(min_length=1)
    static_path_confirmed: bool
    dedup_key: str = ""  # (repo,sha,sink) — 예산 dedup. 비면 candidate_id 사용.


def assemble_semantic_judgement(task: JudgeTask, output: JudgeOutput) -> SemanticJudgement:
    """JudgeOutput(LLM) + JudgeTask(echo) → SemanticJudgement (codex s3plan2 #4 단일 조립점).

    불변: candidate_id=task, static_path_confirmed=task echo(LLM 아님), vulnerability_confirmed=False
    강제, track=A. LLM 은 verdict/이유/충분성/confidence 등 의미판정만 제공한다.
    """
    return SemanticJudgement(
        candidate_id=task.candidate_id,
        verdict=output.verdict,
        reason=output.reason,
        sanitizer_sufficient=output.sanitizer_sufficient,
        exploitability_hint=output.exploitability_hint,
        missing_evidence=list(output.missing_evidence),
        confidence=output.confidence,
        recommended_next_action=output.recommended_next_action,
        static_path_confirmed=task.static_path_confirmed,  # evidence echo — NOT from LLM
        vulnerability_confirmed=False,  # 강제(사람검토 전)
        track=Track.A,
    )


class JudgeOutcome(StrictModel):
    """후보 1개의 S3 결과(회계 단위). codex s3plan2 #5: aggregate count 는 이 리스트에서만 derive.

    state==judged 일 때만 judgement 를 담고, skipped/failed 는 skip_reason 을 담는다(미판정을
    false_positive 로 강등 금지 — JudgeRunState 가 Verdict 와 다른 축인 이유).
    """

    candidate_id: str
    state: JudgeRunState
    judgement: SemanticJudgement | None = None
    skip_reason: str | None = None
    engine: str = ""
    model: str = ""
    probe_id: str = ""

    @model_validator(mode="after")
    def _state_invariants(self) -> JudgeOutcome:
        if self.state == JudgeRunState.JUDGED:
            if self.judgement is None:
                raise ValueError("judged outcome must carry a judgement")
            if self.judgement.candidate_id != self.candidate_id:
                raise ValueError("judgement.candidate_id must match outcome.candidate_id")
            if self.skip_reason is not None:  # codex s3core: judged 면 skip_reason 금지(모순)
                raise ValueError("judged outcome must not carry skip_reason")
        else:  # SKIPPED | FAILED
            if self.judgement is not None:
                raise ValueError("non-judged outcome must not carry a judgement")
            if not self.skip_reason:
                raise ValueError("skipped/failed outcome must carry skip_reason")
        return self


class JudgeRun(StrictModel):
    """S3 실행 전체. eligible 모든 후보가 outcome 하나로 회계됨(누락 불가, codex s3plan2 #5/#2).

    codex s3core: 단일 진실원은 `eligible_candidate_ids`(+`outcomes`). count 는 전부 `@computed_field`
    로 derive 해 직렬화에도 실리고(model_dump), 배선에서 손으로 맞추는 drift 를 차단한다. outcome 의
    candidate_id 집합이 eligible 집합과 **정확히 일치**해야 한다(회계 누락/오염 차단).

    codex s3core2: `model_dump()` 는 **진단 artifact 용(output-only)** 이다. computed count 는 입력
    필드가 아니므로 `model_validate(model_dump())` round-trip 은 지원하지 않는다(StrictModel extra=forbid).
    향후 run.py 배선(S3 wiring) 시에는 `to_report_counts()` 만 쓸 것(round-trip 의존 금지). 현재는 미배선.
    """

    outcomes: list[JudgeOutcome] = Field(default_factory=list)
    eligible_candidate_ids: list[str] = Field(default_factory=list)
    s3_completed: bool = True

    @computed_field  # type: ignore[prop-decorator]
    @property
    def llm_eligible_count(self) -> int:
        return len(self.eligible_candidate_ids)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def judged_count(self) -> int:
        return sum(1 for o in self.outcomes if o.state == JudgeRunState.JUDGED)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def judgement_skipped_count(self) -> int:
        # SKIPPED + FAILED 둘 다 '미판정'(judged 아님).
        return sum(1 for o in self.outcomes if o.state != JudgeRunState.JUDGED)

    @model_validator(mode="after")
    def _accounting(self) -> JudgeRun:
        out_ids = [o.candidate_id for o in self.outcomes]
        if len(set(out_ids)) != len(out_ids):
            raise ValueError("duplicate candidate_id in JudgeRun.outcomes")
        if len(set(self.eligible_candidate_ids)) != len(self.eligible_candidate_ids):
            raise ValueError("duplicate eligible_candidate_id")
        if set(out_ids) != set(self.eligible_candidate_ids):
            raise ValueError(
                "JudgeRun.outcomes ids must exactly match eligible_candidate_ids "
                f"(outcomes={sorted(out_ids)} eligible={sorted(self.eligible_candidate_ids)})"
            )
        return self

    def to_report_counts(self) -> dict:
        """run.py 배선용 단일 변환점(codex s3core: 카운트 수동 손맞춤 금지)."""
        return {
            "llm_eligible_count": self.llm_eligible_count,
            "judged_count": self.judged_count,
            "judgement_skipped_count": self.judgement_skipped_count,
            "s3_completed": self.s3_completed,
        }


class CapabilityProbeResult(StrictModel):
    """엔진 안전성 probe 결과(codex s3plan2 #1).

    `usable` 의 필수 게이트(codex bj94zik1d-3, fall-open 제거): stdin 전달 가능 + 요구 안전플래그가
    `--help` 에 실재 + **behavioral_probe 가 실제로 실행되어 통과**해야 한다. `--help` 플래그 실재는
    동작 보장이 아니므로(엔진이 그냥 거부만 해도 통과하던 fall-open), behavioral probe(temp cwd 에서
    write side-effect/transcript 누출 실측) 미실행/미통과 = **검증 안 된 격리 → unusable**.
    """

    engine: str
    version: str = ""
    argv: list[str] = Field(default_factory=list)
    supports_stdin: bool = False
    safety_flags_present: bool = False
    behavioral_probe_run: bool = False
    behavioral_probe_passed: bool = False
    detail: str = ""

    @property
    def usable(self) -> bool:
        return (
            self.supports_stdin and self.safety_flags_present
            and self.behavioral_probe_run and self.behavioral_probe_passed
        )


# --------------------------------------------------------------------------- #
# S4 — internal evidence memo (외부 제보 아님, codex A4)
# --------------------------------------------------------------------------- #
class FindingReport(StrictModel):
    finding_id: str
    title: str
    severity: str
    cwe: str
    file: str
    line: int
    source_to_sink_path: list[str] = Field(default_factory=list)
    evidence_snippets: list[str] = Field(default_factory=list)
    why_sanitizer_insufficient: str = ""
    impact: str = ""
    safe_reproduction_idea: str = ""
    remediation: str = ""
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    responsible_disclosure_note: str = ""
    vulnerability_confirmed: bool = False
    human_review_state: HumanReviewState = HumanReviewState.NOT_REVIEWED

    @model_validator(mode="after")
    def _never_confirmed(self) -> FindingReport:
        if self.vulnerability_confirmed is not False:
            raise ValueError("vulnerability_confirmed must be False before human review")
        return self


# =========================================================================== #
# P0 — RunStatus 상태기계 / Gates / Track B inventory / RunReport (계획 05 §0/§2)
# "빈 결과를 정상으로 착각 금지" — source=0/flow=0/finding=0 을 자동 NO_VULN_FOUND 로 보지 않음.
# =========================================================================== #
class RunStatus(str, Enum):
    NO_VULN_FOUND = "no_vuln_found"  # G1/G2 pass+S2 완료+finding=0+reliable 일 때만
    FINDINGS_PRESENT = "findings_present"  # Track A finding 또는 Track B inventory 존재
    DIFF_SCOPE_MISSING = "diff_scope_missing"  # G1
    FRAMEWORK_SOURCE_VALIDATION_NOT_RUN = "framework_source_validation_not_run"  # G2(미실행)
    FRAMEWORK_SOURCE_MODEL_MISSING = "framework_source_model_missing"  # G2(source=0)
    EVAL_TARGET_INSUFFICIENT = "eval_target_insufficient"  # G3
    AUTHZ_SCOPE_UNDECLARED = "authz_scope_undeclared"  # G4
    ANALYSIS_ERROR = "analysis_error"  # S2/CodeQL DB build 실패 / S0 귀속 미완(blame 실패)·UNKNOWN sink
    SEMANTIC_JUDGE_NOT_RUN = "semantic_judge_not_run"  # S3: eligible 후보 있는데 전원 판정 못함(미실행/부분/예산)
    COMPLETED_DEGRADED = "completed_degraded"  # smoke 에서 G2 미통과지만 계속(신뢰불가)
    OUT_OF_MVP_SCOPE = "out_of_mvp_scope"  # 명시 표기


class Reliability(str, Enum):
    RELIABLE = "reliable"
    DEGRADED = "degraded"
    UNRELIABLE = "unreliable"


class TargetType(str, Enum):
    SMOKE = "smoke"
    SYNTHETIC = "synthetic"
    KNOWN_CVE = "known_cve"


class GateId(str, Enum):
    G1 = "G1"
    G2 = "G2"
    G3 = "G3"
    G4 = "G4"


class GateStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    SKIPPED = "skipped"
    DEGRADED = "degraded"


class GateFailureCode(str, Enum):
    G1_DIFF = "G1_DIFF"
    G2_SOURCE_NOT_RUN = "G2_SOURCE_NOT_RUN"
    G2_SOURCE_ZERO = "G2_SOURCE_ZERO"
    G3_EVAL = "G3_EVAL"
    G4_AUTHZ = "G4_AUTHZ"


class RiskTrack(str, Enum):
    TRACK_B = "track_b"


class InventoryKind(str, Enum):
    REMOVED_SECURITY_CONTROL = "removed_security_control"
    WEAKENED_CONTROL = "weakened_control"


class SecurityControlKind(str, Enum):
    AUTHZ_CHECK = "authz_check"
    INPUT_VALIDATION = "input_validation"
    SANITIZER = "sanitizer"
    EXCEPTION_GUARD = "exception_guard"
    PATH_NORMALIZATION = "path_normalization"
    PARAMETERIZATION = "parameterization"
    ESCAPING = "escaping"
    DEFAULT_DENY = "default_deny"
    UNKNOWN = "unknown"


class DeletionAttribution(str, Enum):
    """삭제 라인 귀속 — blame 불가라 삭제 commit/PR 메타 기반 (계획 §2.5)."""

    CONFIRMED_AI = "confirmed_ai"
    PROBABLE_AI = "probable_ai"
    PROBABLE_AI_FROM_PR_METADATA = "probable_ai_from_pr_metadata"
    UNKNOWN_DUE_TO_HISTORY_LOSS = "unknown_due_to_history_loss"


class DeletionAttributionSource(str, Enum):
    SINGLE_COMMIT_PR = "single_commit_pr"
    COMMIT_WALK_UNIQUE = "commit_walk_unique"
    PR_METADATA_ONLY = "pr_metadata_only"
    UNKNOWN_DUE_TO_HISTORY_LOSS = "unknown_due_to_history_loss"


class Priority(str, Enum):
    HIGH = "high"
    LOW = "low"


# 삭제 귀속 source 가 약하면 confirmed 로 올리지 않는다 (codex P0-3: squash 강등)
_WEAK_DELETION_SOURCES = {
    DeletionAttributionSource.PR_METADATA_ONLY,
    DeletionAttributionSource.UNKNOWN_DUE_TO_HISTORY_LOSS,
}


def _assert_track_b_invariants(
    *,
    auto_confirmed: bool,
    requires_manual_review: bool,
    inventory_kind: "InventoryKind",
    expected_kind: "InventoryKind",
    ai_attribution: "DeletionAttribution",
    deletion_attribution_source: "DeletionAttributionSource",
) -> None:
    """Track B candidate 공통 불변식 (codex p0code1: Removed/Weakened 양쪽 동일 적용)."""
    if auto_confirmed is not False:
        raise ValueError("Track B is never auto_confirmed")
    if requires_manual_review is not True:
        raise ValueError("Track B always requires_manual_review")
    if inventory_kind != expected_kind:
        raise ValueError(f"inventory_kind must be {expected_kind.value} for this model")
    # squash/모호 source 면 confirmed_ai 금지 (Removed/Weakened 공통)
    if (
        deletion_attribution_source in _WEAK_DELETION_SOURCES
        and ai_attribution == DeletionAttribution.CONFIRMED_AI
    ):
        raise ValueError(
            f"deletion_attribution_source={deletion_attribution_source.value} "
            "cannot yield confirmed_ai (squash/history loss degrade)"
        )


class RemovedSecurityControlCandidate(StrictModel):
    """삭제된 보안 통제 (Track B inventory). FindingCandidate 와 분리(codex 04 H1/r2)."""

    candidate_id: str
    repo: str
    base_sha: str
    head_sha: str
    file: str
    deleted_line_start: int
    deleted_line_end: int
    deleted_code: str
    enclosing_function_before: str = ""
    enclosing_function_after: str = ""
    security_control_kind: SecurityControlKind
    ai_attribution: DeletionAttribution
    deletion_attribution_source: DeletionAttributionSource
    attribution_signals: list[str] = Field(default_factory=list)
    risk_reason: str = ""
    risk_track: RiskTrack = RiskTrack.TRACK_B
    inventory_kind: InventoryKind = InventoryKind.REMOVED_SECURITY_CONTROL
    requires_manual_review: bool = True
    auto_confirmed: bool = False
    priority: Priority = Priority.LOW

    @model_validator(mode="after")
    def _invariants(self) -> RemovedSecurityControlCandidate:
        _assert_track_b_invariants(
            auto_confirmed=self.auto_confirmed,
            requires_manual_review=self.requires_manual_review,
            inventory_kind=self.inventory_kind,
            expected_kind=InventoryKind.REMOVED_SECURITY_CONTROL,
            ai_attribution=self.ai_attribution,
            deletion_attribution_source=self.deletion_attribution_source,
        )
        return self


class WeakenedControlCandidate(StrictModel):
    """약화된 보안 통제 (Track B inventory)."""

    candidate_id: str
    repo: str
    base_sha: str
    head_sha: str
    file: str
    line_start: int
    line_end: int
    before_code: str = ""
    after_code: str = ""
    weakening_kind: str  # allowlist_to_blocklist|parameterized_to_raw|safe_to_unsafe_loader|...
    ai_attribution: DeletionAttribution
    deletion_attribution_source: DeletionAttributionSource
    attribution_signals: list[str] = Field(default_factory=list)
    risk_reason: str = ""
    risk_track: RiskTrack = RiskTrack.TRACK_B
    inventory_kind: InventoryKind = InventoryKind.WEAKENED_CONTROL
    requires_manual_review: bool = True
    auto_confirmed: bool = False
    priority: Priority = Priority.LOW

    @model_validator(mode="after")
    def _invariants(self) -> WeakenedControlCandidate:
        _assert_track_b_invariants(
            auto_confirmed=self.auto_confirmed,
            requires_manual_review=self.requires_manual_review,
            inventory_kind=self.inventory_kind,
            expected_kind=InventoryKind.WEAKENED_CONTROL,
            ai_attribution=self.ai_attribution,
            deletion_attribution_source=self.deletion_attribution_source,
        )
        return self


class RiskInventoryItem(StrictModel):
    item_id: str
    risk_track: RiskTrack = RiskTrack.TRACK_B
    inventory_kind: InventoryKind
    priority: Priority = Priority.LOW
    file: str
    line_or_deleted_line: str
    evidence: str = ""
    why_it_matters: str = ""
    requires_manual_review: bool = True
    auto_confirmed: bool = False

    @model_validator(mode="after")
    def _invariants(self) -> RiskInventoryItem:
        if self.auto_confirmed is not False:
            raise ValueError("Track B inventory is never auto_confirmed")
        if self.requires_manual_review is not True:
            raise ValueError("Track B inventory always requires_manual_review")
        return self


class CandidateInventoryItem(StrictModel):
    """Track A′/heuristic/UNKNOWN+KB sink 후보 인벤토리 (codex MVP r1 M2/r2 C2).

    judged finding 은 아니지만 'clean 으로 빠지면 안 되는' S1 후보(static_pattern_risk, 또는 AI 귀속이
    UNKNOWN 이라 is_ai 후보에서 빠진 KB sink). resolver 는 이게 >0 이면 NO_VULN_FOUND 로 가지 않는다.
    """

    candidate_id: str
    candidate_type: CandidateType
    file: str
    line: int
    sink_span: LocationSpan | None = None  # codex MVP step1 r2 M3: exact-overlap 용 구조화 위치
    capability_id: str | None = None
    sink_spec_id: str | None = None
    reason: str = ""
    ai_attribution_state: AttributionState
    requires_manual_review: bool = True
    auto_confirmed: bool = False

    @model_validator(mode="after")
    def _never_confirmed(self) -> CandidateInventoryItem:
        if self.auto_confirmed is not False:
            raise ValueError("candidate inventory is never auto_confirmed")
        if self.requires_manual_review is not True:  # codex MVP step1 Minor
            raise ValueError("candidate inventory always requires_manual_review")
        return self


# gate 별 허용 failure code (codex p0code3: gate-code 대응 강제)
_GATE_CODES: dict["GateId", set["GateFailureCode"]] = {
    GateId.G1: {GateFailureCode.G1_DIFF},
    GateId.G2: {GateFailureCode.G2_SOURCE_NOT_RUN, GateFailureCode.G2_SOURCE_ZERO},
    GateId.G3: {GateFailureCode.G3_EVAL},
    GateId.G4: {GateFailureCode.G4_AUTHZ},
}

# gate 별 허용 status (codex p0code4): G1=diff scope 는 skip/degraded 불가;
# DEGRADED 는 G2(smoke source) 전용; SKIPPED 는 G2(framework 미사용)만.
_GATE_STATUSES: dict["GateId", set["GateStatus"]] = {
    GateId.G1: {GateStatus.PASS, GateStatus.FAIL},
    GateId.G2: {GateStatus.PASS, GateStatus.FAIL, GateStatus.SKIPPED, GateStatus.DEGRADED},
    GateId.G3: {GateStatus.PASS, GateStatus.FAIL},
    GateId.G4: {GateStatus.PASS, GateStatus.FAIL},
}


class GateResult(StrictModel):
    gate: GateId
    status: GateStatus
    code: GateFailureCode | None = None
    message: str = ""

    @model_validator(mode="after")
    def _code_matches_status(self) -> GateResult:
        # codex p0code4: gate 별 허용 status (G1 skip/degraded 금지, degraded 는 G2 전용)
        if self.status not in _GATE_STATUSES[self.gate]:
            raise ValueError(f"status {self.status.value} not valid for gate {self.gate.value}")
        # codex p0code1: FAIL/DEGRADED 는 code 필수, PASS/SKIPPED 는 code 금지(오입력 침묵 방지)
        if self.status in (GateStatus.FAIL, GateStatus.DEGRADED) and self.code is None:
            raise ValueError(f"GateResult status={self.status.value} requires a failure code")
        if self.status in (GateStatus.PASS, GateStatus.SKIPPED) and self.code is not None:
            raise ValueError(f"GateResult status={self.status.value} must not carry a code")
        # codex p0code3: code 는 해당 gate 의 것이어야 함 (G2 에 G3_EVAL 금지)
        if self.code is not None and self.code not in _GATE_CODES[self.gate]:
            raise ValueError(f"code {self.code.value} not valid for gate {self.gate.value}")
        return self


# Track B 보고서 고정 고지 문구 (G4)
TRACK_B_DISCLOSURE = (
    "This is not automatically confirmed as an access-control vulnerability. However, the PR "
    "appears to remove or weaken a security boundary. Manual review is required."
)


def _gate_map(gate_results: list[GateResult]) -> dict[GateId, GateResult]:
    """gate_results → {gate: result}. 중복 gate 거부 (codex p0code1: last-wins 방지)."""
    out: dict[GateId, GateResult] = {}
    for g in gate_results:
        if g.gate in out:
            raise ValueError(f"duplicate gate result for {g.gate.value}")
        out[g.gate] = g
    return out


class RunReport(StrictModel):
    run_id: str
    target_type: TargetType
    run_status: RunStatus
    reliability: Reliability
    s2_completed: bool  # codex p0code3: resolver 위임에 필요한 run 메타
    track_a_required: bool = True  # codex Q2 R2-2: False=Track-B-only(taint 미요구) 모드
    gate_results: list[GateResult] = Field(default_factory=list)
    findings: list[FindingReport] = Field(default_factory=list)
    risk_inventory: list[RiskInventoryItem] = Field(default_factory=list)
    # --- 전체 5단계 MVP 메타 (codex MVP r2; 옵셔널 디폴트로 하위호환) ---
    s0_attribution_completed: bool = True  # S0 blame 귀속 완료 여부
    unknown_sink_candidate_count: int = Field(default=0, ge=0)  # AI 귀속 UNKNOWN 인 KB sink 후보 수
    s3_completed: bool = True  # S3 judge 단계 도달·완료(미실행이면 False)
    llm_eligible_count: int = Field(default=0, ge=0)  # S2.5 통과(llm_eligible) 후보 수
    judged_count: int = Field(default=0, ge=0)  # S3 가 유효 Verdict 산출한 수(JudgeRunState.JUDGED)
    judgement_skipped_count: int = Field(default=0, ge=0)  # eligible 인데 skipped/failed(미판정) 수
    candidate_inventory: list[CandidateInventoryItem] = Field(default_factory=list)

    @model_validator(mode="after")
    def _judge_count_invariants(self) -> RunReport:
        # codex MVP step1 M2: judge 카운트의 모순 조합 차단(미판정 무해 오독 방지).
        if self.judged_count > self.llm_eligible_count:
            raise ValueError("judged_count must be <= llm_eligible_count")
        if self.judgement_skipped_count > self.llm_eligible_count:
            raise ValueError("judgement_skipped_count must be <= llm_eligible_count")
        if self.judged_count + self.judgement_skipped_count > self.llm_eligible_count:
            raise ValueError("judged_count + judgement_skipped_count must be <= llm_eligible_count")
        return self

    def _effective_unknown_sink_count(self) -> int:
        """codex MVP step1 M3: candidate_inventory 안의 UNKNOWN 귀속 후보를 derive 해 unknown count 와
        합산(max) — count 필드가 0 이어도 inventory 에 UNKNOWN sink 가 있으면 fail-closed(undercount 불가)."""
        derived = sum(
            1 for c in self.candidate_inventory
            if c.ai_attribution_state == AttributionState.UNKNOWN_DUE_TO_HISTORY_LOSS
        )
        return max(self.unknown_sink_candidate_count, derived)

    @model_validator(mode="after")
    def _consistent_with_resolver(self) -> RunReport:
        # codex p0code3: precedence 를 RunReport 가 중복 구현하지 않는다(DRY).
        # 동일 입력으로 resolver 를 돌려 (status, reliability) 가 일치하는지만 검증
        # → resolver 가 절대 만들지 않을 모순 보고서가 구조적으로 불가능.
        _gate_map(self.gate_results)  # 중복 gate 거부

        if self.run_status == RunStatus.OUT_OF_MVP_SCOPE:
            # resolver 가 만들지 않는 명시 marker (target 전체가 MVP 밖 = 분석 안 함).
            # codex p0code4: gate 를 돌렸으면 out-of-scope 가 아니다 → gate_results 비어야 함.
            if self.reliability == Reliability.RELIABLE:
                raise ValueError("OUT_OF_MVP_SCOPE must not be reliable")
            if self.findings or self.risk_inventory or self.candidate_inventory:
                raise ValueError("OUT_OF_MVP_SCOPE must have empty findings/inventory")
            if self.gate_results:
                raise ValueError("OUT_OF_MVP_SCOPE must have empty gate_results (no analysis ran)")
            if self.s2_completed:
                raise ValueError("OUT_OF_MVP_SCOPE must have s2_completed=False (no analysis ran)")
            # codex MVP step1 r2 M3: '분석 안 함' marker 는 신규 MVP 메타도 미실행이어야 일관.
            if (self.llm_eligible_count or self.judged_count or self.judgement_skipped_count
                    or self.unknown_sink_candidate_count):
                raise ValueError("OUT_OF_MVP_SCOPE must have all MVP counts = 0 (no analysis ran)")
            if self.s0_attribution_completed or self.s3_completed:
                raise ValueError(
                    "OUT_OF_MVP_SCOPE must have s0_attribution_completed=False and "
                    "s3_completed=False (no analysis ran)"
                )
            return self

        expected_status, expected_rel = resolve_run_status(
            target_type=self.target_type,
            gate_results=self.gate_results,
            s2_completed=self.s2_completed,
            finding_count=len(self.findings),
            risk_inventory_count=len(self.risk_inventory),
            track_a_required=self.track_a_required,
            s0_attribution_completed=self.s0_attribution_completed,
            unknown_sink_candidate_count=self._effective_unknown_sink_count(),
            s3_completed=self.s3_completed,
            llm_eligible_count=self.llm_eligible_count,
            judged_count=self.judged_count,
            judgement_skipped_count=self.judgement_skipped_count,
            candidate_inventory_count=len(self.candidate_inventory),
        )
        if (self.run_status, self.reliability) != (expected_status, expected_rel):
            raise ValueError(
                f"RunReport ({self.run_status.value}, {self.reliability.value}) "
                f"!= resolver ({expected_status.value}, {expected_rel.value}) for these gates"
            )
        return self


def resolve_run_status(
    *,
    target_type: TargetType,
    gate_results: list[GateResult],
    s2_completed: bool,
    finding_count: int,
    risk_inventory_count: int,
    track_a_required: bool = True,
    s0_attribution_completed: bool = True,
    unknown_sink_candidate_count: int = 0,
    s3_completed: bool = True,
    llm_eligible_count: int = 0,
    judged_count: int = 0,
    judgement_skipped_count: int = 0,
    candidate_inventory_count: int = 0,
) -> tuple[RunStatus, Reliability]:
    """게이트 severity precedence 로 최종 RunStatus + reliability 결정 (계획 §0.2).

    순서(full-scan, track_a_required=True): G1 > G2(hard) > ANALYSIS_ERROR(s2 미완) > G3 > G4 >
      G2(smoke degraded) > FINDINGS_PRESENT > NO_VULN_FOUND.
    Track-B-only(track_a_required=False) 분기(s2 미완): G1 > G2(hard) > G3 > G4 > FINDINGS_PRESENT(inv>0,
      unreliable) > ANALYSIS_ERROR(inv=0). 즉 taint 미요구라 s2 미완이 곧 error 는 아니지만, inventory
      가 없으면 여전히 clean 주장 금지.
    빈 결과 오독 금지: G1/G2 가 명시적으로 평가(존재)되지 않으면 NO_VULN_FOUND 로 가지 않는다.

    track_a_required (codex Q2 R2-2): True(기본, full-scan)면 S2 미완료는 ANALYSIS_ERROR.
    False(Track-B-only 모드, taint 미요구)면 S2 미완료여도 Track B inventory 가 있으면 FINDINGS_PRESENT
    (단 unreliable — taint 미실행). inventory 도 0 이면 여전히 ANALYSIS_ERROR(taint 없이 clean 주장 금지).
    """
    by = _gate_map(gate_results)  # 중복 gate 거부
    g1, g2 = by.get(GateId.G1), by.get(GateId.G2)

    # G1 필수 — PASS 아니면(없음/FAIL) DIFF_SCOPE_MISSING.
    # diff scope 는 절대 skip 불가이므로 PASS 만 통과 (codex p0code4).
    if g1 is None or g1.status != GateStatus.PASS:
        return RunStatus.DIFF_SCOPE_MISSING, Reliability.UNRELIABLE

    # G2 필수 — 없으면 검증 미실행으로 간주
    if g2 is None:
        return RunStatus.FRAMEWORK_SOURCE_VALIDATION_NOT_RUN, Reliability.UNRELIABLE
    if g2.status == GateStatus.FAIL:
        if g2.code == GateFailureCode.G2_SOURCE_ZERO:
            return RunStatus.FRAMEWORK_SOURCE_MODEL_MISSING, Reliability.UNRELIABLE
        return RunStatus.FRAMEWORK_SOURCE_VALIDATION_NOT_RUN, Reliability.UNRELIABLE
    if g2.status == GateStatus.DEGRADED and target_type != TargetType.SMOKE:
        # degraded 는 smoke 에서만 허용; 그 외엔 hard fail 로 승격 (codex p0code1)
        if g2.code == GateFailureCode.G2_SOURCE_ZERO:
            return RunStatus.FRAMEWORK_SOURCE_MODEL_MISSING, Reliability.UNRELIABLE
        return RunStatus.FRAMEWORK_SOURCE_VALIDATION_NOT_RUN, Reliability.UNRELIABLE

    # --- S0 귀속 미완 / UNKNOWN+KB sink fail-closed (codex MVP r2 C2 / S1 중) ---
    # **track mode·s2 완료 여부와 무관하게** clean/FINDINGS 로 가기 전에 차단(UNKNOWN sink 의미 일관).
    # AI-라인 기반이 불확실하면(blame 실패 / 귀속 UNKNOWN sink) 빈 결과를 정상으로 둔갑 못 시킨다.
    if not s0_attribution_completed or unknown_sink_candidate_count > 0:
        return RunStatus.ANALYSIS_ERROR, Reliability.UNRELIABLE

    if not s2_completed:
        # Track-B-only 모드(taint 미요구): inventory 를 findings 로 surface. 단 precedence 유지 —
        # G3(eval) > G4(고지) 를 inventory 반환 전에 검사(codex Q2r2: G3 우회 차단).
        if not track_a_required:
            g3 = by.get(GateId.G3)
            if g3 and g3.status == GateStatus.FAIL:
                return RunStatus.EVAL_TARGET_INSUFFICIENT, Reliability.UNRELIABLE
            g4 = by.get(GateId.G4)
            if g4 and g4.status == GateStatus.FAIL:
                return RunStatus.AUTHZ_SCOPE_UNDECLARED, Reliability.UNRELIABLE
            if finding_count or risk_inventory_count or candidate_inventory_count:
                return RunStatus.FINDINGS_PRESENT, Reliability.UNRELIABLE  # taint 미실행 → unreliable
            return RunStatus.ANALYSIS_ERROR, Reliability.UNRELIABLE  # taint 없이 clean 주장 금지
        return RunStatus.ANALYSIS_ERROR, Reliability.UNRELIABLE

    # --- 분석 완료성 fail-closed (codex MVP r2 C1): s2 완료 이후, G3/G4 이전 ---
    # S3: eligible 후보가 있는데 전원 유효 판정되지 않음(미실행/부분/예산초과/parse 실패) → NO_VULN 금지.
    if llm_eligible_count > 0 and (
        not s3_completed
        or judged_count < llm_eligible_count
        or judgement_skipped_count > 0
    ):
        return RunStatus.SEMANTIC_JUDGE_NOT_RUN, Reliability.UNRELIABLE

    g3 = by.get(GateId.G3)
    if g3 and g3.status == GateStatus.FAIL:
        return RunStatus.EVAL_TARGET_INSUFFICIENT, Reliability.UNRELIABLE
    g4 = by.get(GateId.G4)
    if g4 and g4.status == GateStatus.FAIL:
        return RunStatus.AUTHZ_SCOPE_UNDECLARED, Reliability.UNRELIABLE

    # smoke G2 degraded: 계속하되 신뢰불가
    if g2.status == GateStatus.DEGRADED:
        if finding_count or risk_inventory_count or candidate_inventory_count:
            return RunStatus.FINDINGS_PRESENT, Reliability.UNRELIABLE
        return RunStatus.COMPLETED_DEGRADED, Reliability.UNRELIABLE

    # 여기 도달 = G1 pass && G2 pass/skipped && S2 완료 && S0/S3 완료 && G3/G4 fail 없음
    # candidate_inventory(Track A′/heuristic/UNKNOWN sink)도 있으면 clean 아님 (codex r1 M2).
    if finding_count or risk_inventory_count or candidate_inventory_count:
        return RunStatus.FINDINGS_PRESENT, Reliability.RELIABLE
    return RunStatus.NO_VULN_FOUND, Reliability.RELIABLE
