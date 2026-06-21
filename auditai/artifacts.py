"""단계 경계 아티팩트 (docs/06 §6.1, codex pipeline PLAN 82% 반영).

5단계(S0~S4)는 하나의 워크플로우지만 각 단계는 **앞 단계 아티팩트(고정 JSON 템플릿)만** 읽는 독립
모듈이다. 중간에 끊겨도 그 아티팩트로 다음 단계를 단독 재개할 수 있다(resumability). 입출력 포맷이
고정될 때만 가능 — 이 모듈이 그 고정 템플릿(StageArtifact 메타 래퍼 + 단계별 payload 모델)이다.

핵심 불변(codex pipeline PLAN):
- **valid-empty ≠ failed-empty**: `status`(ok|partial|error)로 구분. `load_stage_artifact` 가 `error`
  를 읽으면 다음 단계 실행 금지(StageArtifactError → 오케스트레이터가 ANALYSIS_ERROR 로 종료).
- payload = 그 단계의 **로드 가능한 모델만**(전 내부모델 raw dump 금지).
- S3 는 `JudgeRun` raw dump 금지 → `{outcomes, eligible_candidate_ids, s3_completed}` 만 보관하고
  counts 는 load 시 재계산(저장된 `report_counts` 와 불일치 → fail-closed).
- schema_version 불일치/손상/누락 → fail-closed.
- `RunReport` 는 **최종 집계물(단계 아티팩트 아님)** — 여기 두지 않는다.
"""

from __future__ import annotations

import json
from enum import Enum
from pathlib import Path
from typing import Literal, TypeVar

from pydantic import Field, model_validator

from .contracts import (
    AILineAttribution,
    CandidateInventoryItem,
    CodeQLTaintResult,
    FindingCandidate,
    FindingReport,
    FlowEvidence,
    JudgeOutcome,
    JudgeRunState,
    JudgeTask,
    LlmGateDecision,
    StrictModel,
)
from .scope import DiffScope

ARTIFACT_SCHEMA_VERSION = "2"  # codex pipeline-qa: S0 에 unknown/human_lines 추가 → bump(구 v1 reject)


class StageStatus(str, Enum):
    OK = "ok"          # 정상 산출(빈 결과 포함 — '정상 빈 결과')
    PARTIAL = "partial"  # 부분 산출(일부 실패) — errors[] 동반, 다운스트림은 미완료로 취급
    ERROR = "error"    # 단계 실패 — '실패 빈 결과'. 다운스트림 진행 금지(ANALYSIS_ERROR)


class StageArtifactError(ValueError):
    """아티팩트 로드/검증 실패 또는 upstream error 아티팩트 → 다음 단계 실행 금지(fail-closed)."""


class StageArtifact(StrictModel):
    """단계 경계 아티팩트 메타 래퍼. 서브클래스가 `stage` 고정 + payload 필드 추가."""

    schema_version: str = ARTIFACT_SCHEMA_VERSION
    stage: str
    status: StageStatus
    repo: str = ""
    commit_sha: str = ""
    input_refs: list[str] = Field(default_factory=list)  # 앞 아티팩트 경로/해시 (self-describing)
    tool_versions: dict[str, str] = Field(default_factory=dict)
    errors: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _status_errors(self) -> StageArtifact:
        # error/partial 은 반드시 사유를 남긴다(valid-empty 와 구분 — '실패를 정상 빈 결과로 위장' 금지).
        if self.status in (StageStatus.ERROR, StageStatus.PARTIAL) and not self.errors:
            raise ValueError(f"{self.status.value} artifact must carry errors[]")
        if self.status == StageStatus.OK and self.errors:
            raise ValueError("ok artifact must not carry errors[] (use status=partial)")
        return self

    @property
    def fully_complete(self) -> bool:
        """단계가 자기 일을 '끝까지' 했는가. 서브클래스가 completed 플래그로 override.
        require_ok 소비는 status==OK 뿐 아니라 이것까지 True 여야 한다(codex artifacts2)."""
        return True


class S0Artifact(StageArtifact):
    stage: Literal["S0"] = "S0"
    scope: DiffScope | None = None
    attributions: list[AILineAttribution] = Field(default_factory=list)
    # self-describing: 하위 단계(S1 scan_candidates)가 AddedLineAttribution 을 재구성하려면 세 라인맵
    # 전부 필요(ai/unknown/human). JSON 직렬화 위해 set→list.
    ai_lines: dict[str, list[int]] = Field(default_factory=dict)       # is_ai(confirmed/probable)
    unknown_lines: dict[str, list[int]] = Field(default_factory=dict)  # UNKNOWN 귀속(fail-closed 입력)
    human_lines: dict[str, list[int]] = Field(default_factory=dict)    # human 귀속
    completed: bool = False

    @model_validator(mode="after")
    def _partial_not_completed(self) -> S0Artifact:
        if self.status == StageStatus.PARTIAL and self.completed:
            raise ValueError("partial S0Artifact must have completed=False")
        return self

    @property
    def fully_complete(self) -> bool:
        return self.completed


class S1Artifact(StageArtifact):
    stage: Literal["S1"] = "S1"
    candidates: list[FindingCandidate] = Field(default_factory=list)
    candidate_inventory: list[CandidateInventoryItem] = Field(default_factory=list)
    unknown_sink_count: int = Field(default=0, ge=0)
    fn_note: str = ""


class S2Artifact(StageArtifact):
    stage: Literal["S2"] = "S2"
    taint_results: list[CodeQLTaintResult] = Field(default_factory=list)
    evidence: list[FlowEvidence] = Field(default_factory=list)
    s2_completed: bool = False
    codeql_version: str = ""

    @model_validator(mode="after")
    def _partial_not_completed(self) -> S2Artifact:
        if self.status == StageStatus.PARTIAL and self.s2_completed:
            raise ValueError("partial S2Artifact must have s2_completed=False")
        return self

    @property
    def fully_complete(self) -> bool:
        return self.s2_completed


class S25Artifact(StageArtifact):
    stage: Literal["S2.5"] = "S2.5"
    gate_decisions: list[LlmGateDecision] = Field(default_factory=list)
    tasks: list[JudgeTask] = Field(default_factory=list)
    eligible_count: int = Field(default=0, ge=0)


class S3Artifact(StageArtifact):
    """S3 판정. codex pipeline PLAN: JudgeRun raw dump 금지 → 로드가능 필드만 + counts 재계산 대조."""

    stage: Literal["S3"] = "S3"
    outcomes: list[JudgeOutcome] = Field(default_factory=list)
    eligible_candidate_ids: list[str] = Field(default_factory=list)
    s3_completed: bool = True
    report_counts: dict[str, int]  # codex artifacts: 필수 — load 시 재계산값과 항상 대조(누락 우회 차단)

    @property
    def judged_count(self) -> int:
        return sum(1 for o in self.outcomes if o.state == JudgeRunState.JUDGED)

    @property
    def judgement_skipped_count(self) -> int:
        return sum(1 for o in self.outcomes if o.state != JudgeRunState.JUDGED)

    def recomputed_counts(self) -> dict[str, int]:
        return {
            "llm_eligible_count": len(self.eligible_candidate_ids),
            "judged_count": self.judged_count,
            "judgement_skipped_count": self.judgement_skipped_count,
        }

    @property
    def fully_complete(self) -> bool:
        return self.s3_completed

    @classmethod
    def build(cls, *, status: StageStatus, outcomes: list[JudgeOutcome],
              eligible_candidate_ids: list[str], **kw) -> S3Artifact:
        """producer 용 — report_counts 와 s3_completed 를 outcomes·status 에서 산출(validator 일관성 보증).
        codex artifacts2: s3_completed = 'all judged'(skip/failed 있으면 False). codex pipeline-qa(Critical):
        status 가 OK 가 아니면(상류 partial 전파) s3_completed=False — PARTIAL+s3_completed=True validator
        충돌(crash)을 산출 단계에서 차단. (status 는 명시 인자 — codex pipeline-qa2 Low.)"""
        judged = sum(1 for o in outcomes if o.state == JudgeRunState.JUDGED)
        skipped = len(outcomes) - judged
        counts = {"llm_eligible_count": len(eligible_candidate_ids), "judged_count": judged,
                  "judgement_skipped_count": skipped}
        return cls(status=status, outcomes=outcomes, eligible_candidate_ids=eligible_candidate_ids,
                   s3_completed=(skipped == 0 and status == StageStatus.OK),
                   report_counts=counts, **kw)

    @model_validator(mode="after")
    def _counts_and_ids(self) -> S3Artifact:
        out_ids = [o.candidate_id for o in self.outcomes]
        if len(set(out_ids)) != len(out_ids):
            raise ValueError("duplicate candidate_id in S3Artifact.outcomes")
        if len(set(self.eligible_candidate_ids)) != len(self.eligible_candidate_ids):
            raise ValueError("duplicate eligible_candidate_id")
        if set(out_ids) != set(self.eligible_candidate_ids):
            raise ValueError("outcomes ids must match eligible_candidate_ids")
        # report_counts(필수)는 항상 재계산값과 일치해야 한다(저장 후 변조/불일치 → fail-closed).
        if self.report_counts != self.recomputed_counts():
            raise ValueError(
                f"S3Artifact.report_counts {self.report_counts} != recomputed "
                f"{self.recomputed_counts()} (tampered/inconsistent artifact)"
            )
        if self.status == StageStatus.PARTIAL and self.s3_completed:
            raise ValueError("partial S3Artifact must have s3_completed=False")
        # codex artifacts2: s3_completed=True 는 'all judged' 의미 — skip/failed 있으면 거짓.
        if self.s3_completed and self.judgement_skipped_count > 0:
            raise ValueError("s3_completed=True but outcomes contain skipped/failed (not all judged)")
        return self


class S4Artifact(StageArtifact):
    stage: Literal["S4"] = "S4"
    findings: list[FindingReport] = Field(default_factory=list)


_T = TypeVar("_T", bound=StageArtifact)


def load_stage_artifact(path: str | Path, cls: type[_T], *, require_ok: bool = False) -> _T:
    """단계 아티팩트 JSON 로드+검증. fail-closed: 손상/버전불일치/`status==error` → StageArtifactError.

    upstream `error` 아티팩트로는 다음 단계를 절대 실행하지 않는다(ANALYSIS_ERROR 로 이어져야 함).
    `require_ok=True`(다운스트림 소비용)면 `partial` 도 거부 — 미완료 입력으로 다음 단계 진행 금지.
    `require_ok=False`(검사/표시용)면 partial 통과(다운스트림이 미완료로 취급해야 함).
    """
    p = Path(path)
    try:
        raw = p.read_text(encoding="utf-8")
    except OSError as e:
        raise StageArtifactError(f"cannot read artifact {p}: {e}") from e
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise StageArtifactError(f"corrupt artifact JSON {p}: {e}") from e
    if not isinstance(data, dict):
        raise StageArtifactError(f"artifact {p} is not a JSON object")
    if data.get("schema_version") != ARTIFACT_SCHEMA_VERSION:
        raise StageArtifactError(
            f"artifact {p} schema_version {data.get('schema_version')!r} "
            f"!= {ARTIFACT_SCHEMA_VERSION!r}"
        )
    try:
        art = cls.model_validate(data)
    except Exception as e:  # pydantic ValidationError 등
        raise StageArtifactError(f"artifact {p} failed {cls.__name__} validation: {e}") from e
    if art.status == StageStatus.ERROR:
        raise StageArtifactError(
            f"upstream stage {art.stage} produced status=error → cannot continue: {art.errors}"
        )
    if require_ok and (art.status != StageStatus.OK or not art.fully_complete):
        raise StageArtifactError(
            f"stage {art.stage} not consumable (require_ok): status={art.status.value} "
            f"fully_complete={art.fully_complete} errors={art.errors}"
        )
    return art


def write_stage_artifact(path: str | Path, artifact: StageArtifact) -> None:
    """아티팩트를 canonical JSON 으로 영속화(다음 단계 입력)."""
    Path(path).write_text(artifact.model_dump_json(indent=2), encoding="utf-8")
