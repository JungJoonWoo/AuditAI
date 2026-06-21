"""단계 경계 아티팩트(§6.1) 테스트 — fail-closed load, valid-empty≠failed-empty, S3 counts 재계산."""

import json

import pytest

from auditai.artifacts import (
    ARTIFACT_SCHEMA_VERSION,
    S1Artifact,
    S3Artifact,
    StageArtifactError,
    StageStatus,
    load_stage_artifact,
    write_stage_artifact,
)
from auditai.contracts import JudgeOutcome, JudgeRunState


def _ok_s1(**kw):
    return S1Artifact(status=StageStatus.OK, repo="r", commit_sha="h", **kw)


# --- status / valid-empty ≠ failed-empty ----------------------------------- #

def test_error_artifact_requires_errors():
    with pytest.raises(ValueError):
        S1Artifact(status=StageStatus.ERROR, errors=[])  # 실패인데 사유 없음 금지


def test_ok_artifact_must_not_carry_errors():
    with pytest.raises(ValueError):
        S1Artifact(status=StageStatus.OK, errors=["boom"])  # 정상인데 errors → status=partial 써야


def test_valid_empty_is_ok():
    art = _ok_s1()  # 빈 candidates 지만 status=ok → 정상 빈 결과
    assert art.status == StageStatus.OK and art.candidates == []


# --- load_stage_artifact: fail-closed -------------------------------------- #

def test_load_roundtrip_ok(tmp_path):
    p = tmp_path / "s1.json"
    write_stage_artifact(p, _ok_s1(unknown_sink_count=2, fn_note="recall-first"))
    loaded = load_stage_artifact(p, S1Artifact)
    assert loaded.unknown_sink_count == 2 and loaded.fn_note == "recall-first"


def test_load_rejects_error_artifact(tmp_path):
    """upstream status=error → 다음 단계 실행 금지(StageArtifactError)."""
    p = tmp_path / "s1.json"
    write_stage_artifact(p, S1Artifact(status=StageStatus.ERROR, errors=["blame incomplete"]))
    with pytest.raises(StageArtifactError):
        load_stage_artifact(p, S1Artifact)


def test_load_schema_version_mismatch(tmp_path):
    p = tmp_path / "s1.json"
    data = _ok_s1().model_dump(mode="json")
    data["schema_version"] = "999"
    p.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(StageArtifactError):
        load_stage_artifact(p, S1Artifact)


def test_load_corrupt_json(tmp_path):
    p = tmp_path / "s1.json"
    p.write_text("{not valid json", encoding="utf-8")
    with pytest.raises(StageArtifactError):
        load_stage_artifact(p, S1Artifact)


def test_load_missing_file(tmp_path):
    with pytest.raises(StageArtifactError):
        load_stage_artifact(tmp_path / "nope.json", S1Artifact)


def test_load_wrong_stage_payload(tmp_path):
    """S1 자리에 S3 데이터 로드 → 검증 실패(stage literal/extra 필드)."""
    p = tmp_path / "x.json"
    write_stage_artifact(p, S3Artifact.build(status=StageStatus.OK, outcomes=[],
                                             eligible_candidate_ids=[]))
    with pytest.raises(StageArtifactError):
        load_stage_artifact(p, S1Artifact)


# --- S3Artifact: JudgeRun raw dump 금지, counts 재계산 --------------------- #

def _outcome(cid, judged=False):
    if judged:
        from auditai.contracts import SemanticJudgement, Verdict
        sj = SemanticJudgement(candidate_id=cid, verdict=Verdict.LIKELY_RISK, reason="r",
                               static_path_confirmed=True)
        return JudgeOutcome(candidate_id=cid, state=JudgeRunState.JUDGED, judgement=sj)
    return JudgeOutcome(candidate_id=cid, state=JudgeRunState.SKIPPED, skip_reason="x")


def test_s3_build_sets_report_counts_and_completed():
    # 전부 judged → s3_completed=True
    done = S3Artifact.build(status=StageStatus.OK, outcomes=[_outcome("a", judged=True)],
                            eligible_candidate_ids=["a"])
    assert done.s3_completed is True and done.judged_count == 1
    # judged + skipped → s3_completed=False(codex artifacts2: all judged 아님)
    mixed = S3Artifact.build(status=StageStatus.OK,
                             outcomes=[_outcome("a", judged=True), _outcome("b")],
                             eligible_candidate_ids=["a", "b"])
    assert mixed.s3_completed is False and mixed.fully_complete is False
    assert mixed.report_counts == mixed.recomputed_counts() == {
        "llm_eligible_count": 2, "judged_count": 1, "judgement_skipped_count": 1}


def test_s3_completed_true_with_skip_rejected():
    """s3_completed=True 인데 skip/failed 있으면 거부(직접구성, codex artifacts2)."""
    with pytest.raises(ValueError):
        S3Artifact(status=StageStatus.OK, outcomes=[_outcome("a")], eligible_candidate_ids=["a"],
                   s3_completed=True,
                   report_counts={"llm_eligible_count": 1, "judged_count": 0,
                                  "judgement_skipped_count": 1})


def test_s3_report_counts_mismatch_fails_closed():
    with pytest.raises(ValueError):
        S3Artifact(status=StageStatus.OK, outcomes=[_outcome("a")],
                   eligible_candidate_ids=["a"],
                   report_counts={"llm_eligible_count": 1, "judged_count": 1,
                                  "judgement_skipped_count": 0})  # 거짓 counts


def test_s3_report_counts_required_on_load(tmp_path):
    """report_counts 누락 → load 거부(무결성 검사 우회 차단)."""
    art = S3Artifact.build(status=StageStatus.OK, outcomes=[_outcome("a")],
                           eligible_candidate_ids=["a"])
    data = art.model_dump(mode="json")
    del data["report_counts"]
    p = tmp_path / "s3.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(StageArtifactError):
        load_stage_artifact(p, S3Artifact)


def test_s3_ids_must_match():
    with pytest.raises(ValueError):
        S3Artifact.build(status=StageStatus.OK, outcomes=[_outcome("a")],
                         eligible_candidate_ids=["a", "b"])


def test_s3_duplicate_eligible_rejected():
    with pytest.raises(ValueError):
        S3Artifact.build(status=StageStatus.OK, outcomes=[_outcome("a")],
                         eligible_candidate_ids=["a", "a"])


def test_s3_partial_must_not_be_completed():
    # 직접 구성: 전부 judged(s3_completed=True 일관)인데 status=PARTIAL → partial-completed validator 거부
    with pytest.raises(ValueError):
        S3Artifact(status=StageStatus.PARTIAL, errors=["budget cut"],
                   outcomes=[_outcome("a", judged=True)], eligible_candidate_ids=["a"],
                   s3_completed=True,
                   report_counts={"llm_eligible_count": 1, "judged_count": 1,
                                  "judgement_skipped_count": 0})


def test_s3_roundtrip(tmp_path):
    art = S3Artifact.build(status=StageStatus.OK, outcomes=[_outcome("a", judged=True)],
                           eligible_candidate_ids=["a"])
    p = tmp_path / "s3.json"
    write_stage_artifact(p, art)
    loaded = load_stage_artifact(p, S3Artifact)
    assert loaded.judged_count == 1 and loaded.s3_completed is True


# --- require_ok / partial / 나머지 단계 round-trip -------------------------- #

def test_load_require_ok_rejects_partial(tmp_path):
    p = tmp_path / "s1.json"
    write_stage_artifact(p, S1Artifact(status=StageStatus.PARTIAL, errors=["codeql timeout"]))
    assert load_stage_artifact(p, S1Artifact).status == StageStatus.PARTIAL  # 기본은 통과
    with pytest.raises(StageArtifactError):
        load_stage_artifact(p, S1Artifact, require_ok=True)  # 다운스트림 소비는 거부


def test_other_stage_artifacts_roundtrip(tmp_path):
    from auditai.artifacts import S0Artifact, S25Artifact, S2Artifact, S4Artifact
    for cls in (S0Artifact, S2Artifact, S25Artifact, S4Artifact):
        p = tmp_path / f"{cls.__name__}.json"
        write_stage_artifact(p, cls(status=StageStatus.OK, repo="r", commit_sha="h"))
        assert load_stage_artifact(p, cls).stage  # round-trip + stage literal 유지


def test_s2_partial_must_not_be_completed():
    from auditai.artifacts import S2Artifact
    with pytest.raises(ValueError):
        S2Artifact(status=StageStatus.PARTIAL, errors=["partial codeql"], s2_completed=True)


def test_require_ok_rejects_incomplete_stage(tmp_path):
    """status=OK 라도 fully_complete 아니면 require_ok 소비 거부(codex artifacts2 #1)."""
    from auditai.artifacts import S2Artifact
    p = tmp_path / "s2.json"
    write_stage_artifact(p, S2Artifact(status=StageStatus.OK, s2_completed=False))  # OK 지만 미완료
    assert load_stage_artifact(p, S2Artifact).fully_complete is False  # 기본 로드는 통과
    with pytest.raises(StageArtifactError):
        load_stage_artifact(p, S2Artifact, require_ok=True)  # 다운스트림 소비는 거부
