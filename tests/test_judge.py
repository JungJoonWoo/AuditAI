"""S3 LLM judge deterministic 핵심 테스트 (네트워크/CLI 0 — FakeEngine).

검증: JSON 파서(코드펜스/ANSI/extra-key), assemble 불변(static_path echo·vuln=False),
fail-closed(parse/CLI 실패 → FAILED, 절대 false_positive 아님), JudgeRun 회계(누락 불가).
"""

import json

import pytest

from auditai.contracts import (
    JudgeOutput,
    JudgeOutcome,
    JudgeRun,
    JudgeRunState,
    JudgeTask,
    Verdict,
    assemble_semantic_judgement,
)
from auditai.judge import (
    FakeEngine,
    JudgeParseError,
    extract_judge_output,
    judge_tasks,
)


def _task(cid="c1", static=True):
    return JudgeTask(candidate_id=cid, prompt="judge this candidate", static_path_confirmed=static)


def _valid_json(verdict="likely_risk", reason="unsanitized user input reaches sink"):
    return json.dumps({"verdict": verdict, "reason": reason, "confidence": 0.7,
                       "sanitizer_sufficient": False})


# --- extract_judge_output --------------------------------------------------- #

def test_extract_plain_json():
    out = extract_judge_output(_valid_json())
    assert out.verdict == Verdict.LIKELY_RISK and out.confidence == 0.7
    assert out.sanitizer_sufficient is False


def test_extract_codefence_and_ansi_and_prose():
    raw = (
        "\x1b[32m여기 판정입니다:\x1b[0m\n```json\n"
        + _valid_json(verdict="suspicious")
        + "\n```\n위 JSON 이 결과입니다."
    )
    out = extract_judge_output(raw)
    assert out.verdict == Verdict.SUSPICIOUS


def test_extract_ignores_llm_supplied_forced_fields():
    """LLM 이 static_path_confirmed/vulnerability_confirmed/잡키를 넣어도 무시(codex s3plan2 #4)."""
    blob = json.dumps({
        "verdict": "static_path_triaged_positive", "reason": "x",
        "static_path_confirmed": False,      # LLM 이 거짓 주장 → 무시
        "vulnerability_confirmed": True,     # LLM 이 확정 시도 → 무시
        "bogus_key": 123,
    })
    out = extract_judge_output(blob)
    assert out.verdict == Verdict.STATIC_PATH_TRIAGED_POSITIVE
    assert not hasattr(out, "vulnerability_confirmed")  # JudgeOutput 에 그 필드 자체가 없음
    assert "static_path_confirmed" not in JudgeOutput.model_fields


def test_extract_empty_and_garbage_raise():
    for bad in ["", "   ", "no json here", "{not valid}", "[1,2,3]"]:
        with pytest.raises(JudgeParseError):
            extract_judge_output(bad)


def test_extract_invalid_verdict_raises():
    with pytest.raises(JudgeParseError):
        extract_judge_output(json.dumps({"verdict": "definitely_vulnerable", "reason": "x"}))


def test_extract_rejects_top_level_array():
    """JSON 배열은 거부(배열 내부 객체를 top-level 로 승격 금지, codex s3core)."""
    with pytest.raises(JudgeParseError):
        extract_judge_output("[" + _valid_json() + "]")


def test_extract_valid_json_with_trailing_prose_braces():
    """유효 JSON 뒤에 중괄호 든 산문이 와도 raw_decode 가 객체만 취함."""
    raw = _valid_json(verdict="suspicious") + "\n\n참고: {이건 JSON 아님} 추가 설명."
    assert extract_judge_output(raw).verdict == Verdict.SUSPICIOUS


def test_extract_takes_first_object_not_deeper():
    """첫 최외곽 객체를 취한다(두 객체면 첫째). 무차별 스캔 아님."""
    raw = _valid_json(verdict="likely_risk") + "\n" + _valid_json(verdict="false_positive")
    assert extract_judge_output(raw).verdict == Verdict.LIKELY_RISK


def test_extract_rejects_array_even_after_prose():
    """산문이 앞에 붙은 배열도 거부 — 배열 내부 객체 승격 금지(codex s3core2 High)."""
    raw = 'Result:\n[' + _valid_json(verdict="false_positive") + ']'
    with pytest.raises(JudgeParseError):
        extract_judge_output(raw)


def test_extract_rejects_nested_wrapper_object():
    """비스키마 wrapper 안의 내부 객체를 승격하지 않는다(codex s3core2 Medium)."""
    raw = '{"note": {"verdict": "false_positive", "reason": "nested injection"}}'
    with pytest.raises(JudgeParseError):
        extract_judge_output(raw)


def test_extract_leading_nonschema_object_rejected():
    """선행 비스키마 객체 → 더 깊이 스캔하지 않고 reject(fail-closed; repair 가 처리)."""
    raw = '{"note": "thinking out loud"}\n' + _valid_json(verdict="suspicious")
    with pytest.raises(JudgeParseError):
        extract_judge_output(raw)


# --- assemble_semantic_judgement ------------------------------------------- #

def test_assemble_echoes_static_path_and_forces_invariants():
    out = JudgeOutput(verdict=Verdict.LIKELY_RISK, reason="r", confidence=0.5)
    sj = assemble_semantic_judgement(_task(cid="cX", static=True), out)
    assert sj.candidate_id == "cX"
    assert sj.static_path_confirmed is True       # task echo, NOT from LLM
    assert sj.vulnerability_confirmed is False    # 강제
    assert sj.track.value == "A"
    assert sj.verdict == Verdict.LIKELY_RISK and sj.confidence == 0.5


def test_assemble_static_path_false_echo():
    sj = assemble_semantic_judgement(_task(static=False),
                                     JudgeOutput(verdict=Verdict.SUSPICIOUS))
    assert sj.static_path_confirmed is False


# --- judge_tasks: fail-closed + 회계 --------------------------------------- #

def test_judge_tasks_judged():
    run = judge_tasks([_task()], FakeEngine(_valid_json()))
    assert run.llm_eligible_count == 1 and run.judged_count == 1
    assert run.judgement_skipped_count == 0 and run.s3_completed is True
    o = run.outcomes[0]
    assert o.state == JudgeRunState.JUDGED and o.judgement.verdict == Verdict.LIKELY_RISK
    assert o.engine == "fake"


def test_judge_tasks_parse_fail_then_repair_succeeds():
    eng = FakeEngine(["sorry, no JSON", _valid_json(verdict="suspicious")])
    run = judge_tasks([_task()], eng)
    assert run.judged_count == 1
    assert run.outcomes[0].judgement.verdict == Verdict.SUSPICIOUS
    assert len(eng.calls) == 2  # 원본 + repair


def test_judge_tasks_parse_fail_twice_is_failed_not_false_positive():
    run = judge_tasks([_task()], FakeEngine(["garbage", "still garbage"]))
    o = run.outcomes[0]
    assert o.state == JudgeRunState.FAILED  # 절대 false_positive/judged 아님
    assert o.judgement is None and "parse_failed" in o.skip_reason
    assert run.judged_count == 0 and run.judgement_skipped_count == 1


def test_judge_tasks_engine_error_is_failed():
    run = judge_tasks([_task()], FakeEngine([RuntimeError("cli crashed")]))
    o = run.outcomes[0]
    assert o.state == JudgeRunState.FAILED and "engine_error" in o.skip_reason
    assert o.judgement is None


def test_judge_tasks_close_error_is_failed_not_judged():
    """transcript 삭제 실패(close)는 보안상 FAILED — 판정이 성공해도 강등(§4.3)."""
    eng = FakeEngine(_valid_json(), close_error=RuntimeError("transcript delete failed"))
    run = judge_tasks([_task()], eng)
    o = run.outcomes[0]
    assert o.state == JudgeRunState.FAILED and o.judgement is None
    assert "session close failed" in o.skip_reason
    assert run.judged_count == 0 and run.judgement_skipped_count == 1


def test_judge_tasks_close_failure_takes_priority_over_parse_failure():
    """§4.3 #8(codex bj94zik1d-8): parse 실패와 close(transcript 삭제) 실패가 동시 발생하면
    **보안상 close 실패가 우선** 기록된다(parse 실패에 가려지지 않음)."""
    # 첫 응답·repair 응답 모두 garbage(parse 2회 실패) + close 도 raise(transcript 삭제 실패).
    eng = FakeEngine(["garbage", "still garbage"],
                     close_error=RuntimeError("transcript delete failed"))
    run = judge_tasks([_task()], eng)
    o = run.outcomes[0]
    assert o.state == JudgeRunState.FAILED and o.judgement is None
    assert "session close failed" in o.skip_reason  # parse_failed 가 아니라 close 가 우선
    assert "parse_failed" not in o.skip_reason


def test_judge_tasks_opens_one_session_per_candidate():
    """§4.2: 후보당 새 세션 1개, 각각 close."""
    eng = FakeEngine(_valid_json())
    judge_tasks([_task("a"), _task("b")], eng)
    assert len(eng.sessions) == 2
    assert all(s.closed for s in eng.sessions)


def test_judge_tasks_no_engine_all_skipped():
    run = judge_tasks([_task("a"), _task("b")], None)
    assert run.judged_count == 0 and run.judgement_skipped_count == 2
    assert all(o.state == JudgeRunState.SKIPPED for o in run.outcomes)
    assert run.llm_eligible_count == 2


# --- JudgeRun 회계 불변 ----------------------------------------------------- #

def test_judge_run_accounting_requires_id_set_match():
    o = JudgeOutcome(candidate_id="c1", state=JudgeRunState.SKIPPED, skip_reason="x")
    with pytest.raises(ValueError):  # outcomes {c1} != eligible {c1,c2}
        JudgeRun(outcomes=[o], eligible_candidate_ids=["c1", "c2"])


def test_judge_run_rejects_duplicate_candidate():
    o1 = JudgeOutcome(candidate_id="c1", state=JudgeRunState.SKIPPED, skip_reason="x")
    o2 = JudgeOutcome(candidate_id="c1", state=JudgeRunState.SKIPPED, skip_reason="y")
    with pytest.raises(ValueError):  # outcomes 중복 c1
        JudgeRun(outcomes=[o1, o2], eligible_candidate_ids=["c1"])


def test_judge_run_counts_are_computed_and_serialized():
    """codex s3core: count 는 @computed_field 라 model_dump/to_report_counts 로 누락 없이 전달."""
    run = judge_tasks([_task("a"), _task("b")], FakeEngine(_valid_json()))
    assert run.to_report_counts() == {
        "llm_eligible_count": 2, "judged_count": 2,
        "judgement_skipped_count": 0, "s3_completed": True,
    }
    dumped = run.model_dump()
    assert dumped["llm_eligible_count"] == 2 and dumped["judged_count"] == 2


def test_judge_run_dump_is_output_only_not_round_trippable():
    """codex s3core2: model_dump 는 진단용(output-only). computed count 는 입력이 아니라
    model_validate(dump) round-trip 은 미지원(StrictModel extra=forbid). 배선은 to_report_counts."""
    run = judge_tasks([_task("a")], FakeEngine(_valid_json()))
    with pytest.raises(Exception):
        JudgeRun.model_validate(run.model_dump())


def test_judge_outcome_judged_requires_matching_judgement():
    out = JudgeOutput(verdict=Verdict.LIKELY_RISK)
    sj = assemble_semantic_judgement(_task(cid="c1"), out)
    with pytest.raises(ValueError):  # candidate_id mismatch
        JudgeOutcome(candidate_id="c2", state=JudgeRunState.JUDGED, judgement=sj)
    with pytest.raises(ValueError):  # judged without judgement
        JudgeOutcome(candidate_id="c1", state=JudgeRunState.JUDGED)
    with pytest.raises(ValueError):  # skipped without reason
        JudgeOutcome(candidate_id="c1", state=JudgeRunState.SKIPPED)
