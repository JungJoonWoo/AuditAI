"""S3 — LLM semantic judge (CLI 멀티엔진). 설계/검증: docs/06 §4·§4.1 (codex s3plan2 82%/조건부).

이 모듈의 **deterministic 핵심**(FakeEngine·JSON 파서·assemble·회계)은 네트워크/CLI 0 으로 테스트된다.
실 CLI 엔진(claude/codex/gemini)과 capability probe(보안 민감)는 별도 모듈/청크로 추가·검증한다.

핵심 불변(fail-closed, codex r1 M4): 파싱/CLI 실패는 **절대 `Verdict.false_positive`/NO_VULN 로 강등하지
않고** `JudgeRunState.FAILED`(또는 미전송 시 SKIPPED)로 회계한다 — '미판정'은 '무해'가 아니다.
모든 eligible task 는 outcome 하나로 회계되어 카운트 누락이 불가능하다(codex s3plan2 #5).
"""

from __future__ import annotations

import json
import re
from typing import Callable, Protocol

from .contracts import (
    JudgeOutcome,
    JudgeOutput,
    JudgeRun,
    JudgeRunState,
    JudgeTask,
    assemble_semantic_judgement,
)


class JudgeSession(Protocol):
    """판정 대화 세션(§4.2). 첫 send=새 세션, 이후 send=resume. judge.py 가 세션 수명으로
    new(후보별)/resume(후보내 repair) 정책을 강제한다 — 엔진/세션은 정책을 결정하지 않는다."""

    def send(self, prompt: str, *, timeout: float) -> str: ...
    def close(self) -> None: ...
    def __enter__(self) -> "JudgeSession": ...
    def __exit__(self, *exc) -> None: ...


class JudgeEngine(Protocol):
    """판정 엔진 추상화. `start_session()` 으로 세션을 열고, 그 세션의 `send()` 로만 프롬프트를 보낸다.

    실 엔진은 프롬프트를 **stdin** 으로 전달하고 shell=False·cwd=temp·env scrub·안전플래그를
    강제한다(docs/06 §4). 여기 protocol 은 그 계약의 표면만 정의한다.
    """

    name: str
    model: str

    def start_session(self) -> JudgeSession: ...


class _FakeSession:
    """FakeEngine 세션. send 순서대로 응답 소진, close 시 정리(transcript 삭제 시뮬레이션 포함)."""

    def __init__(self, engine: "FakeEngine"):
        self._engine = engine
        self.closed = False

    def send(self, prompt: str, *, timeout: float) -> str:
        if self.closed:
            raise RuntimeError("send() on a closed fake session")
        return self._engine._next(prompt)

    def close(self) -> None:
        self.closed = True
        if self._engine.close_error is not None:
            raise self._engine.close_error  # transcript 삭제 실패 시뮬레이션

    def __enter__(self) -> "_FakeSession":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


class FakeEngine:
    """테스트용 엔진. 미리 정한 응답을 순서대로 반환(네트워크/CLI 0).

    `responses`: str(항상 동일) | list[str|Exception](순서대로; Exception 은 raise; 소진 시 마지막
    반복) | Callable[[str], str](프롬프트→응답). Exception 응답으로 CLI 실패를 시뮬레이션한다.
    세션 인터페이스(start_session/send/close)를 지원한다(§4.2). `sessions` 로 생성된 세션을,
    `calls` 로 전체 프롬프트를 관찰한다. `close_error` 설정 시 close 가 raise(transcript 삭제 실패).
    """

    name = "fake"

    def __init__(self, responses: str | list | Callable[[str], str], model: str = "fake-model",
                 close_error: BaseException | None = None):
        self._responses = responses
        self._i = 0
        self.model = model
        self.calls: list[str] = []
        self.sessions: list[_FakeSession] = []
        self.close_error = close_error

    def _next(self, prompt: str) -> str:
        self.calls.append(prompt)
        r = self._responses
        if callable(r):
            val = r(prompt)
        elif isinstance(r, str):
            val = r
        else:
            val = r[self._i] if self._i < len(r) else r[-1]
            self._i += 1
        if isinstance(val, BaseException):
            raise val
        return val

    def start_session(self) -> _FakeSession:
        s = _FakeSession(self)
        self.sessions.append(s)
        return s


_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
_FENCE_RE = re.compile(r"```[a-zA-Z0-9_-]*\n?|```")


class JudgeParseError(ValueError):
    """LLM 출력에서 유효한 JudgeOutput 을 복원하지 못함(절대 verdict 추측 금지 → 미판정)."""


def extract_judge_output(raw: str) -> JudgeOutput:
    """LLM stdout → JudgeOutput.

    코드펜스/ANSI strip → 첫 ``{`` .. 마지막 ``}`` 블록 → JSON → **JudgeOutput 알려진 필드만**
    취함(codex s3plan2 #4: LLM 이 넣은 `static_path_confirmed`/`vulnerability_confirmed`/잡키는
    무시). 복원 실패 시 `JudgeParseError`.
    """
    if not raw or not raw.strip():
        raise JudgeParseError("empty output")
    s = _ANSI_RE.sub("", raw)
    s = _FENCE_RE.sub("", s)
    # codex s3core2: 무차별 '{' 스캔은 배열(`prose\n[{...}]`)·중첩 wrapper(`{"note":{...}}`) 내부
    # 객체를 top-level 로 **승격**하는 fail-open 이다. 첫 JSON 구조 시작 문자만 본다 — '[' 가 '{' 보다
    # 먼저 나오면 배열로 reject, '{' 면 **그 하나의 최외곽 객체만** raw_decode(trailing prose 무시).
    # 그 객체가 JudgeOutput 으로 검증 안 되면 더 깊이 스캔하지 않고 reject(fail-closed). 산문+객체는
    # 통과하나, '비스키마 wrapper + 내부 verdict' 류는 거부 → 필요 시 repair 재요청이 처리한다.
    brace = s.find("{")
    bracket = s.find("[")
    if brace < 0:
        raise JudgeParseError("no JSON object found")
    if 0 <= bracket < brace:
        raise JudgeParseError("top-level JSON array not accepted (expected a single object)")
    try:
        obj, _end = json.JSONDecoder().raw_decode(s[brace:])
    except json.JSONDecodeError as e:
        raise JudgeParseError(f"invalid JSON object: {e}") from e
    if not isinstance(obj, dict):
        raise JudgeParseError("first JSON value is not an object")
    known = {k: v for k, v in obj.items() if k in JudgeOutput.model_fields}
    try:
        return JudgeOutput(**known)  # 알려진 필드만 — LLM 의 잡키/강제필드 무시
    except Exception as e:  # pydantic ValidationError 등 → 미판정(verdict 추측 금지)
        raise JudgeParseError(f"schema mismatch: {e}") from e


_REPAIR_SUFFIX = (
    "\n\n[형식 오류] 직전 출력이 JSON 스키마에 맞지 않았다. "
    "지정한 JSON 객체 **하나만** 다시 출력하라(코드펜스·산문·설명 금지)."
)


def _judge_one(task: JudgeTask, engine: JudgeEngine, *, timeout: float) -> JudgeOutcome:
    """task 1개(=1 후보) 판정. **새 세션 1개**로 첫 send(new), parse 실패 시 같은 세션 resume 으로
    1회 repair 재요청, 그래도 실패면 FAILED. CLI/세션/transcript-삭제 예외도 FAILED.

    §4.2: new(후보별)/resume(후보내 repair) 결정은 **judge.py 가 세션 수명으로** 한다 — `with
    engine.start_session()` 으로 후보당 1 세션을 열고, repair 는 같은 세션의 send(=resume)로 보낸다.
    엔진은 send 횟수로 new/resume 을 자동 결정할 뿐 정책을 결정하지 않는다.

    **어떤 실패도 false_positive 로 떨어뜨리지 않는다**(fail-closed). transcript 삭제 실패(close)도
    보안상 FAILED 로 회계한다(§4.3).
    """
    model = getattr(engine, "model", "")

    def _fail(reason: str) -> JudgeOutcome:
        return JudgeOutcome(
            candidate_id=task.candidate_id, state=JudgeRunState.FAILED,
            skip_reason=reason, engine=engine.name, model=model,
        )

    try:
        session = engine.start_session()  # 후보별 새 세션
    except Exception as e:
        return _fail(f"engine_error: session start failed: {type(e).__name__}: {e}")

    out = None
    parse_err: str | None = None
    engine_err: str | None = None
    close_err: str | None = None
    try:
        try:
            try:
                out = extract_judge_output(session.send(task.prompt, timeout=timeout))  # new
            except JudgeParseError:
                # 같은 세션 resume 으로 repair(모델이 자기 직전 출력을 이어서 교정).
                out = extract_judge_output(
                    session.send(task.prompt + _REPAIR_SUFFIX, timeout=timeout)
                )
        except JudgeParseError as e:
            parse_err = f"parse_failed: {e}"
        except Exception as e:  # CLI/timeout/비정상 종료/세션 send 실패 — 전송했으나 실패
            engine_err = f"engine_error: {type(e).__name__}: {e}"
    finally:
        try:
            session.close()  # temp cwd/config 삭제 + transcript 삭제(실패는 보안 FAILED)
        except Exception as e:
            # §4.3 #8(codex bj94zik1d-8): close(=transcript 삭제) 실패는 **보안 우선** 으로 기록하며
            # 동시 발생한 parse 실패에 가려지지 않는다(우선순위: close > engine > parse).
            close_err = f"engine_error: session close failed: {type(e).__name__}: {e}"

    if close_err is not None:
        return _fail(close_err)
    if engine_err is not None:
        return _fail(engine_err)
    if parse_err is not None:
        return _fail(parse_err)
    return JudgeOutcome(
        candidate_id=task.candidate_id, state=JudgeRunState.JUDGED,
        judgement=assemble_semantic_judgement(task, out), engine=engine.name, model=model,
    )


def judge_tasks(
    tasks: list[JudgeTask], engine: JudgeEngine | None, *, timeout: float = 60.0
) -> JudgeRun:
    """eligible task 들을 판정 → JudgeRun. 모든 task 가 outcome 하나로 회계(누락 불가).

    engine 이 None(미설치/probe 실패/graceful degrade) → 전원 SKIPPED(미전송). s3_completed 는
    judge 단계가 실제로 수행됐음을 뜻하며(=True), 미판정은 outcomes 의 SKIPPED/FAILED 로 표면화돼
    `resolve_run_status` 가 SEMANTIC_JUDGE_NOT_RUN 으로 처리한다(NO_VULN 오독 금지).
    """
    if engine is None:
        outcomes = [
            JudgeOutcome(
                candidate_id=t.candidate_id, state=JudgeRunState.SKIPPED,
                skip_reason="no usable judge engine (not installed / probe failed)",
            )
            for t in tasks
        ]
    else:
        outcomes = [_judge_one(t, engine, timeout=timeout) for t in tasks]
    return JudgeRun(
        outcomes=outcomes,
        eligible_candidate_ids=[t.candidate_id for t in tasks],
        s3_completed=True,
    )
