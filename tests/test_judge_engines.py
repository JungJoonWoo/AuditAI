"""S3 실 CLI 엔진 + 세션 + capability probe 테스트 (docs/06 §4.2·§4.3).

보안 subprocess 속성(stdin/env scrub/cwd/timeout/nonzero-exit)은 `python` 을 fake 바이너리로 검증
(LLM 호출 0). argv 검증자·COMSPEC 고정·세션 new/resume(Fake)·behavioral canary(Fake leak vs no-leak)
도 LLM 0 으로 검증. 실 CLI probe 는 `--help` 만(설치 시에만 skipif) — 실 LLM 판정은 안 한다.
"""

import os
import subprocess
import sys

import pytest

from auditai.contracts import CapabilityProbeResult
from auditai.judge_engines import (
    ArgValidationError,
    ClaudeCliEngine,
    CodexCliEngine,
    EngineError,
    GeminiCliEngine,
    JudgeSession,
    _fixed_comspec,
    _run_behavioral_probe,
    _run_cli,
    _scrubbed_env,
    build_judge_engine,
    probe_engine,
    validate_binary_path,
    validate_effort_arg,
    validate_model_arg,
    validate_uuid_arg,
)

import shutil

_UUID = "12345678-1234-1234-1234-123456789abc"


# --- 보안 subprocess (_run_cli / _scrubbed_env) ---------------------------- #

def test_run_cli_returns_completed_process_with_stdin():
    proc = _run_cli([sys.executable, "-c", "import sys; sys.stdout.write(sys.stdin.read())"],
                    "PROMPT-VIA-STDIN", timeout=30)
    assert isinstance(proc, subprocess.CompletedProcess)
    assert proc.returncode == 0 and proc.stdout.strip() == "PROMPT-VIA-STDIN"


def test_run_cli_preserves_nonzero_returncode():
    proc = _run_cli([sys.executable, "-c", "import sys; sys.exit(3)"], "", timeout=30)
    assert proc.returncode == 3  # CompletedProcess 로 returncode 보존(예외 아님)


def test_run_cli_scrubs_env(monkeypatch):
    monkeypatch.setenv("AUDITAI_TEST_SECRET", "leak-me")
    proc = _run_cli(
        [sys.executable, "-c", "import os; print(os.environ.get('AUDITAI_TEST_SECRET','SCRUBBED'))"],
        "", timeout=30)
    assert proc.stdout.strip() == "SCRUBBED"


def test_scrubbed_env_keeps_path_drops_secret(monkeypatch):
    monkeypatch.setenv("AUDITAI_TEST_SECRET2", "x")
    env = _scrubbed_env()
    assert "AUDITAI_TEST_SECRET2" not in env
    assert "PATH" in env or "Path" in env


def test_scrubbed_env_drops_gemini_api_key_file(monkeypatch):
    """§4.3 #4: GEMINI_API_KEY_FILE 는 allowlist 에서 제거됐다."""
    monkeypatch.setenv("GEMINI_API_KEY_FILE", "/secret/key")
    assert "GEMINI_API_KEY_FILE" not in _scrubbed_env()


def test_run_cli_runs_in_given_cwd(tmp_path):
    proc = _run_cli([sys.executable, "-c", "import os; print(os.getcwd())"],
                    "", timeout=30, cwd=str(tmp_path))
    assert str(tmp_path) in proc.stdout


def test_run_cli_timeout_raises():
    with pytest.raises(subprocess.TimeoutExpired):
        _run_cli([sys.executable, "-c", "import time; time.sleep(10)"], "", timeout=0.5)


# --- COMSPEC 고정 (§4.3 #1) ------------------------------------------------ #

@pytest.mark.skipif(os.name != "nt", reason="COMSPEC fixing is Windows-only")
def test_fixed_comspec_uses_systemroot_not_parent_env(monkeypatch):
    monkeypatch.setenv("COMSPEC", r"C:\evil\cmd.exe")  # 부모 COMSPEC 오염
    cs = _fixed_comspec()
    assert cs.lower().endswith(r"system32\cmd.exe")
    assert "evil" not in cs.lower()  # 부모 COMSPEC 무시


@pytest.mark.skipif(os.name != "nt", reason="COMSPEC fixing is Windows-only")
def test_fixed_comspec_uses_real_system_dir_even_without_systemroot_env(monkeypatch):
    """§4.3 #7: SystemRoot env 가 없어도 GetSystemDirectoryW 로 실 system32 를 쓴다(env 불신)."""
    monkeypatch.delenv("SystemRoot", raising=False)
    monkeypatch.delenv("SYSTEMROOT", raising=False)
    cs = _fixed_comspec()
    assert cs.lower().endswith(r"system32\cmd.exe")


@pytest.mark.skipif(os.name != "nt", reason="COMSPEC fixing is Windows-only")
def test_fixed_comspec_rejects_forged_systemroot(monkeypatch):
    """§4.3 #7: SystemRoot env 가 실 system32 와 불일치(위조)면 fail-closed."""
    monkeypatch.setenv("SystemRoot", r"C:\evil-windows")
    monkeypatch.setenv("SYSTEMROOT", r"C:\evil-windows")
    with pytest.raises(EngineError):
        _fixed_comspec()


@pytest.mark.skipif(os.name == "nt", reason="non-Windows: no GetSystemDirectoryW → fail-closed")
def test_fixed_comspec_fails_closed_without_os_api():
    """비 Windows: GetSystemDirectoryW 미가용 → SystemRoot env 만으로 신뢰 불가, fail-closed."""
    with pytest.raises(EngineError):
        _fixed_comspec()


# --- argv 검증자 (§4.3 #1) ------------------------------------------------- #

def test_validate_model_arg_accepts_and_rejects():
    assert validate_model_arg("claude-haiku-4-5") == "claude-haiku-4-5"
    assert validate_model_arg("anthropic/claude.opus_4:8@v1") == "anthropic/claude.opus_4:8@v1"
    for bad in ["claude haiku", "model;rm -rf", "m&n", "m|n", "m>x", "m`x`", "m$x", ""]:
        with pytest.raises(ArgValidationError):
            validate_model_arg(bad)


def test_validate_uuid_arg_accepts_and_rejects():
    assert validate_uuid_arg(_UUID) == _UUID
    for bad in ["", "short", _UUID + "extra", _UUID[:-1] + "!", "zzzzzzzz-1234-1234-1234-123456789abc",
                _UUID + " " + _UUID]:
        with pytest.raises(ArgValidationError):
            validate_uuid_arg(bad)


def test_validate_effort_arg():
    for ok in ["low", "medium", "high", "xhigh", "max"]:
        assert validate_effort_arg(ok) == ok
    for bad in ["LOW", "extreme", "", "high; rm"]:
        with pytest.raises(ArgValidationError):
            validate_effort_arg(bad)


def test_validate_binary_path():
    abs_ok = r"C:\Tools\claude.exe" if os.name == "nt" else "/usr/bin/claude"
    assert validate_binary_path(abs_ok) == abs_ok
    with pytest.raises(ArgValidationError):  # 상대경로
        validate_binary_path("claude")
    with pytest.raises(ArgValidationError):  # 메타문자
        validate_binary_path(abs_ok + " & calc")
    # repo 내부 거부
    repo = os.getcwd()
    inside = os.path.join(repo, "evil.exe")
    with pytest.raises(ArgValidationError):
        validate_binary_path(inside, repo_root=repo)


def test_validate_uuid_arg_round_trip_rejects_malformed_hyphens():
    """§4.3 #9: hex/하이픈-36 형태만 맞고 실 UUID 아닌 값(하이픈 오배치)은 거부."""
    # 길이 36·[0-9a-fA-F-] 통과하지만 canonical UUID 아님(하이픈 위치 비정상).
    bad = "123456789012345678901234567890------"
    assert len(bad) == 36
    with pytest.raises(ArgValidationError):
        validate_uuid_arg(bad)
    # 하이픈 위치가 8-4-4-4-12 가 아닌 케이스도 거부.
    bad2 = "1234567-812-3412-3412-3456789abcd012"
    with pytest.raises(ArgValidationError):
        validate_uuid_arg(bad2)


def test_validate_binary_path_repo_internal_env_override(tmp_path):
    """§4.3 #5: env-override(절대경로)도 repo_root 내부면 거부."""
    repo = tmp_path / "repo"
    (repo).mkdir()
    inside = repo / "evil.exe"
    inside.write_text("x")
    with pytest.raises(ArgValidationError):
        validate_binary_path(str(inside), repo_root=str(repo))


def test_resolve_binary_rejects_path_resolved_inside_repo(tmp_path, monkeypatch):
    """§4.3 #5: PATH 가 repo 내부로 해석되는 바이너리도 거부(악성 PATH 주입 차단)."""
    import auditai.judge_engines as je

    repo = tmp_path / "repo"
    repo.mkdir()
    fake_bin = repo / "claude"
    fake_bin.write_text("#!/bin/sh\n")
    monkeypatch.setattr(je.shutil, "which", lambda name: str(fake_bin))
    with pytest.raises(ArgValidationError):
        je._resolve_binary("claude", repo_root=str(repo))


def test_resolve_binary_env_override_inside_repo(tmp_path):
    """§4.3 #5: env-override 가 repo 내부면 _resolve_binary 가 거부."""
    import auditai.judge_engines as je

    repo = tmp_path / "repo"
    repo.mkdir()
    inside = repo / "claude.exe"
    inside.write_text("x")
    with pytest.raises(ArgValidationError):
        je._resolve_binary("claude", env_override=str(inside), repo_root=str(repo))


def test_build_judge_engine_repo_root_rejects_internal_binary(tmp_path, monkeypatch):
    """§4.3 #5: build_judge_engine(repo_root=) 가 PATH-resolved repo-내부 바이너리를 graceful degrade."""
    repo = tmp_path / "repo"
    repo.mkdir()
    fake_bin = repo / "claude"
    fake_bin.write_text("#!/bin/sh\n")
    import auditai.judge_engines as je
    monkeypatch.setattr(je.shutil, "which", lambda name: str(fake_bin))
    engine, probe = build_judge_engine("claude", repo_root=str(repo))
    assert engine is None and not probe.usable


def test_engine_construct_rejects_bad_model():
    with pytest.raises(ArgValidationError):
        ClaudeCliEngine(model="bad model; rm")


def test_codex_construct_rejects_bad_effort():
    with pytest.raises(ArgValidationError):
        CodexCliEngine(effort="extreme")


# --- 엔진 argv 안전 플래그 + 세션 argv ------------------------------------- #

def test_claude_new_and_resume_argv():
    eng = ClaudeCliEngine()
    new = eng._new_argv(_UUID)
    assert new[:2] == ["--session-id", _UUID]
    assert "--tools" in new and new[new.index("--tools") + 1] == ""
    assert "--strict-mcp-config" in new and "--output-format" in new
    res = eng._resume_argv(_UUID)
    assert res[:2] == ["--resume", _UUID]
    with pytest.raises(ArgValidationError):  # 메타문자 uuid 거부
        eng._new_argv("bad;id")


def test_claude_argv_model_override():
    a = ClaudeCliEngine(model="claude-haiku-4-5")._new_argv(_UUID)
    assert "--model" in a and a[a.index("--model") + 1] == "claude-haiku-4-5"
    assert "--model" not in ClaudeCliEngine()._new_argv(_UUID)


def test_codex_new_and_resume_argv():
    eng = CodexCliEngine()
    new = eng._new_argv("")
    assert new[0] == "exec" and "--skip-git-repo-check" in new
    assert new[new.index("-s") + 1] == "read-only"
    assert "model_reasoning_effort=medium" in new
    res = eng._resume_argv(_UUID)
    assert res[:3] == ["exec", "resume", _UUID]
    assert "model_reasoning_effort=high" in CodexCliEngine(effort="high")._new_argv("")


def test_codex_new_session_id_parsed_from_output():
    eng = CodexCliEngine()
    assert eng._new_session_id() is None  # 출력 파싱이라 사전생성 안 함
    assert eng._parse_session_id(f"prelude\nsession id: {_UUID}\nmore") == _UUID
    with pytest.raises(EngineError):
        eng._parse_session_id("no session here")
    with pytest.raises(EngineError):  # 앵커는 맞으나 uuid 형식 위반 → 매칭 실패
        eng._parse_session_id("session id: not-a-valid-uuid")


def test_gemini_new_resume_delete_argv():
    eng = GeminiCliEngine()
    new = eng._new_argv(_UUID)
    assert new[:2] == ["--session-id", _UUID]
    assert new[new.index("--approval-mode") + 1] == "plan"
    assert new[new.index("--prompt") + 1] == ""
    assert eng._resume_argv(_UUID)[:2] == ["--resume", _UUID]
    assert eng._delete_argv(_UUID) == ["--delete-session", _UUID]


def test_claude_has_no_delete_argv():
    assert ClaudeCliEngine()._delete_argv(_UUID) is None


# --- 출력 추출 (_extract) -------------------------------------------------- #

def test_claude_extract_unwraps_json_envelope():
    import json
    inner = '{"verdict": "likely_risk", "reason": "x"}'
    envelope = json.dumps({"type": "result", "result": inner})
    assert ClaudeCliEngine()._extract(envelope) == inner


def test_claude_extract_passthrough_when_not_envelope():
    raw = '{"verdict": "suspicious"}'
    assert ClaudeCliEngine()._extract(raw) == raw


def test_codex_extract_strips_ansi_and_truncates_usage_line_anchored():
    raw = '\x1b[32mcodex\x1b[0m\n{"verdict":"false_positive"}\ntokens used: 1234'
    out = CodexCliEngine()._extract(raw)
    assert "\x1b[" not in out and "tokens used" not in out
    assert '{"verdict":"false_positive"}' in out


def test_codex_extract_does_not_truncate_tokens_used_inside_json():
    """§4.3 #6: 줄-앵커라 JSON 내부의 'tokens used' 는 안 자른다."""
    raw = '{"reason": "the tokens used were unsanitized", "verdict": "likely_risk"}'
    out = CodexCliEngine()._extract(raw)
    assert "unsanitized" in out and "likely_risk" in out


# --- nonzero exit → EngineError (fail-closed, §4.3 #2) --------------------- #

class _FakeBinEngine(ClaudeCliEngine):
    """python 을 fake 바이너리로 써서 _exec 의 nonzero fail-closed 를 검증."""

    def __init__(self, code: int, stdout: str):
        super().__init__()
        self.binary_path = sys.executable
        self._code = code
        self._stdout = stdout

    def _prog_argv(self):  # python -c 로 지정 stdout 출력 후 exit code
        prog = f"import sys; sys.stdout.write({self._stdout!r}); sys.exit({self._code})"
        return ["-c", prog]

    def _new_argv(self, session_id):
        return self._prog_argv()

    def _resume_argv(self, session_id):
        return self._prog_argv()


def test_engine_run_nonzero_exit_raises_even_with_json_stdout():
    eng = _FakeBinEngine(code=2, stdout='{"verdict":"false_positive"}')
    with eng.start_session() as s:
        with pytest.raises(EngineError):  # exit≠0 → stdout JSON 무시
            s.send("prompt", timeout=30)


def test_engine_run_zero_exit_returns_stdout():
    eng = _FakeBinEngine(code=0, stdout='{"verdict":"likely_risk"}')
    with eng.start_session() as s:
        out = s.send("prompt", timeout=30)
    assert '{"verdict":"likely_risk"}' in out


# --- 세션 new-per-candidate + resume-for-repair (§4.2) --------------------- #

class _RecordingSession:
    """new/resume 호출을 기록하는 가짜 세션."""

    def __init__(self, engine):
        self.engine = engine
        self.modes: list[str] = []
        self.started = False
        self.closed = False

    def send(self, prompt, *, timeout):
        mode = "resume" if self.started else "new"
        self.started = True
        self.modes.append(mode)
        self.engine.all_modes.append(mode)
        return self.engine.responses.pop(0)

    def close(self):
        self.closed = True
        self.engine.closed_count += 1

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class _RecordingEngine:
    name = "rec"
    model = "rec-model"

    def __init__(self, responses):
        self.responses = list(responses)
        self.all_modes: list[str] = []
        self.sessions: list[_RecordingSession] = []
        self.closed_count = 0

    def start_session(self):
        s = _RecordingSession(self)
        self.sessions.append(s)
        return s


def test_session_new_per_candidate_and_resume_for_repair():
    from auditai.contracts import JudgeTask
    from auditai.judge import judge_tasks
    valid = '{"verdict":"likely_risk","reason":"r"}'
    # 후보 c1: 첫 응답 garbage(parse fail) → repair resume → valid. 후보 c2: 첫 응답 valid.
    eng = _RecordingEngine(["garbage", valid, valid])
    tasks = [JudgeTask(candidate_id="c1", prompt="p1", static_path_confirmed=True),
             JudgeTask(candidate_id="c2", prompt="p2", static_path_confirmed=True)]
    run = judge_tasks(tasks, eng)
    assert run.judged_count == 2
    # 후보당 새 세션 2개, 각각 close
    assert len(eng.sessions) == 2 and eng.closed_count == 2
    # 세션1: new + resume(repair), 세션2: new
    assert eng.sessions[0].modes == ["new", "resume"]
    assert eng.sessions[1].modes == ["new"]


def test_real_session_new_then_resume_modes():
    """실 _CliJudgeEngine 세션: 첫 send=new, 둘째 send=resume (python fake 바이너리)."""
    eng = _FakeBinEngine(code=0, stdout='{"verdict":"suspicious"}')
    s = eng.start_session()
    assert isinstance(s, JudgeSession)
    assert not s._started
    s.send("first", timeout=30)
    assert s._started  # 첫 send 후 started
    # 둘째 send 는 resume 경로(session_id 필요) — claude 는 사전생성 uuid 라 resume 가능
    s.send("second", timeout=30)
    s.close()


# --- behavioral probe canary (§4.3 #3) ------------------------------------- #

class _LeakyBinEngine(ClaudeCliEngine):
    """도구가 '안 막힌' 엔진 시뮬레이션 — cwd 의 CANARY 파일을 읽어 stdout 으로 유출."""

    def __init__(self):
        super().__init__()
        self.binary_path = sys.executable

    def _new_argv(self, session_id):
        prog = ("import os,glob\n"
                "for f in glob.glob('CANARY'):\n"
                "    print(open(f).read())\n")
        return ["-c", prog]


class _SafeBinEngine(ClaudeCliEngine):
    """도구가 막힌 엔진 시뮬레이션 — 파일 안 읽고 UNABLE 만 출력."""

    def __init__(self):
        super().__init__()
        self.binary_path = sys.executable

    def _new_argv(self, session_id):
        return ["-c", "print('UNABLE')"]


class _WriteLeakBinEngine(ClaudeCliEngine):
    """도구가 '안 막힌' 엔진 — read-canary 는 안 찍지만 cwd 의 CANARY 파일을 **수정**(write side-effect).

    codex bj94zik1d-1 의 핵심: 출력에 토큰이 없어도(=read-token 스캔 통과해도) write side-effect 가
    일어나면 도구가 켜진 것이므로 probe 는 FAIL 해야 한다. "UNABLE" 출력만으로 통과 금지를 강제."""

    def __init__(self):
        super().__init__()
        self.binary_path = sys.executable

    def _new_argv(self, session_id):
        prog = ("open('CANARY','w').write('PWNED')\n"
                "print('done, said UNABLE')\n")  # 출력엔 canary 토큰 없음
        return ["-c", prog]


class _TranscriptLeakBinEngine(ClaudeCliEngine):
    """도구가 '안 막힌' 엔진 — read-canary 를 stdout 이 아니라 **config/transcript 디렉토리**로 유출.

    codex bj94zik1d-2: stdout/stderr 만 스캔하면 transcript 로 새는 토큰을 놓친다. config_env_var 로
    주입된 세션 전용 디렉토리에 canary 내용을 쓰면 probe 가 그 디렉토리도 스캔해 FAIL 해야 한다."""

    def __init__(self):
        super().__init__()
        self.binary_path = sys.executable

    def _new_argv(self, session_id):
        # CLAUDE_CONFIG_DIR(세션 전용 temp config) 안에 cwd 의 CANARY 내용을 transcript 로 기록.
        prog = (
            "import os\n"
            "cfg=os.environ.get('CLAUDE_CONFIG_DIR')\n"
            "data=open('CANARY').read()\n"
            "open(os.path.join(cfg,'transcript.log'),'w').write('user asked; read: '+data)\n"
            "print('UNABLE')\n"  # 출력엔 canary 없음 — transcript 에만 샘
        )
        return ["-c", prog]


def test_behavioral_probe_detects_leak():
    res = _run_behavioral_probe(_LeakyBinEngine(), timeout=30)
    assert not res.passed and "leak" in res.detail.lower()


def test_behavioral_probe_passes_when_safe():
    res = _run_behavioral_probe(_SafeBinEngine(), timeout=30)
    assert res.passed, res.detail


def test_behavioral_probe_detects_write_side_effect():
    """§4.3 #1: write side-effect(canary 수정)는 출력 토큰 없어도 FAIL — 'UNABLE'만으론 통과 못 함."""
    res = _run_behavioral_probe(_WriteLeakBinEngine(), timeout=30)
    assert not res.passed
    assert "write" in res.detail.lower() or "mutat" in res.detail.lower()


def test_behavioral_probe_detects_transcript_leak():
    """§4.3 #2: read-canary 가 stdout 이 아닌 transcript/config 디렉토리로 새면 FAIL."""
    res = _run_behavioral_probe(_TranscriptLeakBinEngine(), timeout=30)
    assert not res.passed
    assert "transcript" in res.detail.lower() or "config" in res.detail.lower()


def test_behavioral_probe_nonzero_exit_is_failclosed():
    """§4.3 #1·#2: probe CLI 가 nonzero exit → 검증 불가 → passed=False(fail-closed)."""

    class _ErrEngine(ClaudeCliEngine):
        def __init__(self):
            super().__init__()
            self.binary_path = sys.executable

        def _new_argv(self, session_id):
            return ["-c", "import sys; print('UNABLE'); sys.exit(7)"]

    res = _run_behavioral_probe(_ErrEngine(), timeout=30)
    assert not res.passed and "exit" in res.detail.lower()


def test_behavioral_probe_send_exception_is_failclosed(monkeypatch):
    """codex bj94zik1d-1: send 예외가 밖으로 새지 않고 passed=False 로 수렴(fail-closed)."""
    eng = _SafeBinEngine()

    def boom(self, session, prompt, *, timeout):
        raise RuntimeError("subprocess blew up")

    monkeypatch.setattr(type(eng), "_probe_send_raw", boom)
    res = _run_behavioral_probe(eng, timeout=30)
    assert not res.passed and "send failed" in res.detail.lower()


def test_behavioral_probe_start_session_exception_is_failclosed(monkeypatch):
    """codex bj94zik1d-1: start_session 예외도 passed=False 로 수렴(밖으로 raise 안 함)."""
    eng = _SafeBinEngine()

    def boom(self):
        raise RuntimeError("cannot create temp dir")

    monkeypatch.setattr(type(eng), "start_session", boom)
    res = _run_behavioral_probe(eng, timeout=30)
    assert not res.passed and "fail-closed" in res.detail.lower()


def test_probe_send_raw_sets_started_and_parses_codex_session(monkeypatch):
    """codex bj94zik1d(round2)-1: probe send 도 세션 상태를 갱신해 close 가 세션을 삭제하게 한다.

    codex 는 출력에서 session id 를 파싱하고 _started=True 가 되어, close() 가 _delete_session 호출."""
    eng = CodexCliEngine()
    eng.binary_path = sys.executable
    deleted = {"called": False, "id": None}

    def fake_run_cli(argv, stdin, *, timeout, cwd=None, env=None):
        return subprocess.CompletedProcess(argv, 0, stdout=f"session id: {_UUID}\nUNABLE", stderr="")

    def fake_delete(self, session):
        deleted["called"] = True
        deleted["id"] = session._session_id

    import auditai.judge_engines as je
    monkeypatch.setattr(je, "_run_cli", fake_run_cli)
    monkeypatch.setattr(CodexCliEngine, "_delete_session", fake_delete)

    s = eng.start_session()
    eng._probe_send_raw(s, "probe", timeout=30)
    assert s._started is True
    assert s._session_id == _UUID  # codex 출력에서 파싱됨
    s.close()
    assert deleted["called"] and deleted["id"] == _UUID  # probe 세션이 삭제됨


def test_safety_fingerprint_propagates_failure(monkeypatch):
    """codex bj94zik1d(round2)-3: _safety_fingerprint 실패는 삼키지 않고 전파(빈 튜플 fallback 없음)."""
    eng = ClaudeCliEngine()

    def boom(self):
        raise EngineError("base argv broke")

    monkeypatch.setattr(ClaudeCliEngine, "_base_argv", boom)
    with pytest.raises(EngineError):
        eng._safety_fingerprint()


def test_build_judge_engine_argv_build_error_converges_unusable(monkeypatch):
    """codex bj94zik1d(round3)-1: _base_argv(→_new_argv/_safety_fingerprint) 예외가 factory 밖으로
    새지 않고 engine=None + unusable 로 수렴(fail-closed)."""
    import auditai.judge_engines as je

    eng_for_markers = ClaudeCliEngine()
    markers = " ".join(eng_for_markers.spec.safety_markers)

    def fake_run_cli(argv, stdin, *, timeout, cwd=None, env=None):
        if "--help" in argv:
            return subprocess.CompletedProcess(argv, 0, stdout=markers, stderr="")
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    def boom(self):
        raise EngineError("base argv broke")

    monkeypatch.setattr(je, "_run_cli", fake_run_cli)
    monkeypatch.setattr(je, "_resolve_binary", lambda *a, **k: sys.executable)
    monkeypatch.setattr(ClaudeCliEngine, "_base_argv", boom)
    # factory 가 crash 하지 않고 graceful degrade 해야 함.
    engine, probe = build_judge_engine("claude")
    assert engine is None and not probe.usable


def test_build_judge_engine_defaults_repo_root_to_cwd(monkeypatch, tmp_path):
    """codex bj94zik1d(round2)-2: repo_root 미지정 시 cwd 로 fail-closed — env-override 가 cwd 내부면 거부."""
    import auditai.judge_engines as je
    # cwd 를 tmp_path 로 바꾸고, 그 안의 바이너리를 env-override 로 지정 → repo 내부라 거부되어야 함.
    inside = tmp_path / "claude.exe"
    inside.write_text("x")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("AUDITAI_JUDGE_CLAUDE_PATH", str(inside))
    engine, probe = build_judge_engine("claude")  # repo_root 미지정 → cwd(tmp_path)
    assert engine is None and not probe.usable
    assert "repo" in probe.detail.lower() or "arg validation" in probe.detail.lower()


def test_behavioral_probe_no_config_dir_is_failclosed():
    """codex bj94zik1d-2/6: config/transcript 격리 dir 가 없으면 누출 검증 불가 → fail-closed."""

    class _NoConfigEngine(_SafeBinEngine):
        config_env_var = ""  # transcript 격리 없음

    res = _run_behavioral_probe(_NoConfigEngine(), timeout=30)
    assert not res.passed and "config" in res.detail.lower()


def test_behavioral_probe_unreadable_transcript_is_failclosed(monkeypatch):
    """codex bj94zik1d-2: transcript 스캔 중 읽기 실패는 '누출 없음'이 아니라 '검증 불가' → fail-closed."""
    import auditai.judge_engines as je
    eng = _SafeBinEngine()

    orig = je._scan_dir_for_token

    def uncertain_scan(root, tokens):
        return None, True  # 읽기 실패 시뮬레이션(uncertain)

    monkeypatch.setattr(je, "_scan_dir_for_token", uncertain_scan)
    res = _run_behavioral_probe(eng, timeout=30)
    assert not res.passed and "inconclusive" in res.detail.lower()


# --- run-scoped behavioral cache (§4.3 #4) --------------------------------- #

def test_behavioral_cache_is_run_scoped_not_global():
    """§4.3 #4: 캐시는 프로세스 전역이 아니라 주입된 run-scoped 객체. 한 run 내 1회만 실행."""
    from auditai.judge_engines import BehavioralProbeCache

    calls = {"n": 0}

    class _CountingEngine(_SafeBinEngine):
        pass

    import auditai.judge_engines as je
    orig = je._run_behavioral_probe

    def counting(engine, *, timeout=60.0):
        calls["n"] += 1
        return orig(engine, timeout=timeout)

    je._run_behavioral_probe = counting
    try:
        cache = BehavioralProbeCache()
        eng = _CountingEngine()
        cache.get_or_run(eng)
        cache.get_or_run(eng)  # 같은 키 → 캐시 히트
        assert calls["n"] == 1
        cache.clear()
        cache.get_or_run(eng)  # clear 후 재실행
        assert calls["n"] == 2
        # 새 cache 인스턴스는 독립(전역 공유 아님)
        BehavioralProbeCache().get_or_run(eng)
        assert calls["n"] == 3
    finally:
        je._run_behavioral_probe = orig


def test_behavioral_cache_key_includes_safety_and_mode():
    """§4.3 #4: 캐시 키 = (클래스, model, effort, binary, help-argv, safety-markers, config mode,
    **실제 sandbox argv 지문**). help marker 가 아니라 실행 안전 argv 가 키에 들어가야 한다."""
    from auditai.judge_engines import BehavioralProbeCache

    eng = ClaudeCliEngine()
    k = BehavioralProbeCache.key(eng)
    assert ClaudeCliEngine.spec.help_argv in k
    assert ClaudeCliEngine.spec.safety_markers in k
    assert "CLAUDE_CONFIG_DIR" in k  # config/sandbox mode
    # 실제 sandbox argv 지문(--tools "" 등)이 키에 포함되어야 함(codex bj94zik1d-4).
    fp = tuple(eng._base_argv())
    assert fp in k
    assert "--tools" in fp


def test_behavioral_cache_key_differs_by_sandbox_argv():
    """§4.3 #4: codex effort(=sandbox 실행 인자 일부)가 다르면 캐시 키도 달라야 한다(stale 방지)."""
    from auditai.judge_engines import BehavioralProbeCache

    k_med = BehavioralProbeCache.key(CodexCliEngine(effort="medium"))
    k_high = BehavioralProbeCache.key(CodexCliEngine(effort="high"))
    assert k_med != k_high


# --- 세션 전용 config/transcript 격리 (§4.3 #6) ---------------------------- #

def test_session_injects_dedicated_config_dir():
    """§4.3 #6: 세션이 전용 temp CLAUDE_CONFIG_DIR 을 만들어 env 로 주입한다."""
    eng = ClaudeCliEngine()
    s = eng.start_session()
    try:
        assert s.config_dir and os.path.isdir(s.config_dir)
        env = s.env()
        assert env["CLAUDE_CONFIG_DIR"] == s.config_dir
        # config dir 은 cwd 와 분리(둘 다 temp, 분석 repo 아님)
        assert s.config_dir != s.cwd
    finally:
        s.close()


def test_session_close_removes_config_dir():
    """§4.3 #6: close 가 전용 config(=transcript) 디렉토리를 삭제한다."""
    eng = ClaudeCliEngine()
    s = eng.start_session()
    cfg = s.config_dir
    assert cfg and os.path.isdir(cfg)
    s.close()
    assert not os.path.isdir(cfg)  # transcript 잔존 금지


def test_claude_delete_session_no_config_dir_is_failclosed():
    """§4.3 #6: claude(삭제 미지원)인데 config-dir 격리도 없으면 transcript 누출 → EngineError."""
    eng = ClaudeCliEngine()
    s = eng.start_session()
    s._session_id = _UUID
    s._started = True
    # config 격리 제거 시뮬레이션 → _delete_session 이 fail-closed
    s.config_dir = None
    eng.config_env_var = ""
    with pytest.raises(EngineError):
        eng._delete_session(s)
    s.config_dir = None  # cleanup 안전


def test_probe_engine_unusable_when_behavioral_fails(monkeypatch):
    """help probe 통과해도 behavioral leak 이면 usable=False."""
    eng = _LeakyBinEngine()
    # help 통과 시뮬레이션: 안전마커 전부 포함하는 --help stdout
    markers = " ".join(eng.spec.safety_markers)
    import auditai.judge_engines as je

    def fake_run_cli(argv, stdin, *, timeout, cwd=None, env=None):
        if "--help" in argv:
            return subprocess.CompletedProcess(argv, 0, stdout=markers, stderr="")
        # behavioral send → leak (cwd 의 canary 읽음)
        import glob
        os.chdir(cwd)
        leaked = ""
        for f in glob.glob("CANARY"):
            leaked += open(f).read()
        return subprocess.CompletedProcess(argv, 0, stdout=leaked, stderr="")

    monkeypatch.setattr(je, "_run_cli", fake_run_cli)
    probe = probe_engine(eng, run_behavioral=True)
    assert probe.safety_flags_present and probe.behavioral_probe_run
    assert not probe.behavioral_probe_passed and not probe.usable


# --- session close: transcript delete failure = security FAILED (§4.3) ----- #

def test_session_close_delete_failure_raises(monkeypatch):
    eng = GeminiCliEngine()
    eng.binary_path = sys.executable
    s = eng.start_session()
    s._mark_session(_UUID)  # id commit → _delete_needed=True
    s._started = True

    def boom(self, session):
        raise EngineError("delete failed")

    monkeypatch.setattr(GeminiCliEngine, "_delete_session", boom)
    with pytest.raises(EngineError):
        s.close()  # transcript 삭제 실패 → 보안 FAILED


def test_session_close_deletes_even_if_send_failed(monkeypatch):
    """round3-2: send 가 timeout/예외로 _started 가 안 올라가도, id 가 commit 됐으면 close 가 삭제 시도."""
    eng = GeminiCliEngine()
    eng.binary_path = sys.executable
    s = eng.start_session()
    s._mark_session(_UUID)  # _send_new 가 _run_cli 호출 '전' 표시한 상태 모사
    # _started 는 False(=send 가 중간에 죽음) — 그래도 삭제는 시도되어야 함.
    assert s._started is False and s._delete_needed is True
    called = {"n": 0}

    def rec(self, session):
        called["n"] += 1

    monkeypatch.setattr(GeminiCliEngine, "_delete_session", rec)
    s.close()
    assert called["n"] == 1  # _started=False 여도 삭제 시도됨


# --- probe / factory: graceful degrade ------------------------------------ #

def test_probe_absent_binary_unusable():
    eng = ClaudeCliEngine()
    eng.binary_path = None
    probe = probe_engine(eng)
    assert isinstance(probe, CapabilityProbeResult)
    assert not probe.usable and "not on PATH" in probe.detail


def test_build_unknown_engine_returns_none():
    engine, probe = build_judge_engine("totally-not-an-engine")
    assert engine is None and not probe.usable
    assert "unknown" in probe.detail


def test_build_engine_bad_model_graceful_degrade():
    engine, probe = build_judge_engine("claude", model="bad model;rm")
    assert engine is None and not probe.usable


def test_capability_probe_usable_gate():
    """§4.3 #3(codex bj94zik1d-3): usable 의 불변 게이트(stdin·flags 누락/behavioral 실패 → unusable).

    TARGET 계약 공식 = stdin AND flags AND behavioral_probe_run AND behavioral_probe_passed
    (contract_change_needed 로 통합자에게 전달). 전부 True 면 usable, 어느 하나라도 거짓이면 unusable."""
    full = CapabilityProbeResult(engine="x", supports_stdin=True, safety_flags_present=True,
                                 behavioral_probe_run=True, behavioral_probe_passed=True)
    assert full.usable  # 4-True → usable (모든 계약 공식에서 성립)
    bad = CapabilityProbeResult(engine="x", supports_stdin=True, safety_flags_present=False)
    assert not bad.usable
    beh = CapabilityProbeResult(engine="x", supports_stdin=True, safety_flags_present=True,
                                behavioral_probe_run=True, behavioral_probe_passed=False)
    assert not beh.usable  # behavioral 돌렸는데 실패 → unusable
    no_stdin = CapabilityProbeResult(engine="x", supports_stdin=False, safety_flags_present=True,
                                     behavioral_probe_run=True, behavioral_probe_passed=True)
    assert not no_stdin.usable


def test_build_judge_engine_requires_behavioral_pass(monkeypatch):
    """§4.3 #3b: behavioral 미실행/미통과면 build_judge_engine 이 engine 을 절대 반환하지 않는다.

    계약 usable 공식과 무관하게 factory 레벨에서 명시 가드(behavioral_probe_run AND passed)를 강제한다."""
    import auditai.judge_engines as je

    # help 통과 + behavioral 미통과 시뮬레이션(safety markers 포함 stdout, behavioral leak).
    eng_for_markers = ClaudeCliEngine()
    markers = " ".join(eng_for_markers.spec.safety_markers)

    def fake_run_cli(argv, stdin, *, timeout, cwd=None, env=None):
        if "--help" in argv:
            return subprocess.CompletedProcess(argv, 0, stdout=markers, stderr="")
        # behavioral send → leak (read canary 유출)
        leaked = ""
        if cwd:
            cpath = os.path.join(cwd, "CANARY")
            if os.path.exists(cpath):
                leaked = open(cpath).read()
        return subprocess.CompletedProcess(argv, 0, stdout=leaked, stderr="")

    monkeypatch.setattr(je, "_run_cli", fake_run_cli)
    monkeypatch.setattr(je, "_resolve_binary", lambda *a, **k: sys.executable)
    engine, probe = build_judge_engine("claude", cache=None)
    assert engine is None  # behavioral 실패 → 등록 금지
    assert probe.behavioral_probe_run and not probe.behavioral_probe_passed


# --- 실 CLI probe (--help 만, 설치 시에만; behavioral 미실행) --------------- #

@pytest.mark.skipif(not shutil.which("claude"), reason="claude CLI not installed")
def test_real_claude_probe_finds_safety_flags():
    probe = probe_engine(ClaudeCliEngine(), run_behavioral=False)
    assert probe.supports_stdin and probe.safety_flags_present, probe.detail


@pytest.mark.skipif(not shutil.which("codex"), reason="codex CLI not installed")
def test_real_codex_probe_finds_safety_flags():
    probe = probe_engine(CodexCliEngine(), run_behavioral=False)
    assert probe.supports_stdin and probe.safety_flags_present, probe.detail


@pytest.mark.skipif(not shutil.which("gemini"), reason="gemini CLI not installed")
def test_real_gemini_probe_finds_safety_flags():
    probe = probe_engine(GeminiCliEngine(), run_behavioral=False)
    assert probe.supports_stdin and probe.safety_flags_present, probe.detail
