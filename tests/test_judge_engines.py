"""S3 실 CLI 엔진 + capability probe 테스트.

보안 subprocess 속성(stdin/env scrub/cwd/timeout)은 `python` 을 fake 바이너리로 검증(LLM 호출 0).
실 CLI probe 는 `--help` 만 호출(LLM·인증 불필요)하며 해당 CLI 가 PATH 에 있을 때만(skipif).
실제 판정 실행(real LLM call)은 이 단위테스트에서 하지 않는다.
"""

import shutil
import subprocess
import sys

import pytest

from auditai.contracts import CapabilityProbeResult
from auditai.judge_engines import (
    ClaudeCliEngine,
    CodexCliEngine,
    GeminiCliEngine,
    _run_cli,
    _scrubbed_env,
    build_judge_engine,
    probe_engine,
)


# --- 보안 subprocess (_run_cli / _scrubbed_env) ---------------------------- #

def test_run_cli_passes_prompt_via_stdin():
    out = _run_cli([sys.executable, "-c", "import sys; sys.stdout.write(sys.stdin.read())"],
                   "PROMPT-VIA-STDIN", timeout=30)
    assert out.strip() == "PROMPT-VIA-STDIN"


def test_run_cli_scrubs_env(monkeypatch):
    monkeypatch.setenv("AUDITAI_TEST_SECRET", "leak-me")
    out = _run_cli(
        [sys.executable, "-c", "import os; print(os.environ.get('AUDITAI_TEST_SECRET','SCRUBBED'))"],
        "", timeout=30)
    assert out.strip() == "SCRUBBED"  # allowlist 밖 → subprocess 에 미전달


def test_scrubbed_env_keeps_path_drops_secret(monkeypatch):
    monkeypatch.setenv("AUDITAI_TEST_SECRET2", "x")
    env = _scrubbed_env()
    assert "AUDITAI_TEST_SECRET2" not in env
    assert "PATH" in env or "Path" in env  # 실행에 필요한 PATH 는 보존


def test_run_cli_runs_in_given_cwd(tmp_path):
    out = _run_cli([sys.executable, "-c", "import os; print(os.getcwd())"],
                   "", timeout=30, cwd=str(tmp_path))
    assert str(tmp_path) in out


def test_run_cli_timeout_raises():
    with pytest.raises(subprocess.TimeoutExpired):
        _run_cli([sys.executable, "-c", "import time; time.sleep(10)"], "", timeout=0.5)


# --- 엔진 argv 안전 플래그 ------------------------------------------------- #

def test_claude_argv_disables_tools_and_mcp():
    a = ClaudeCliEngine()._argv()
    assert a[:2] == ["-p", "--output-format"] and "json" in a
    # --tools "" (도구 전무) + --strict-mcp-config
    i = a.index("--tools")
    assert a[i + 1] == "" and "--strict-mcp-config" in a
    assert "--model" not in a  # 모델 미지정 시 CLI 기본(검증=capable)


def test_claude_argv_model_override():
    a = ClaudeCliEngine(model="claude-haiku-4-5")._argv()
    assert "--model" in a and a[a.index("--model") + 1] == "claude-haiku-4-5"


def test_codex_argv_read_only_sandbox_and_effort():
    a = CodexCliEngine()._argv()
    assert a[0] == "exec" and "--skip-git-repo-check" in a
    assert a[a.index("-s") + 1] == "read-only"
    assert "model_reasoning_effort=medium" in a  # S3=검증 → low 아님
    a_high = CodexCliEngine(effort="high")._argv()
    assert "model_reasoning_effort=high" in a_high


def test_gemini_argv_approval_plan_readonly():
    a = GeminiCliEngine()._argv()
    assert a[a.index("--approval-mode") + 1] == "plan"  # read-only
    assert a[a.index("--prompt") + 1] == ""  # 프롬프트는 stdin


# --- 출력 추출 (_extract) -------------------------------------------------- #

def test_claude_extract_unwraps_json_envelope():
    import json
    inner = '{"verdict": "likely_risk", "reason": "x"}'
    envelope = json.dumps({"type": "result", "result": inner})
    assert ClaudeCliEngine()._extract(envelope) == inner


def test_claude_extract_passthrough_when_not_envelope():
    raw = '{"verdict": "suspicious"}'
    assert ClaudeCliEngine()._extract(raw) == raw  # result 키 없음 → 원문 그대로


def test_codex_extract_strips_ansi_and_truncates_usage():
    raw = '\x1b[32mcodex\x1b[0m\n{"verdict":"false_positive"}\ntokens used\n1234'
    out = CodexCliEngine()._extract(raw)
    assert "\x1b[" not in out and "tokens used" not in out
    assert '{"verdict":"false_positive"}' in out


# --- probe / factory: graceful degrade ------------------------------------ #

def test_probe_absent_binary_unusable():
    eng = ClaudeCliEngine()
    eng.binary_path = None  # 미설치 시뮬레이션
    probe = probe_engine(eng)
    assert isinstance(probe, CapabilityProbeResult)
    assert not probe.usable and "not on PATH" in probe.detail


def test_build_unknown_engine_returns_none():
    engine, probe = build_judge_engine("totally-not-an-engine")
    assert engine is None and not probe.usable
    assert "unknown" in probe.detail


def test_capability_probe_usable_gate():
    # stdin + safety flags → usable (behavioral 미실행이면 플래그 신뢰)
    ok = CapabilityProbeResult(engine="x", supports_stdin=True, safety_flags_present=True)
    assert ok.usable
    # 안전플래그 부재 → unusable
    bad = CapabilityProbeResult(engine="x", supports_stdin=True, safety_flags_present=False)
    assert not bad.usable
    # behavioral 돌렸는데 실패 → unusable(돌린 경우엔 통과 필수)
    beh = CapabilityProbeResult(engine="x", supports_stdin=True, safety_flags_present=True,
                                behavioral_probe_run=True, behavioral_probe_passed=False)
    assert not beh.usable


# --- 실 CLI probe (--help 만 호출, 설치 시에만) ---------------------------- #

@pytest.mark.skipif(not shutil.which("claude"), reason="claude CLI not installed")
def test_real_claude_probe_finds_safety_flags():
    probe = probe_engine(ClaudeCliEngine())
    assert probe.supports_stdin and probe.safety_flags_present, probe.detail


@pytest.mark.skipif(not shutil.which("codex"), reason="codex CLI not installed")
def test_real_codex_probe_finds_safety_flags():
    probe = probe_engine(CodexCliEngine())
    assert probe.supports_stdin and probe.safety_flags_present, probe.detail


@pytest.mark.skipif(not shutil.which("gemini"), reason="gemini CLI not installed")
def test_real_gemini_probe_finds_safety_flags():
    probe = probe_engine(GeminiCliEngine())
    assert probe.supports_stdin and probe.safety_flags_present, probe.detail
