"""S3 — 실 CLI judge 엔진 + capability probe (보안 민감). 설계: docs/06 §4·§4.1.

deterministic 핵심은 `judge.py`(FakeEngine). 이 모듈은 **실제 LLM CLI 를 subprocess 로** 호출하는
어댑터다(claude/codex/gemini). 사용자 결정: API 키가 아니라 설치된 CLI 의 자체 인증을 쓴다.

보안(codex s3plan2 #1/§4.1):
- `shell=False`(argv 리스트) — 셸 인젝션 차단.
- **프롬프트는 argv 가 아니라 stdin** — 인자 인젝션/길이 한계 회피.
- **cwd = 임시 디렉토리**(분석 repo 아님) — 후보 코드가 있는 트리에서 실행하지 않음.
- **env scrub**(allowlist) — 분석 repo 의 비밀/토큰을 LLM CLI 로 새지 않게.
- 엔진별 **안전 플래그 강제**: claude `--tools ""`(도구 전무)+`--strict-mcp-config`, codex `-s read-only`,
  gemini `--approval-mode plan`(read-only). 실재는 capability probe 가 `--help` 로 확인.
- timeout 강제(미응답 hang 차단).

capability probe(`probe_engine`): 바이너리 PATH 존재 + 요구 안전플래그가 `--help` 에 실재해야
`usable`. (behavioral probe — temp cwd 에서 도구/파일접근 실차단 실측 — 는 추가 hardening, 별도.)
미설치/플래그 부재 → `build_judge_engine` 이 None 반환 → judge_tasks 가 graceful degrade(전원 SKIPPED).
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass

from .contracts import CapabilityProbeResult

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

# subprocess 로 넘길 환경변수 allowlist — 나머지(ANTHROPIC_API_KEY·repo 비밀·CI 토큰 등)는 제거.
# CLI 인증은 자체 config 디렉토리(USERPROFILE/HOME/CODEX_HOME 등)에서 읽으므로 그 경로만 보존.
_ENV_ALLOWLIST = (
    "PATH", "PATHEXT", "HOME", "USERPROFILE", "SYSTEMROOT", "SystemRoot", "WINDIR",
    "TEMP", "TMP", "TMPDIR", "COMSPEC", "LANG", "LC_ALL", "LC_CTYPE",
    "APPDATA", "LOCALAPPDATA", "NUMBER_OF_PROCESSORS",
    "CODEX_HOME", "CLAUDE_CONFIG_DIR", "GEMINI_CONFIG_DIR", "GEMINI_API_KEY_FILE",
    "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME",
)


def _scrubbed_env() -> dict[str, str]:
    """allowlist 만 남긴 최소 환경(분석 repo 비밀 유출 차단)."""
    return {k: os.environ[k] for k in _ENV_ALLOWLIST if k in os.environ}


def _resolve_binary(binary: str) -> str | None:
    """CLI 바이너리 절대경로 해석. Windows 에선 npm 글로벌 셰임이 확장자 없는 bash 스크립트일 수 있어
    (CreateProcess 시 WinError 193), `.cmd`/`.exe`/`.bat` 실행 변형을 우선 탐색한다."""
    if os.name == "nt":
        for ext in (".cmd", ".exe", ".bat"):
            p = shutil.which(binary + ext)
            if p:
                return p
    return shutil.which(binary)


def _run_cli(
    argv: list[str], stdin_text: str, *, timeout: float,
    cwd: str | None = None, env: dict[str, str] | None = None,
) -> str:
    """보안 subprocess: shell=False, 프롬프트 stdin, cwd 격리, env scrub, timeout. stdout 반환.

    TimeoutExpired/OSError 등은 호출측으로 전파(→ _judge_one 이 FAILED 로 회계). 비정상 종료코드는
    예외로 올리지 않고 stdout 을 반환한다(LLM CLI 가 경고와 함께 0!=exit 로 끝나도 출력을 파싱)."""
    exe = argv[0]
    real = list(argv)
    # Windows: npm 글로벌 .cmd/.bat 셰임은 CreateProcess 로 직접 실행 불가 → comspec 경유(여전히 shell=False, 고정 argv).
    if os.name == "nt" and exe.lower().endswith((".cmd", ".bat")):
        real = [os.environ.get("COMSPEC", "cmd.exe"), "/c", *real]
    proc = subprocess.run(
        real, input=stdin_text, capture_output=True, text=True, timeout=timeout,
        cwd=cwd, env=env if env is not None else _scrubbed_env(), shell=False, check=False,
    )
    return proc.stdout


@dataclass(frozen=True)
class _EngineSpec:
    name: str
    binary: str
    help_argv: tuple[str, ...]       # capability probe 용 --help 호출 인자
    safety_markers: tuple[str, ...]  # --help 에 반드시 존재해야 하는 안전플래그 토큰


class _CliJudgeEngine:
    """공통 CLI 엔진. 서브클래스가 `spec`·`_argv()`(+선택 `_extract`)를 정의."""

    spec: _EngineSpec

    def __init__(self, model: str | None = None):
        self.name = self.spec.name
        self.model = model or ""
        self.binary_path = _resolve_binary(self.spec.binary)

    def _argv(self) -> list[str]:
        raise NotImplementedError

    def _extract(self, stdout: str) -> str:
        return stdout

    def run(self, prompt: str, *, timeout: float) -> str:
        if not self.binary_path:
            raise FileNotFoundError(f"{self.spec.binary} not on PATH")
        # cwd=임시 디렉토리(분석 repo 아님). 프롬프트는 stdin.
        with tempfile.TemporaryDirectory(prefix="auditai-judge-") as td:
            out = _run_cli([self.binary_path, *self._argv()], prompt, timeout=timeout, cwd=td)
        return self._extract(out)


class ClaudeCliEngine(_CliJudgeEngine):
    """`claude -p` 비대화. `--tools ""`(도구 전무)+`--strict-mcp-config`(외부 MCP 차단). JSON envelope 의 result 추출."""

    spec = _EngineSpec(
        "claude", "claude", ("--help",),
        ("--tools", "--strict-mcp-config", "--output-format", "--print"),
    )

    def _argv(self) -> list[str]:
        a = ["-p", "--output-format", "json", "--tools", "", "--strict-mcp-config"]
        if self.model:
            a += ["--model", self.model]
        return a

    def _extract(self, stdout: str) -> str:
        # claude --output-format json → {"result": "<assistant text>", ...}. result 안에 판정 JSON 이 들어옴.
        try:
            env = json.loads(stdout)
        except (json.JSONDecodeError, ValueError):
            return stdout
        if isinstance(env, dict) and isinstance(env.get("result"), str):
            return env["result"]
        return stdout


class CodexCliEngine(_CliJudgeEngine):
    """`codex exec -s read-only`(샌드박스, approval=never). S3=검증이므로 effort 기본 medium(low 는 검출용)."""

    spec = _EngineSpec(
        "codex", "codex", ("exec", "--help"),
        ("--sandbox", "read-only", "--skip-git-repo-check"),
    )

    def __init__(self, model: str | None = None, effort: str = "medium"):
        super().__init__(model)
        self.effort = effort

    def _argv(self) -> list[str]:
        a = ["exec", "--skip-git-repo-check", "-s", "read-only",
             "-c", f"model_reasoning_effort={self.effort}"]
        if self.model:
            a += ["-m", self.model]
        return a

    def _extract(self, stdout: str) -> str:
        s = _ANSI_RE.sub("", stdout)
        i = s.rfind("tokens used")  # codex exec usage footer 절단(codex-review.sh 패턴)
        return s[:i] if i >= 0 else s


class GeminiCliEngine(_CliJudgeEngine):
    """`gemini --prompt "" --approval-mode plan`(plan=read-only). 프롬프트는 stdin 으로 전달."""

    spec = _EngineSpec(
        "gemini", "gemini", ("--help",),
        ("--approval-mode", "--prompt", "--model"),
    )

    def _argv(self) -> list[str]:
        a = ["--prompt", "", "--approval-mode", "plan"]
        if self.model:
            a += ["-m", self.model]
        return a


def probe_engine(engine: _CliJudgeEngine) -> CapabilityProbeResult:
    """바이너리 존재 + 요구 안전플래그가 `--help` 에 실재하는지 확인 → CapabilityProbeResult.

    검증 불가(미설치/--help 실패/플래그 부재)면 usable=False → 등록 안 함(graceful degrade).
    """
    spec = engine.spec
    if not engine.binary_path:
        return CapabilityProbeResult(
            engine=spec.name, supports_stdin=False, safety_flags_present=False,
            detail=f"{spec.binary} not on PATH",
        )
    try:
        help_text = _run_cli([engine.binary_path, *spec.help_argv], "", timeout=30)
    except Exception as e:
        return CapabilityProbeResult(
            engine=spec.name, argv=engine._argv(), supports_stdin=False,
            safety_flags_present=False,
            detail=f"--help probe failed: {type(e).__name__}: {e}",
        )
    missing = [m for m in spec.safety_markers if m not in help_text]
    return CapabilityProbeResult(
        engine=spec.name, version="", argv=engine._argv(), supports_stdin=True,
        safety_flags_present=not missing,
        detail="ok" if not missing else f"missing safety markers in --help: {missing}",
    )


_ENGINE_CLASSES: dict[str, type[_CliJudgeEngine]] = {
    "claude": ClaudeCliEngine,
    "codex": CodexCliEngine,
    "gemini": GeminiCliEngine,
}


def build_judge_engine(
    name: str | None = None, model: str | None = None
) -> tuple[_CliJudgeEngine | None, CapabilityProbeResult]:
    """엔진 팩토리(probe-게이트). 반환: (engine|None, probe). probe.usable 가 아니면 engine=None.

    name 기본 = env `AUDITAI_JUDGE_ENGINE` 또는 'claude'. model 오버라이드 = env `AUDITAI_JUDGE_MODEL`.
    None 이면 호출측(judge_tasks)이 전원 SKIPPED 로 graceful degrade.
    """
    name = (name or os.environ.get("AUDITAI_JUDGE_ENGINE") or "claude").lower()
    model = model or os.environ.get("AUDITAI_JUDGE_MODEL")
    cls = _ENGINE_CLASSES.get(name)
    if cls is None:
        return None, CapabilityProbeResult(
            engine=name, detail=f"unknown judge engine {name!r} (choices: {sorted(_ENGINE_CLASSES)})",
        )
    engine = cls(model=model)
    probe = probe_engine(engine)
    if not probe.usable:
        return None, probe
    return engine, probe
