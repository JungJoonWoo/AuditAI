"""Pipeline gates G1~G4 (계획 docs/05-p0-blockers.md §6).

각 게이트는 GateResult 를 산출하고, RunReport/resolve_run_status 가 이를 최종 RunStatus 로
변환한다. 핵심: "빈 결과를 정상으로 착각 금지" — source=0/flow=0 은 G2 가 먼저 판정.
"""

from __future__ import annotations

import ast
import re
import subprocess
from dataclasses import dataclass

from .attribution import _GIT_TIMEOUT, GitError, _git
from .contracts import (
    GateFailureCode,
    GateId,
    GateResult,
    GateStatus,
    TargetType,
    TRACK_B_DISCLOSURE,
)
from .scope import DiffScope

_FRAMEWORKS = ("fastapi", "starlette", "strawberry")

# 탐지 패턴(part-1 changed-file content 용 Python regex). 다중 import/서브모듈/경계 처리
# (codex Q1r3 R3-5 + Q1r4 R4-2):
#   import 줄: `import X` / `import os, fastapi` / `import fastapi as fa` / `import fastapi.sub`
#   from 줄:   `from fastapi import Y` / `from fastapi.sub import Y`
#   배제:      `fastapix`, `from fastapilib import` (prefix 오탐)
def _py_import_re(name: str) -> re.Pattern:
    return re.compile(
        rf"(?m)^[ \t]*("
        rf"import[ \t]+(.*[ \t,])?{name}([ \t.,]|$)"
        rf"|from[ \t]+{name}([.]|[ \t]+import))"
    )


# repo-wide 후보 파일 토큰 grep(part-2). codex G2 over-flag r7 #1: 후보 단계는 **보수적으로 넓게**
# (framework 이름이 단어로 등장하는 모든 .py) 잡고, 정밀 판정은 AST(`_frameworks_from_tree`)에 맡긴다.
# line-anchored import 문법으로 좁히면 line-continuation(`import os, \`↵`fastapi`) 같은 유효 import 를
# 후보에서 놓쳐 under-detection 이 된다. 단어 경계로 `myfastapi`/`fastapix` prefix 오탐만 배제.
def _token_candidate_ere(name: str) -> str:
    return rf"(^|[^[:alnum:]_]){name}([^[:alnum:]_]|$)"


# 동적 import 탐지(codex Q1r5 R5-1): importlib.import_module("fastapi") / __import__('fastapi')
#   codex G2 over-flag r2 #2: keyword 리터럴(`import_module(name="fastapi")`)도 잡음.
#   codex G2 over-flag r3 #2: 함수명 경계((?<![\w.]))로 `not_import_module(`/`obj.import_module(`/
#     `my__import__(` 같은 부분문자열·메서드 오탐 차단. importlib. 접두는 선택.
#   codex G2 over-flag r4 #1: 함수명과 `(` 사이 공백(`import_module ("x")`)도 유효한 Python 호출 → 허용.
#   주의: 이 regex 는 **변경 파일 parse 실패 시의 폴백 전용**(`_scan_changed_file`). repo-wide import
#   탐지는 regex(ERE)로 Python callee 문법·문자열/주석을 정확히 막을 수 없어(예: `obj . import_module(...)`
#   공백 속성 접근, multiline 문자열 내 import) AST 스캔(`_repo_wide_frameworks`)을 쓴다(codex r5 #1/r6 #2).
def _py_dyn_re(name: str) -> re.Pattern:
    return re.compile(
        rf"(?<![\w.])(?:importlib\s*\.\s*)?import_module\s*\(\s*(?:name\s*=\s*)?['\"]{name}['\".]"
        rf"|(?<![\w.])__import__\s*\(\s*(?:name\s*=\s*)?['\"]{name}['\".]"
    )


_FRAMEWORK_MARKERS: dict[str, re.Pattern] = {n: _py_import_re(n) for n in _FRAMEWORKS}
_TOKEN_CANDIDATE_ERES: dict[str, str] = {n: _token_candidate_ere(n) for n in _FRAMEWORKS}
_DYN_MARKERS: dict[str, re.Pattern] = {n: _py_dyn_re(n) for n in _FRAMEWORKS}
# repo-wide 동적 import 후보 파일을 좁히는 느슨한 ERE(정밀 판정은 AST). 부분문자열도 허용(AST 가 거른다).
_DYN_CANDIDATE_ERE = r"(import_module|__import__)[[:space:]]*\("

# 의존성 선언 fallback(codex Q1r5 R5-1, fail-closed): 매니페스트에 framework 가 선언됐는데
# 어떤 import 로도 못 찾으면(동적/난독화 import 가능성) 탐지 미완료로 보고 G2 NOT_RUN 으로 강등.
_DEP_FILES = (
    "pyproject.toml", "setup.py", "setup.cfg", "Pipfile",
    "requirements.txt", "requirements-dev.txt",
    "requirements/base.txt", "requirements/dev.txt", "requirements/prod.txt",
)
_DEP_NAMES: dict[str, tuple[str, ...]] = {
    "fastapi": ("fastapi",),
    "starlette": ("starlette",),
    "strawberry": ("strawberry-graphql", "strawberry"),
}


def declared_framework_deps(repo: str, head_sha: str) -> set[str]:
    """head 트리의 의존성 매니페스트에서 선언된 framework 패키지 탐지.

    패키지명은 `-`/단어경계로 구분(예: `fastapi-utils` 는 fastapi 로 안 침). git show 실패 파일은 건너뜀.
    """
    found: set[str] = set()
    for path in _DEP_FILES:
        try:
            content = _git(repo, "show", f"{head_sha}:{path}")
        except GitError:
            continue
        for fw, pkgs in _DEP_NAMES.items():
            if fw in found:
                continue
            for pkg in pkgs:
                if re.search(rf"(?im)(?<![\w-]){re.escape(pkg)}(?![\w-])", content):
                    found.add(fw)
                    break
    return found


def _is_dynamic_import_callee(func: ast.expr) -> bool:
    """동적 import 호출 callee 인가 — `importlib.import_module(...)` / bare `import_module(...)` /
    builtin `__import__(...)` 만 인정.

    codex G2 over-flag r3 #1: receiver 를 확인해 임의 객체 메서드(`obj.import_module(...)`,
    `obj.__import__(...)`)는 제외(이름만 같을 뿐 importlib 가 아님 → over-flag/오탐 방지). alias 추적은
    MVP 밖(README)."""
    if isinstance(func, ast.Name):
        return func.id in ("import_module", "__import__")  # bare import_module / builtin __import__
    if isinstance(func, ast.Attribute):
        # importlib.import_module(...) 만 — obj.import_module/obj.__import__ 제외.
        return (func.attr == "import_module"
                and isinstance(func.value, ast.Name) and func.value.id == "importlib")
    return False


def _dynamic_import_spec(node: ast.Call) -> tuple[bool, str | None]:
    """node 가 동적 import 호출이면 (True, 리터럴 모듈명 or None), 아니면 (False, None).

    codex G2 over-flag r2 #1: **import 대상 인자만** 본다 — 첫 positional 또는 `name=` keyword.
    `import_module` 의 `package`, `__import__` 의 `globals/locals/fromlist/level` 같은 보조 인자는
    비-리터럴이어도 무시한다(`__import__("fastapi", globals(), locals(), ["FastAPI"])` 같은 정상 호출이
    over-flag 를 켜지 않게). 대상이 리터럴 str 이면 모듈명, 아니면(변수/표현식/`**kwargs`/누락) None."""
    if not _is_dynamic_import_callee(node.func):
        return False, None
    if node.args:
        target: ast.expr | None = node.args[0]
    else:
        target = next((kw.value for kw in node.keywords if kw.arg == "name"), None)
        if target is None and any(kw.arg is None for kw in node.keywords):
            return True, None  # `import_module(**d)` — 대상 미상
    if target is None:
        return True, None  # 동적 import 인데 대상 인자 식별 불가 → 미상(보강 트리거)
    if isinstance(target, ast.Constant) and isinstance(target.value, str):
        return True, target.value
    return True, None  # 비-리터럴 대상 → 미상


def _frameworks_from_tree(tree: ast.AST) -> set[str]:
    """parse 된 tree 에서 static + 동적(import_module/__import__ 리터럴 대상, 위치/키워드 인자) framework import."""
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                base = a.name.split(".")[0]
                if base in _FRAMEWORKS:
                    found.add(base)
        elif isinstance(node, ast.ImportFrom):
            # codex Q1r7 R7-2: 상대 import(`from .fastapi import x`)는 로컬 모듈 → level==0(절대)만 인정.
            if node.level == 0:
                base = (node.module or "").split(".")[0]
                if base in _FRAMEWORKS:
                    found.add(base)
        elif isinstance(node, ast.Call):
            is_dyn, mod = _dynamic_import_spec(node)
            if is_dyn and mod:
                base = mod.split(".")[0]
                if base in _FRAMEWORKS:
                    found.add(base)
    return found


def _frameworks_in_ast(content: str) -> set[str] | None:
    """AST framework import 탐지. parse 실패(부분 내용 등) 시 None → 호출측이 regex 폴백.

    주석/문자열 오탐 없음(codex Q1r6 R6-3). 변수인자 동적 import(`import_module(mod)`)는 정적 분석
    한계 — MVP out-of-scope(README 명시). 단 그 '불확실성'은 `_has_uncertain_dynamic_import` 로 별도 신호화."""
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return None
    return _frameworks_from_tree(tree)


def _has_uncertain_dynamic_import(tree: ast.AST) -> bool:
    """import_module/__import__ 호출의 **import 대상**이 정적 리터럴로 확정 안 되나 — 무엇을 import 하는지 불확실.

    codex G2 over-flag r2 #1/#2: 변경 파일이 검증된 framework(fastapi)를 import 하면서 동시에 변수 동적
    import(`mod="starlette"; import_module(mod)`)로 미검증 framework 를 끌어오면 정적 탐지가 후자를 놓친다.
    이 '불확실성'을 신호화해 case A 라도 보강을 켠다(트리거일 뿐 — NOT_RUN 보장 아님, r3 #3). 단 대상이
    리터럴이고 보조 인자만 비-리터럴인 정상 호출(`__import__("fastapi", globals(), ...)`)은 불확실로 보지 않는다."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            is_dyn, mod = _dynamic_import_spec(node)
            if is_dyn and mod is None:
                return True  # 대상 인자가 변수/표현식/누락 → import 대상 미상(out-of-scope) → 불확실
    return False


def _scan_changed_file(content: str) -> tuple[set[str], bool]:
    """변경 파일 1개 스캔 → (탐지된 framework, 불확실성).

    불확실성(uncertain)=True 조건: (a) AST parse 실패(부분/invalid 내용) 또는 (b) 변수 동적 import 존재.
    둘 다 '변경 파일이 실제로 무엇을 import 하는지 정적으로 확신 불가' → 호출측이 보강(repo-wide/dep-fallback)을 켜게."""
    try:
        tree = ast.parse(content)
    except SyntaxError:
        # parse 실패: regex 폴백으로 framework 추정 + 불확실성 True(보강 트리거).
        found = {n for n in _FRAMEWORKS
                 if _FRAMEWORK_MARKERS[n].search(content) or _DYN_MARKERS[n].search(content)}
        return found, True
    return _frameworks_from_tree(tree), _has_uncertain_dynamic_import(tree)


@dataclass(frozen=True)
class FrameworkScope:
    """G2 검증 스코프 결정을 위한 프레임워크 탐지 결과 분해.

    codex G2 over-flag 판정(2026-06): 단일 union set 으로 G2 를 돌리면 repo-wide 탐지가 transitive
    의존(FastAPI repo 내부 Starlette/Strawberry)을 잡아 거의 모든 실 FastAPI repo 를 항상 over-flag
    (MODEL_MISSING)로 만든다. → 변경 파일(AI-authored) framework 를 primary 스코프로 분리.
    """
    changed: set[str]                    # 변경 .py 파일에서 직접 탐지된 framework
    repo_wide: set[str]                  # repo 전체 AST 보강분(case B 또는 불확실성 시에만 수집)
    has_frameworkless_changed_py: bool   # framework import 가 없는 변경 .py 파일이 하나라도 있나
    uncertain_changed_py: bool           # 변경 .py 중 parse 실패 또는 변수 동적 import(import 대상 미상)
    repo_wide_incomplete: bool           # repo-wide 후보 파일 parse 실패(확인 불가) — detection-incomplete

    @property
    def needs_repo_wide_fallback(self) -> bool:
        """case B(frameworkless 변경 .py) 또는 불확실성 신호 → repo-wide/dep-fallback **보강을 켜는 트리거**.

        codex G2 over-flag r3 #3: 이 신호 자체는 차단(NOT_RUN)이 아니다 — 보강(repo-wide 정적 탐지 +
        의존성 매니페스트 dep-fallback)이 미검증 framework 를 잡아낼 '기회'를 켤 뿐이다. 보강이 잡으면
        그때 차단된다: dep-fallback(declared-but-not-imported) → fail-closed NOT_RUN, repo-wide 가 미검증
        framework 탐지 → G2 hard fail MODEL_MISSING(unreliable). 어떤 framework 인지 정적으로도 매니페스트
        로도 확인 불가한 순수 변수 동적 import 는 MVP 미탐지(README ⑥/⑧ 한계)."""
        return self.has_frameworkless_changed_py or self.uncertain_changed_py


def detect_framework_scope(repo: str, scope: DiffScope) -> FrameworkScope:
    """G2 스코프용 프레임워크 탐지. part-1 변경 파일 + part-2 repo-wide(조건부).

    **확정 설계(codex G2 over-flag 판정)** — "changed-file primary + frameworkless-changed-file fallback":
    - part-1: 변경된 각 .py 파일에서 framework import 를 탐지(`changed`). import 가 하나도 없는 변경 .py 가
      있으면 `has_frameworkless_changed_py=True`.
    - part-2(repo-wide grep)는 **변경 파일에 framework 없는 .py 가 있을 때만** 실행한다. 이유: 모든 변경
      .py 가 framework 에 귀속되면(case A) 그 framework 가 PR 결과 신뢰성을 결정하므로 repo 다른 곳의
      transitive import 로 over-flag 하면 안 된다. 반대로 framework 없는 변경 .py(helper-only/혼합 PR)가
      있으면(case B) 그 helper 가 미검증 framework 라우트로 흘러갈 수 있어 repo-wide 보강이 필요하다
      (under-detection 방지 보강 — 보강이 미검증 framework 를 잡으면 NOT_RUN/MODEL_MISSING). **트리거는
      "변경 framework 가 비었나"가 아니라 "framework 없는 변경
      .py 가 있나"** — 전자는 fastapi 파일 + frameworkless helper 혼합 PR 에서 구멍이 난다(codex 판정).

    **불확실성 보강 (codex G2 over-flag r2 #2 / r3 #3)**: 변경 파일에 framework import 가 있어도(case A),
    그 파일에 parse 실패나 변수 동적 import(import 대상 미상)가 있으면 미검증 framework 를 정적으로
    놓칠 수 있다. 이 경우(`uncertain_changed_py`)도 repo-wide/dep-fallback **보강을 켠다** — 단 이 신호
    자체가 차단(NOT_RUN)은 아니고, 보강이 해소할 때만 차단된다: dep-fallback(declared-but-not-imported)
    → fail-closed NOT_RUN, repo-wide 가 미검증 framework 탐지 → G2 hard fail MODEL_MISSING. 해소 안 되는
    순수 변수 동적 import(어떤 framework 인지 미상)는 MVP 미탐지(README ⑥/⑧).

    **fail-closed (codex Q1r3 R3-3/R3-4)**: repo-wide grep 의 '실제 장애'(no-match 아님)는 삼키지
    않고 GitError 를 전파한다 — 호출측(run_pipeline)이 G2 NOT_RUN(hard fail)으로 처리하게 한다.
    """
    changed: set[str] = set()
    has_frameworkless = False
    uncertain = False
    # (1) 변경된 .py 파일: 파일별로 framework import + 불확실성(parse 실패/변수 동적 import) 탐지.
    for fd in scope.files:
        if fd.is_delete or fd.is_binary or not fd.file.endswith(".py"):
            continue
        try:
            content = _git(repo, "show", f"{scope.head_sha}:{fd.file}")
        except GitError:
            content = "\n".join(a.text for a in fd.added_lines)
        file_fw, file_uncertain = _scan_changed_file(content)
        if file_fw:
            changed |= file_fw
        else:
            has_frameworkless = True  # framework import 없는 변경 .py → repo-wide fallback 트리거
        if file_uncertain:
            uncertain = True  # parse 실패/변수 동적 import → 정적 미상 → 보강 트리거(NOT_RUN 아님)
    # (2) repo-wide: frameworkless 변경 .py 또는 불확실성 신호가 있을 때만(over-flag 방지).
    #     정적·동적 import 모두 후보 grep → AST 확정(codex r5 #1/r6 #2 — regex 로는 `obj . import_module`
    #     공백 속성 접근·multiline 문자열 내 import 를 못 거름). 실제 grep 장애는 전파(fail-closed).
    repo_wide: set[str] = set()
    repo_wide_incomplete = False
    if has_frameworkless or uncertain:
        repo_wide, repo_wide_incomplete = _repo_wide_frameworks(repo, scope.head_sha, exclude=changed)
    return FrameworkScope(changed=changed, repo_wide=repo_wide,
                          has_frameworkless_changed_py=has_frameworkless,
                          uncertain_changed_py=uncertain,
                          repo_wide_incomplete=repo_wide_incomplete)


def detect_frameworks(repo: str, scope: DiffScope) -> set[str]:
    """호환 wrapper(변경 파일 + 조건부 repo-wide 의 union). G2 스코프 결정은 `detect_framework_scope` 사용.

    repo-wide 는 frameworkless 변경 .py 가 있을 때만 수집되므로, 모든 변경 .py 가 framework 에
    귀속된 경우(case A)에는 변경 파일 framework 만 반환된다(과거의 무조건 repo-wide union 과 다름).
    """
    fs = detect_framework_scope(repo, scope)
    return fs.changed | fs.repo_wide


def _grep_head_files(repo: str, pattern: str, ref: str) -> list[str]:
    """head 트리 .py 중 ERE pattern 매치 파일 경로 목록(`git grep -lIE`).

    codex Q1r2 F7: exit 1(no match)=[], exit 0(match)=파일목록, 그 외=실제 장애(GitError). `_git` 은 모든
    non-zero 를 GitError 로 접어 no-match 와 장애를 못 가리므로 직접 호출한다. `-I`(바이너리 무시).
    codex Q1r3 R3-4: timeout/OSError 도 GitError 로 정규화(통제된 hard fail → repo-wide 탐지 미완료 = NOT_RUN).
    `<ref>:path` 형태이므로 'ref:' 접두를 떼어 순수 경로를 돌려준다(이후 `git show <ref>:path` 재사용)."""
    try:
        proc = subprocess.run(
            ["git", "-C", repo, "grep", "-lIE", pattern, ref, "--", "*.py"],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=_GIT_TIMEOUT,
        )
    except (subprocess.SubprocessError, OSError) as e:
        raise GitError(f"git grep failed: {e}") from e
    if proc.returncode == 1:
        return []  # no match (정상)
    if proc.returncode != 0:
        raise GitError(f"git grep failed (exit {proc.returncode}): {proc.stderr.strip()}")
    prefix = f"{ref}:"
    out: list[str] = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if line:
            out.append(line[len(prefix):] if line.startswith(prefix) else line)
    return out


def _repo_wide_frameworks(repo: str, ref: str, exclude: set[str]) -> tuple[set[str], bool]:
    """repo-wide framework import(정적 + 동적)를 **AST 로 정밀** 탐지(exclude 제외). (found, incomplete) 반환.

    codex G2 over-flag r5 #1 / r6 #2 / r7 #1·#2: grep(ERE)으로는 (a) `obj . import_module(...)`(공백 속성
    접근) 같은 임의 객체 메서드, (b) multiline 문자열/주석 안의 줄-시작 `import fastapi` 를 정확히 거를 수
    없다. 그래서 (1) **보수적으로 넓은** 토큰 grep(`_token_candidate_ere`/`_DYN_CANDIDATE_ERE`)으로 후보
    파일을 모으고 (2) 각 후보를 AST 로 확정한다(주석/문자열 무오탐 + callee qualifier 정확 + line-continuation
    import 포착).

    **fail-closed (codex r7 #2)**: 후보 grep 의 실제 장애는 GitError 전파(→ NOT_RUN). 후보 파일(=framework
    토큰 보유)의 `git show` 실패도 GitError 전파(확인 불가를 빈 결과로 두지 않음). parse 실패는 그 후보의
    framework import 여부를 확정 못 하므로 `incomplete=True` 로 신호(호출측이 detection-incomplete→NOT_RUN)."""
    candidates: set[str] = set()
    for name in _FRAMEWORKS:
        if name in exclude:
            continue
        candidates.update(_grep_head_files(repo, _TOKEN_CANDIDATE_ERES[name], ref))
    candidates.update(_grep_head_files(repo, _DYN_CANDIDATE_ERE, ref))
    found: set[str] = set()
    incomplete = False
    for f in sorted(candidates):
        content = _git(repo, "show", f"{ref}:{f}")  # 후보 파일 read 실패 → GitError 전파(fail-closed)
        try:
            tree = ast.parse(content)
        except SyntaxError:
            incomplete = True  # 후보(framework 토큰 보유) 파일 parse 실패 → 확인 불가(detection-incomplete)
            continue
        for name in _frameworks_from_tree(tree):
            if name not in exclude:
                found.add(name)
    return found, incomplete


# --------------------------------------------------------------------------- #
# Gates
# --------------------------------------------------------------------------- #
def gate_g1(diff_scope_ok: bool) -> GateResult:
    """G1 — diff attribution: PR diff hunks 산출 성공 여부."""
    if diff_scope_ok:
        return GateResult(gate=GateId.G1, status=GateStatus.PASS)
    return GateResult(
        gate=GateId.G1, status=GateStatus.FAIL, code=GateFailureCode.G1_DIFF,
        message="PR diff scope (merge-base..head) 산출 실패",
    )


def gate_g2(
    *,
    frameworks: set[str],
    unvalidated: set[str] | None,
    target_type: TargetType,
) -> GateResult:
    """G2 — framework source model (codex Q1 F4/F6: per-framework 검증, source_count int 폐기).

    framework 미사용 → SKIPPED.
    `unvalidated` = detect 된 프레임워크 중 source model 검증 안 된 집합:
      - None → 검증 매트릭스 자체가 없음(미실행) → NOT_RUN.
      - 비어있음 → 모든 프레임워크 source model 검증됨 → PASS.
      - 비어있지 않음 → 해당 프레임워크 source model 누락(예: starlette) → SOURCE_ZERO(MODEL_MISSING).
    smoke 는 hard fail 대신 DEGRADED(계속, 신뢰불가). 그 외(PR/known_cve)는 FAIL.
    """
    if not frameworks:
        return GateResult(gate=GateId.G2, status=GateStatus.SKIPPED)

    fail_status = GateStatus.DEGRADED if target_type == TargetType.SMOKE else GateStatus.FAIL
    if unvalidated is None:
        return GateResult(
            gate=GateId.G2, status=fail_status, code=GateFailureCode.G2_SOURCE_NOT_RUN,
            message=(
                "CodeQL framework source validation was NOT RUN (validation matrix missing). "
                "Cannot trust taint results. frameworks="
                f"{sorted(frameworks)}"
            ),
        )
    if unvalidated:
        return GateResult(
            gate=GateId.G2, status=fail_status, code=GateFailureCode.G2_SOURCE_ZERO,
            message=(
                "CodeQL did not identify any remote/user-controlled source model for these "
                "frameworks (source model missing). Results are not reliable. Add or fix the "
                f"framework source model before using this target. unvalidated={sorted(unvalidated)}"
            ),
        )
    return GateResult(gate=GateId.G2, status=GateStatus.PASS)


def gate_g2_detection_incomplete(
    target_type: TargetType, reason: str = "framework detection could not complete"
) -> GateResult:
    """프레임워크 탐지 미완료 → fail-closed G2 NOT_RUN (codex Q1r3 R3-3).

    프레임워크 존재 여부를 확정 못 하면 G2 를 SKIPPED 로 두어선 안 된다(false NO_VULN 방지).
    codex Q1r7 R7-1: `reason` 으로 원인(grep 장애 vs dep 선언-미탐지)을 정직히 구분 기록."""
    fail_status = GateStatus.DEGRADED if target_type == TargetType.SMOKE else GateStatus.FAIL
    return GateResult(
        gate=GateId.G2, status=fail_status, code=GateFailureCode.G2_SOURCE_NOT_RUN,
        message=f"framework detection incomplete ({reason}) — fail-closed NOT_RUN",
    )


# 효과입증(efficacy) 타겟 — codex Q2 R2-3/R2-4: synthetic_python 은 plumbing(파이프라인 동작/회귀)
# 이고 bare-param taint 미탐지이므로 효과입증 아님. G3 efficacy pass 는 source-bearing Track A
# corpus(owasp_sourced) 또는 실제 known_cve/ghsa 케이스가 있어야 한다.
_PLUMBING_TARGETS = {"synthetic_python"}  # G3 efficacy 로 인정 안 함
_EFFICACY_TARGETS = {"owasp_sourced", "python_known_cves", "python_ghsa_patch_diffs"}


def gate_g3(eval_targets: list[str]) -> GateResult:
    """G3 — eval target: 효과입증 타겟(source-bearing owasp_sourced/known_cve) 없으면 실패.

    phoenix(smoke)·synthetic_python(plumbing) 단독은 효과입증이 아니므로 G3 FAIL."""
    targets = set(eval_targets)
    if targets & _EFFICACY_TARGETS:
        return GateResult(gate=GateId.G3, status=GateStatus.PASS)
    return GateResult(
        gate=GateId.G3, status=GateStatus.FAIL, code=GateFailureCode.G3_EVAL,
        message=("효과입증 타겟 없음 — phoenix(smoke)/synthetic_python(plumbing) 단독 금지. "
                 "source-bearing owasp_sourced 또는 python_known_cves/ghsa 케이스 필요"),
    )


def gate_g4(report_text: str) -> GateResult:
    """G4 — Track B 한정 고지: authz/IDOR 자동확정 안 함 문구가 **실제 report 에 들어갔는지** 검증.

    codex Q2 R2-6: 항상 True 를 넘기는 형식 게이트가 아니라, 생성된 report 텍스트에서
    TRACK_B_DISCLOSURE 문자열 존재를 실제로 확인한다."""
    if TRACK_B_DISCLOSURE and TRACK_B_DISCLOSURE in (report_text or ""):
        return GateResult(gate=GateId.G4, status=GateStatus.PASS)
    return GateResult(
        gate=GateId.G4, status=GateStatus.FAIL, code=GateFailureCode.G4_AUTHZ,
        message="authz/IDOR 자동확정 안 함(Track B) 고지 문구가 생성 report 에 없음",
    )
