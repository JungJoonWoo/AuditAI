"""Gates G1~G4 + framework 탐지 테스트."""

from __future__ import annotations

from pathlib import Path

from auditai.contracts import GateFailureCode, GateId, GateStatus, TargetType
from auditai.gates import (
    detect_framework_scope,
    detect_frameworks,
    gate_g1,
    gate_g2,
    gate_g3,
    gate_g4,
)
from auditai.scope import build_diff_scope


def test_g1():
    assert gate_g1(True).status == GateStatus.PASS
    g = gate_g1(False)
    assert g.status == GateStatus.FAIL and g.code == GateFailureCode.G1_DIFF


def test_g2_no_framework_skipped():
    g = gate_g2(frameworks=set(), unvalidated=None, target_type=TargetType.SYNTHETIC)
    assert g.status == GateStatus.SKIPPED


def test_g2_framework_not_run_hard_fail():
    # 매트릭스 없음(unvalidated=None) → 검증 미실행
    g = gate_g2(frameworks={"fastapi"}, unvalidated=None, target_type=TargetType.KNOWN_CVE)
    assert g.status == GateStatus.FAIL and g.code == GateFailureCode.G2_SOURCE_NOT_RUN
    assert "NOT RUN" in g.message


def test_g2_framework_not_run_smoke_degraded():
    g = gate_g2(frameworks={"strawberry"}, unvalidated=None, target_type=TargetType.SMOKE)
    assert g.status == GateStatus.DEGRADED


def test_g2_source_model_missing():
    # starlette source model 미검증 → unvalidated 비어있지 않음 → MODEL_MISSING
    g = gate_g2(frameworks={"fastapi", "starlette"}, unvalidated={"starlette"},
                target_type=TargetType.KNOWN_CVE)
    assert g.status == GateStatus.FAIL and g.code == GateFailureCode.G2_SOURCE_ZERO
    assert "starlette" in g.message


def test_g2_pass():
    # 모든 detect 프레임워크 검증됨(unvalidated 빈 집합) → PASS
    g = gate_g2(frameworks={"fastapi"}, unvalidated=set(), target_type=TargetType.KNOWN_CVE)
    assert g.status == GateStatus.PASS


def test_g3():
    # codex Q2 R2-3: efficacy 타겟(owasp_sourced/known_cve)만 PASS. synthetic_python=plumbing → FAIL.
    assert gate_g3(["owasp_sourced"]).status == GateStatus.PASS
    assert gate_g3(["python_known_cves"]).status == GateStatus.PASS
    for plumbing in (["synthetic_python"], ["phoenix_smoke"], ["synthetic_python", "phoenix_smoke"]):
        g = gate_g3(plumbing)
        assert g.status == GateStatus.FAIL and g.code == GateFailureCode.G3_EVAL, plumbing


def test_g4():
    # codex Q2 R2-6: gate_g4 는 실제 report 텍스트에서 고지 문구 존재를 검증.
    from auditai.contracts import TRACK_B_DISCLOSURE

    assert gate_g4(f"...\n> {TRACK_B_DISCLOSURE}\n...").status == GateStatus.PASS
    assert gate_g4("report without the disclosure line").status == GateStatus.FAIL
    assert gate_g4("").status == GateStatus.FAIL


def test_detect_frameworks_none(diff_repo: Path):
    # diff_repo 는 framework import 없음
    scope = build_diff_scope(str(diff_repo), "HEAD~1", "HEAD")
    assert detect_frameworks(str(diff_repo), scope) == set()


def test_import_pattern_boundaries():
    """codex Q1r4 R4-4: import 탐지 패턴이 다중 import/서브모듈을 잡고 prefix 를 배제."""
    from auditai.gates import _FRAMEWORK_MARKERS

    fa = _FRAMEWORK_MARKERS["fastapi"]
    for hit in ("from fastapi import FastAPI", "import fastapi", "import os, fastapi",
                "import fastapi as fa", "import fastapi.routing",
                "from fastapi.security import X", "    from fastapi import Y"):
        assert fa.search(hit), f"should match: {hit!r}"
    for nospace in ("import os,fastapi", "import os ,fastapi"):  # codex Q1r5 R5-2 (공백없는 콤마)
        assert fa.search(nospace), f"should match: {nospace!r}"
    for miss in ("import fastapix", "from fastapilib import z", "import myfastapi",
                 "import os,fastapilib",  # prefix 오탐 배제(공백없는 콤마)
                 "# from fastapi import x", "x = 'from fastapi import'"):
        assert not fa.search(miss), f"should NOT match: {miss!r}"


def test_dynamic_import_pattern():
    """codex Q1r5 R5-1: importlib.import_module / __import__ 문자열 리터럴 탐지.
    codex G2 over-flag r2 #2: keyword 리터럴(`import_module(name="fastapi")`)도 잡음(repo-wide 일치)."""
    from auditai.gates import _DYN_MARKERS

    fa = _DYN_MARKERS["fastapi"]
    for hit in ('importlib.import_module("fastapi")', "import_module('fastapi')",
                '__import__("fastapi")', 'importlib.import_module("fastapi.routing")',
                'importlib.import_module(name="fastapi")', "import_module(name='fastapi')",
                # codex G2 over-flag r4 #1: 함수명-`(` 사이 공백도 유효한 Python 호출
                'importlib.import_module ("fastapi")', 'import_module ("fastapi")',
                '__import__ ("fastapi")'):
        assert fa.search(hit), f"should match: {hit!r}"
    for miss in ('import_module("fastapix")', 'x = "fastapi"',
                 # codex G2 over-flag r3 #2: 함수명 경계 — 부분문자열/메서드 오탐 차단
                 'not_import_module("fastapi")', 'my__import__("fastapi")',
                 'obj.import_module("fastapi")', 'self.import_module("fastapi")'):
        assert not fa.search(miss), f"should NOT match: {miss!r}"


def test_scan_changed_file_dynamic_import_target_only():
    """codex G2 over-flag r2 #1: 동적 import 의 '대상 인자'(첫 positional/`name=`)만 불확실성 판정.

    보조 인자(globals/locals/fromlist/package)가 비-리터럴이어도 대상이 리터럴이면 uncertain=False
    (정상 호출이 over-flag 를 켜지 않게). 대상이 변수/표현식/`**kwargs`/누락이면 uncertain=True."""
    from auditai.gates import _scan_changed_file

    # 대상 리터럴 + 보조 인자 비-리터럴 → 탐지됨 & 불확실 아님(over-flag 방지)
    for ok in (
        'import importlib\nx = importlib.import_module("fastapi", __package__)\n',
        'm = __import__("fastapi", globals(), locals(), ["FastAPI"])\n',
        'import importlib\nx = importlib.import_module(name="fastapi")\n',
    ):
        fw, uncertain = _scan_changed_file(ok)
        assert fw == {"fastapi"}, ok
        assert uncertain is False, ok
    # 대상이 변수/표현식/**kwargs/누락 → 불확실(보강 트리거)
    for bad in (
        'import importlib\nmod = "x"\nimportlib.import_module(mod)\n',
        'import importlib\nimportlib.import_module("fa" + "stapi")\n',
        'import importlib\nimportlib.import_module(**opts)\n',
    ):
        _, uncertain = _scan_changed_file(bad)
        assert uncertain is True, bad
    # parse 실패 → 불확실(보강 트리거)
    _, uncertain = _scan_changed_file("def f(:\n  pass\n")
    assert uncertain is True


def test_scan_changed_file_dynamic_import_callee_qualifier():
    """codex G2 over-flag r3 #1: 임의 객체 메서드(`obj.import_module(...)`)는 importlib 가 아니므로
    framework 탐지·불확실성 판정에서 제외(이름만 같을 뿐). importlib.import_module / bare import_module /
    builtin __import__ 만 인정."""
    from auditai.gates import _scan_changed_file

    # obj.import_module(...) 는 importlib 아님 → 리터럴이어도 framework 탐지 안 함
    fw, uncertain = _scan_changed_file('loader.import_module("fastapi")\n')
    assert fw == set() and uncertain is False
    # obj.import_module(변수) 도 importlib 아님 → 불확실 아님(over-flag 방지)
    _, uncertain = _scan_changed_file('mod = "x"\nloader.import_module(mod)\n')
    assert uncertain is False
    # codex r5 #1: 공백 속성 접근(`obj . import_module ("x")`)도 AST 로 정확히 거름(regex 의 한계와 무관)
    fw, uncertain = _scan_changed_file('loader . import_module ("fastapi")\n')
    assert fw == set() and uncertain is False
    fw, uncertain = _scan_changed_file('mod = "x"\nloader . import_module (mod)\n')
    assert fw == set() and uncertain is False
    # importlib.import_module(변수) 는 진짜 동적 import → 불확실
    _, uncertain = _scan_changed_file('import importlib\nmod = "x"\nimportlib.import_module(mod)\n')
    assert uncertain is True
    # importlib.import_module(리터럴) → 탐지
    fw, uncertain = _scan_changed_file('import importlib\nimportlib.import_module("fastapi")\n')
    assert fw == {"fastapi"} and uncertain is False
    # 함수명-`(` 사이 공백(codex r4 #1): AST 는 공백 무관 — 리터럴 탐지/변수 불확실 동일
    fw, uncertain = _scan_changed_file('import importlib\nimportlib.import_module ("fastapi")\n')
    assert fw == {"fastapi"} and uncertain is False


def test_scan_changed_file_importlib_alias_is_out_of_scope():
    """codex G2 over-flag r4 #2 (계약 잠금): `from importlib import import_module as im; im(...)` 의
    alias 호출은 MVP 탐지 밖(README ⑥). 현재 동작이 '미탐지'임을 명시적으로 잠근다 — 향후 alias map
    구현 시 이 테스트를 갱신."""
    from auditai.gates import _scan_changed_file

    fw, uncertain = _scan_changed_file(
        "from importlib import import_module as im\nx = im('starlette')\n")
    assert fw == set()        # alias 호출은 동적 import 로 인식 안 함(미탐지)
    assert uncertain is False  # alias 는 불확실성 신호로도 안 잡음(MVP 한계, 문서화됨)


def test_scope_repo_wide_dynamic_import_with_space(starlette_helper_space_dyn_repo: Path):
    """codex G2 over-flag r4 #1: repo-wide grep 이 공백 표기 동적 import(`import_module ("starlette")`)도
    잡는다 — helper-only PR(case B)에서 미변경 파일의 공백 동적 import 누락 방지(under-detection)."""
    repo = str(starlette_helper_space_dyn_repo)
    scope = build_diff_scope(repo, "HEAD~1", "HEAD")
    fs = detect_framework_scope(repo, scope)
    assert fs.has_frameworkless_changed_py is True
    assert "starlette" in fs.repo_wide


def test_scope_repo_wide_spaced_method_not_over_flagged(helper_only_spaced_method_repo: Path):
    """codex G2 over-flag r5 #1 (over-detection negative): 미변경 파일의 `obj . import_module("fastapi")`
    (importlib 아닌 임의 객체 메서드, 공백 속성 접근)는 repo-wide AST 스캔이 callee qualifier 로 거른다 →
    repo_wide 에 fastapi 가 들어가면 안 된다(over-flag 방지)."""
    repo = str(helper_only_spaced_method_repo)
    scope = build_diff_scope(repo, "HEAD~1", "HEAD")
    fs = detect_framework_scope(repo, scope)
    assert fs.has_frameworkless_changed_py is True  # repo-wide 보강은 켜지지만
    assert "fastapi" not in fs.repo_wide            # 임의 객체 메서드는 안 잡힘


def test_scope_repo_wide_string_import_not_over_flagged(helper_only_string_import_repo: Path):
    """codex G2 over-flag r6 #2 (over-detection negative): 미변경 파일의 multiline 문자열 안 줄-시작
    `import fastapi` 는 실제 import 가 아니다 — repo-wide AST 확정이 문자열/주석을 무오탐으로 거른다 →
    repo_wide 에 fastapi 가 들어가면 안 된다(line-anchored grep 단독이었다면 오탐했을 경로)."""
    repo = str(helper_only_string_import_repo)
    scope = build_diff_scope(repo, "HEAD~1", "HEAD")
    fs = detect_framework_scope(repo, scope)
    assert fs.has_frameworkless_changed_py is True
    assert "fastapi" not in fs.repo_wide  # 문자열 안 import 는 AST 가 안 잡음


def test_scope_repo_wide_line_continuation_import_caught(helper_only_line_continuation_repo: Path):
    """codex G2 over-flag r7 #1 (under-detection): line-continuation import(`import os, \\`↵`fastapi`)는
    line-anchored grep 으론 후보 누락되지만 토큰 grep→AST 가 잡는다 → repo_wide 에 fastapi 포함."""
    repo = str(helper_only_line_continuation_repo)
    scope = build_diff_scope(repo, "HEAD~1", "HEAD")
    fs = detect_framework_scope(repo, scope)
    assert fs.has_frameworkless_changed_py is True
    assert "fastapi" in fs.repo_wide


def test_scope_repo_wide_unparseable_candidate_is_incomplete(
    helper_only_unparseable_candidate_repo: Path,
):
    """codex G2 over-flag r7 #2 (fail-closed): framework 토큰을 가진 미변경 파일이 parse 불가 → 확인
    불가 → repo_wide_incomplete=True(조용히 skip 금지)."""
    repo = str(helper_only_unparseable_candidate_repo)
    scope = build_diff_scope(repo, "HEAD~1", "HEAD")
    fs = detect_framework_scope(repo, scope)
    assert fs.has_frameworkless_changed_py is True
    assert fs.repo_wide_incomplete is True


def test_scope_aux_nonliteral_dynamic_import_no_over_flag(
    fastapi_aux_dynamic_starlette_repo: Path,
):
    """codex G2 over-flag r2 #1/#4: 변경 파일이 `__import__("fastapi", globals(), locals(), [...])`(대상
    리터럴, 보조 인자 비-리터럴) + 미변경 starlette → uncertain=False → case A 유지(starlette 무시),
    over-flag 재발 없음."""
    repo = str(fastapi_aux_dynamic_starlette_repo)
    scope = build_diff_scope(repo, "HEAD~1", "HEAD")
    fs = detect_framework_scope(repo, scope)
    assert fs.changed == {"fastapi"}
    assert fs.uncertain_changed_py is False  # 보조 인자 비-리터럴은 불확실 아님
    assert fs.has_frameworkless_changed_py is False
    assert fs.repo_wide == set()  # case A → repo-wide 미수집 → starlette over-flag 없음


def test_detect_frameworks_repo_wide_multi_import(multi_import_repo: Path):
    """helper-only PR(변경 파일에 import 없음) + 미변경 파일의 `import os, fastapi` →
    repo-wide grep 이 fastapi 를 탐지(과소탐지 금지, R4-2)."""
    scope = build_diff_scope(str(multi_import_repo), "HEAD~1", "HEAD")
    assert "fastapi" in detect_frameworks(str(multi_import_repo), scope)


def test_detect_frameworks_dynamic_import(dynamic_import_repo: Path):
    """codex Q1r5 R5-1: importlib.import_module("fastapi") 동적 import 도 탐지."""
    scope = build_diff_scope(str(dynamic_import_repo), "HEAD~1", "HEAD")
    assert "fastapi" in detect_frameworks(str(dynamic_import_repo), scope)


# --- detect_framework_scope: G2 over-flag 판정 확정 설계(case A/B) ------------- #
def test_scope_case_a_changed_only_ignores_repo_wide(fastapi_internal_starlette_repo: Path):
    """codex G2 over-flag #1: 변경 파일이 fastapi 만 import + framework 없는 변경 .py 없음(case A)
    → changed={fastapi}, repo_wide 미수집(starlette 무시), has_frameworkless=False."""
    repo = str(fastapi_internal_starlette_repo)
    scope = build_diff_scope(repo, "HEAD~1", "HEAD")
    fs = detect_framework_scope(repo, scope)
    assert fs.changed == {"fastapi"}
    assert fs.has_frameworkless_changed_py is False
    assert fs.repo_wide == set()  # repo 내부 starlette 는 case A 에서 수집조차 안 함(over-flag 방지)


def test_scope_case_b_helper_only_collects_repo_wide(starlette_helper_only_repo: Path):
    """codex G2 over-flag #2: framework 없는 변경 .py(helper.py)만 있음(case B) → repo-wide 가
    미변경 starlette 를 수집(under-detection 방지)."""
    repo = str(starlette_helper_only_repo)
    scope = build_diff_scope(repo, "HEAD~1", "HEAD")
    fs = detect_framework_scope(repo, scope)
    assert fs.changed == set()
    assert fs.has_frameworkless_changed_py is True
    assert "starlette" in fs.repo_wide


def test_scope_case_b_mixed_pr_keeps_repo_wide(mixed_fastapi_helper_starlette_repo: Path):
    """codex G2 over-flag #3(제안 구멍): fastapi 변경 파일 + frameworkless helper 혼합 PR →
    "변경 framework 비었나"로 트리거하면 fallback 이 꺼져 starlette 누락. 올바른 트리거(framework 없는
    변경 .py 존재)면 case B 유지 → changed={fastapi} 이면서도 repo_wide 가 starlette 를 잡는다."""
    repo = str(mixed_fastapi_helper_starlette_repo)
    scope = build_diff_scope(repo, "HEAD~1", "HEAD")
    fs = detect_framework_scope(repo, scope)
    assert fs.changed == {"fastapi"}
    assert fs.has_frameworkless_changed_py is True  # helper.py 가 frameworkless
    assert "starlette" in fs.repo_wide


def test_scope_uncertain_var_dynamic_import_triggers_fallback(
    fastapi_var_dynamic_starlette_repo: Path,
):
    """codex G2 over-flag r2 #2: 변경 파일이 fastapi import + 변수 동적 import(대상 미상) →
    uncertain_changed_py=True → frameworkless 변경 .py 가 없어도 repo-wide 보강 트리거가 켜진다
    (트리거일 뿐 — NOT_RUN 은 매니페스트/정적 해소 시에만, r3 #3)."""
    repo = str(fastapi_var_dynamic_starlette_repo)
    scope = build_diff_scope(repo, "HEAD~1", "HEAD")
    fs = detect_framework_scope(repo, scope)
    assert fs.changed == {"fastapi"}
    assert fs.has_frameworkless_changed_py is False  # api.py 는 fastapi import 가 있음
    assert fs.uncertain_changed_py is True           # 변수 동적 import → 불확실
    assert fs.needs_repo_wide_fallback is True


def test_scope_literal_dynamic_import_is_not_uncertain(dynamic_import_repo: Path):
    """리터럴 동적 import(`import_module("fastapi")`)는 대상이 명확 → 불확실성 아님(over-flag 재발 방지)."""
    repo = str(dynamic_import_repo)
    scope = build_diff_scope(repo, "HEAD~1", "HEAD")
    fs = detect_framework_scope(repo, scope)
    assert fs.changed == {"fastapi"}
    assert fs.uncertain_changed_py is False  # 리터럴 인자 → 확실


def test_declared_framework_deps(declared_not_imported_repo: Path):
    """의존성 매니페스트의 framework 선언 탐지(fail-closed fallback 입력)."""
    from auditai.gates import declared_framework_deps

    scope = build_diff_scope(str(declared_not_imported_repo), "HEAD~1", "HEAD")
    assert declared_framework_deps(str(declared_not_imported_repo), scope.head_sha) == {"fastapi"}


def test_declared_framework_deps_boundaries(dep_boundary_repo: Path):
    """codex Q1r6 R6-4: fastapi-utils/starlette-x/strawberry_graphql 배제, strawberry-graphql→strawberry."""
    from auditai.gates import declared_framework_deps

    assert declared_framework_deps(str(dep_boundary_repo), "HEAD") == {"strawberry"}


def test_frameworks_in_ast_no_false_positive():
    """codex Q1r6 R6-3: AST 탐지는 주석/문자열/변수인자를 framework 사용으로 오탐하지 않음."""
    from auditai.gates import _frameworks_in_ast

    assert _frameworks_in_ast('# importlib.import_module("fastapi")') == set()
    assert _frameworks_in_ast('x = "from fastapi import X"') == set()
    assert _frameworks_in_ast('mod="fastapi"; import_module(mod)') == set()  # 변수인자 out-of-scope
    assert _frameworks_in_ast('import_module(name="fastapi")') == {"fastapi"}  # keyword 리터럴
    assert _frameworks_in_ast('from fastapi import FastAPI') == {"fastapi"}
    # codex Q1r7 R7-2: 상대 import(로컬 모듈)는 framework 아님
    assert _frameworks_in_ast('from .fastapi import local') == set()
    assert _frameworks_in_ast('from ..fastapi import local') == set()
    # codex Q1r8 R8-1: 절대 서브모듈 import 는 잡아야 함(상대와 구분)
    assert _frameworks_in_ast('from fastapi.security import X') == {"fastapi"}
    assert _frameworks_in_ast('from starlette.requests import Request') == {"starlette"}
