"""S1 known-KB AST seed scanner (candidates.py) 테스트."""

from __future__ import annotations

import ast
from pathlib import Path

from auditai.candidates import (
    _conditions_met,
    _dotted_name,
    _is_dynamic_string,
    scan_candidates,
)
from auditai.contracts import AttributionState, CandidateType
from auditai.kb import load_kb
from auditai.scope import AddedLineAttribution, attribute_added_lines, build_diff_scope


def _scan(repo: Path):
    scope = build_diff_scope(str(repo), "HEAD~1", "HEAD")
    added = attribute_added_lines(str(repo), scope)
    return scan_candidates(str(repo), scope, added, load_kb()), scope, added


# --- 헬퍼 단위 ------------------------------------------------------------- #
def test_dotted_name():
    assert _dotted_name(ast.parse("subprocess.run(x)", mode="eval").body.func) == "subprocess.run"
    assert _dotted_name(ast.parse("eval(x)", mode="eval").body.func) == "eval"
    assert _dotted_name(ast.parse("a.b.c(x)", mode="eval").body.func) == "a.b.c"
    # 호출 결과 receiver → None
    assert _dotted_name(ast.parse("f().g(x)", mode="eval").body.func) is None


def test_is_dynamic_string():
    assert _is_dynamic_string(ast.parse("f'{x}'", mode="eval").body)        # f-string
    assert _is_dynamic_string(ast.parse("'a' + x", mode="eval").body)       # concat
    assert not _is_dynamic_string(ast.parse("'literal'", mode="eval").body)


def test_conditions_met_shell_true():
    call = ast.parse("subprocess.run(c, shell=True)", mode="eval").body
    assert _conditions_met(call, [{"arg": "shell", "equals": True}], {})
    safe = ast.parse("subprocess.run(c, shell=False)", mode="eval").body
    assert not _conditions_met(safe, [{"arg": "shell", "equals": True}], {})
    nokw = ast.parse("subprocess.run(c)", mode="eval").body
    assert not _conditions_met(nokw, [{"arg": "shell", "equals": True}], {})


def test_conditions_met_dynamic_string():
    fstr = ast.parse("cur.execute(f\"SELECT {n}\")", mode="eval").body
    assert _conditions_met(fstr, [{"arg": "0", "dynamic_string": True}], {})
    lit = ast.parse("cur.execute('SELECT 1')", mode="eval").body
    assert not _conditions_met(lit, [{"arg": "0", "dynamic_string": True}], {})


# --- 통합 (실 fixture) ----------------------------------------------------- #
def test_scan_subprocess_shell_taint(fastapi_pr_repo: Path):
    """fastapi_pr_repo: route param 으로 흐르는 subprocess.run(shell=True) → TAINT_PATH 후보."""
    scan, _, _ = _scan(fastapi_pr_repo)
    caps = {c.capability_id for c in scan.candidates}
    assert "command_execution" in caps
    # route handler(param 있음) → source_nearby → taint_path
    assert any(c.candidate_type == CandidateType.TAINT_PATH and c.source_nearby
               for c in scan.taint_candidates)
    assert any(c.sink_spec_id == "sink.subprocess.shell" for c in scan.candidates)


def test_scan_owasp_multiple_sinks(owasp_efficacy_repo: Path):
    """owasp_efficacy_repo: 6개 OWASP 핸들러의 KB sink 들을 후보로 잡는다(대략적 탐지)."""
    scan, _, _ = _scan(owasp_efficacy_repo)
    caps = {c.capability_id for c in scan.candidates}
    # 최소 command/code 실행은 KB 에 있고 fixture 에 존재
    assert "command_execution" in caps
    assert "code_execution" in caps
    assert len(scan.candidates) >= 2


def test_scan_unknown_attributed_sink_is_inventory(fastapi_pr_repo: Path):
    """sink 라인이 UNKNOWN 귀속이면 candidate(taint) 아니라 candidate_inventory + unknown count(C2 fail-closed)."""
    scope = build_diff_scope(str(fastapi_pr_repo), "HEAD~1", "HEAD")
    real = attribute_added_lines(str(fastapi_pr_repo), scope)
    # 모든 ai 라인을 UNKNOWN 으로 강제(귀속 불확실 시나리오)
    forced = AddedLineAttribution(
        ai_lines={}, unknown_lines={f: set(l) for f, l in real.ai_lines.items()},
        human_lines={}, attributions=[], completed=False,
    )
    scan = scan_candidates(str(fastapi_pr_repo), scope, forced, load_kb())
    assert scan.unknown_sink_candidate_count >= 1
    assert scan.candidate_inventory
    assert not scan.taint_candidates  # UNKNOWN 은 taint 후보로 안 감
    assert all(i.ai_attribution_state == AttributionState.UNKNOWN_DUE_TO_HISTORY_LOSS
               for i in scan.candidate_inventory)


def test_scan_skips_human_lines(fastapi_pr_repo: Path):
    """sink 라인이 ai/unknown 어디에도 없으면(human/미변경) 후보 아님."""
    scope = build_diff_scope(str(fastapi_pr_repo), "HEAD~1", "HEAD")
    empty = AddedLineAttribution(completed=True)  # ai/unknown 비어있음
    scan = scan_candidates(str(fastapi_pr_repo), scope, empty, load_kb())
    assert not scan.candidates and not scan.candidate_inventory
    assert scan.unknown_sink_candidate_count == 0


# --- edge negative/positive (codex S1 QA) — git-free 합성 소스 ---------------- #
def _scan_src(monkeypatch, src: str, ai_lines: set[int] | None = None,
              unknown_lines: set[int] | None = None, commit="h", conf=0.95):
    from auditai.contracts import AILineAttribution
    from auditai.scope import AddedLineAttribution, DiffLine, DiffScope, FileDiff

    lines = src.splitlines()
    fd = FileDiff(file="m.py", added_lines=[
        DiffLine(change="added", new_lineno=i + 1, text=l) for i, l in enumerate(lines)])
    scope = DiffScope(repo="r", base_sha="b", head_sha="h", merge_base="mb", pr_commit_count=1, files=[fd])
    monkeypatch.setattr("auditai.candidates._git", lambda repo, *a, **k: src)
    ai = ai_lines if ai_lines is not None else set(range(1, len(lines) + 1))
    unk = unknown_lines or set()
    attribs = [AILineAttribution(file="m.py", line_range=(ln, ln), commit=commit,
                                 attribution_state=AttributionState.CONFIRMED_AI,
                                 ai_confidence=conf, label_source="blame") for ln in ai]
    added = AddedLineAttribution(ai_lines={"m.py": ai} if ai else {},
                                 unknown_lines={"m.py": unk} if unk else {},
                                 attributions=attribs, completed=True)
    return scan_candidates("r", scope, added, load_kb())


def test_edge_import_from_alias(monkeypatch):
    """`from subprocess import run; run(c, shell=True)` → alias 정규화로 sink 탐지(FN 차단)."""
    src = ("from subprocess import run\n"
           "@app.get('/x')\n"
           "def h(c):\n"
           "    return run(c, shell=True)\n")
    scan = _scan_src(monkeypatch, src)
    assert any(c.sink_spec_id == "sink.subprocess.shell" for c in scan.candidates)


def test_edge_dict_get_no_fp(monkeypatch):
    """`d.get(x)`(변수 receiver, 조건없는 method)는 SSRF 후보로 잡히면 안 됨(.get FP 차단)."""
    src = ("def h(d, x):\n    return d.get(x)\n")
    scan = _scan_src(monkeypatch, src)
    assert not scan.candidates and not scan.candidate_inventory


def test_edge_json_load_not_yaml_fp(monkeypatch):
    """`import json; json.load(f)` 는 yaml.load(CWE-502)로 오매칭되면 안 됨(import 된 모듈 receiver)."""
    src = ("import json\ndef h(f):\n    return json.load(f)\n")
    scan = _scan_src(monkeypatch, src)
    assert not any(c.capability_id == "unsafe_deserialization" for c in scan.candidates)


def test_edge_yaml_load_unsafe_vs_safe(monkeypatch):
    """absent_or_unsafe: yaml.load(blob) → 위험(탐지), yaml.load(blob, Loader=yaml.SafeLoader) → 안전(미탐지)."""
    unsafe = ("import yaml\n@app.get('/x')\ndef h(blob):\n    return yaml.load(blob)\n")
    assert any(c.sink_spec_id == "sink.yaml.load" for c in _scan_src(monkeypatch, unsafe).candidates)
    safe = ("import yaml\n@app.get('/x')\ndef h(blob):\n    return yaml.load(blob, Loader=yaml.SafeLoader)\n")
    assert not any(c.sink_spec_id == "sink.yaml.load" for c in _scan_src(monkeypatch, safe).candidates)


def test_edge_multiline_dangerous_arg(monkeypatch):
    """멀티라인 call 에서 AI 가 shell=True 줄만 추가해도(call 시작 줄이 AI 아님) 탐지(라인범위 교차)."""
    src = ("import subprocess\n"
           "@app.get('/x')\n"
           "def h(cmd):\n"
           "    subprocess.run(\n"
           "        cmd,\n"
           "        shell=True,\n"
           "    )\n")
    # call 은 4~7행. AI 는 shell=True(6행)만.
    scan = _scan_src(monkeypatch, src, ai_lines={6})
    assert any(c.sink_spec_id == "sink.subprocess.shell" for c in scan.candidates)


def test_edge_same_line_duplicate_sinks(monkeypatch):
    """같은 줄 2개 sink 는 col 로 구분해 둘 다 후보(undercount 금지)."""
    src = ("import os\n@app.get('/x')\ndef h(a, b):\n    os.system(a); os.system(b)\n")
    scan = _scan_src(monkeypatch, src)
    sysc = [c for c in scan.candidates if c.sink_spec_id == "sink.os.system"]
    assert len(sysc) == 2


def test_edge_attribution_refs_preserve_origin(monkeypatch):
    """ai_attribution_refs 는 원본 blame commit/confidence 를 보존(0.9 로 덮지 않음)."""
    src = ("import os\n@app.get('/x')\ndef h(a):\n    os.system(a)\n")
    scan = _scan_src(monkeypatch, src, commit="abc123", conf=0.77)
    cand = next(c for c in scan.candidates if c.sink_spec_id == "sink.os.system")
    assert cand.ai_attribution_refs
    assert cand.ai_attribution_refs[0].commit == "abc123"
    assert cand.ai_attribution_refs[0].ai_confidence == 0.77


def test_edge_non_route_sink_is_static_not_taint(monkeypatch):
    """route 데코/Request 없는 일반 함수의 sink 는 TAINT_PATH 과대분류 금지 → STATIC_PATTERN_RISK."""
    src = ("import os\ndef helper(a):\n    os.system(a)\n")
    scan = _scan_src(monkeypatch, src)
    assert not scan.taint_candidates
    assert any(c.candidate_type == CandidateType.STATIC_PATTERN_RISK for c in scan.candidates)


# --- codex S1 r2 추가 정밀화 ----------------------------------------------- #
def test_edge_obj_run_no_duck_fp(monkeypatch):
    """`obj.run(cmd, shell=True)` (generic verb, 변수 receiver)는 subprocess 로 duck-match 금지."""
    src = ("@app.get('/x')\ndef h(obj, cmd):\n    return obj.run(cmd, shell=True)\n")
    scan = _scan_src(monkeypatch, src)
    assert not any(c.sink_spec_id == "sink.subprocess.shell" for c in scan.candidates)


def test_edge_cursor_chain_execute(monkeypatch):
    """`conn.cursor().execute(f\"...\")` (call receiver) 도 cursor.execute sink 로 잡는다(FN 차단)."""
    src = ("@app.get('/x')\ndef h(conn, n):\n    return conn.cursor().execute(f\"SELECT {n}\")\n")
    scan = _scan_src(monkeypatch, src)
    assert any(c.sink_spec_id == "sink.cursor.execute" for c in scan.candidates)


def test_edge_yaml_safe_positional(monkeypatch):
    """yaml.load(blob, yaml.SafeLoader) (positional Loader) → 안전(미탐지)."""
    src = ("import yaml\n@app.get('/x')\ndef h(blob):\n    return yaml.load(blob, yaml.SafeLoader)\n")
    assert not any(c.sink_spec_id == "sink.yaml.load" for c in _scan_src(monkeypatch, src).candidates)


def test_edge_yaml_name_loader_kept_candidate(monkeypatch):
    """codex S1 r4(recall-first): bare Name Loader(alias)는 출처 단정 불가 → safe 로 안 보고 후보 유지.
    안전성 확정은 S3. (직접 yaml.SafeLoader Attribute 만 drop)."""
    src = ("import yaml\nfrom yaml import SafeLoader as SL\n@app.get('/x')\n"
           "def h(blob):\n    return yaml.load(blob, Loader=SL)\n")
    assert any(c.sink_spec_id == "sink.yaml.load" for c in _scan_src(monkeypatch, src).candidates)


def test_edge_yaml_bare_unknown_loader_is_unsafe(monkeypatch):
    """출처 불명 bare SafeLoader(로컬 정의 등)는 fail-closed(unsafe → 탐지)."""
    src = ("import yaml\n@app.get('/x')\ndef h(blob):\n    return yaml.load(blob, Loader=SafeLoader)\n")
    assert any(c.sink_spec_id == "sink.yaml.load" for c in _scan_src(monkeypatch, src).candidates)


def test_edge_format_literal_only_not_dynamic(monkeypatch):
    """cur.execute('SELECT {}'.format('1')) — literal-only format 은 동적 아님(FP 차단)."""
    src = ("@app.get('/x')\ndef h(cur):\n    return cur.execute('SELECT {}'.format('1'))\n")
    assert not any(c.sink_spec_id == "sink.cursor.execute" for c in _scan_src(monkeypatch, src).candidates)


def test_edge_import_shadowing_recall_first(monkeypatch):
    """codex S1 r4(recall-first): scope/shadowing 미추적 → import alias 유지(매칭). 재바인딩 FP 는 S2
    CodeQL evidence 가 거른다(제거하면 reverse-order FN → recall 우선). 한계는 fn_note."""
    src = ("from subprocess import run\nrun = lambda *a, **k: None\n"
           "@app.get('/x')\ndef h(c):\n    return run(c, shell=True)\n")
    scan = _scan_src(monkeypatch, src)
    assert any(c.sink_spec_id == "sink.subprocess.shell" for c in scan.candidates)


def test_edge_multiline_anchor_is_ai_line(monkeypatch):
    """멀티라인 call 에서 후보 표시 라인(sink_loc)은 첫 AI 교차 라인(human call-start 아님)."""
    src = ("import subprocess\n@app.get('/x')\ndef h(cmd):\n    subprocess.run(\n        cmd,\n        shell=True,\n    )\n")
    scan = _scan_src(monkeypatch, src, ai_lines={6})  # shell=True 만 AI(6행)
    cand = next(c for c in scan.candidates if c.sink_spec_id == "sink.subprocess.shell")
    assert cand.sink_loc.endswith(":6")  # anchor = 6행
    assert cand.sink_span.start_line == 4  # span 은 call 전체 시작


# --- codex S1 r3 추가 --------------------------------------------------------- #
def test_edge_yaml_local_rebind_loader_is_unsafe(monkeypatch):
    """from yaml import SafeLoader as SL; 함수 안 SL=yaml.Loader 재바인딩 → unsafe(fail-closed, 탐지)."""
    src = ("import yaml\nfrom yaml import SafeLoader as SL\n@app.get('/x')\n"
           "def h(blob):\n    SL = yaml.Loader\n    return yaml.load(blob, Loader=SL)\n")
    assert any(c.sink_spec_id == "sink.yaml.load" for c in _scan_src(monkeypatch, src).candidates)


def test_edge_yaml_direct_submodule_attr_safe(monkeypatch):
    """직접 Attribute yaml.loader.SafeLoader 는 canonical safe → drop(미탐지)."""
    src = ("import yaml.loader\n@app.get('/x')\n"
           "def h(blob):\n    return yaml.load(blob, Loader=yaml.loader.SafeLoader)\n")
    assert not any(c.sink_spec_id == "sink.yaml.load" for c in _scan_src(monkeypatch, src).candidates)


def test_edge_literal_only_fstring_not_dynamic(monkeypatch):
    """cur.execute(f\"{'SELECT 1'}\") — literal-only f-string 은 동적 아님(FP 차단)."""
    src = ("@app.get('/x')\ndef h(cur):\n    return cur.execute(f\"{'SELECT 1'}\")\n")
    assert not any(c.sink_spec_id == "sink.cursor.execute" for c in _scan_src(monkeypatch, src).candidates)


def test_edge_duck_execute_route_is_taint_candidate(monkeypatch):
    """codex S1 r4(recall-first): route 의 `.execute(f\"{x}\")` 는 taint 후보(약간 낮은 신뢰 0.4). 비-SQL
    provenance 는 S2 CodeQL evidence 가 거른다 — S1 에서 죽이지 않음(SQLi recall 보존)."""
    src = ("@app.get('/x')\ndef h(cur, x):\n    return cur.execute(f\"GO {x}\")\n")
    scan = _scan_src(monkeypatch, src)
    ex = [c for c in scan.candidates if c.sink_spec_id == "sink.cursor.execute"]
    assert ex and any(c.candidate_type == CandidateType.TAINT_PATH for c in ex)


# --- codex S1 r5 (상): 선행변수 dynamic-string 추적 (execute(Name)) -------------- #
def test_dynamic_assigned_names_unit():
    """_dynamic_assigned_names: 함수 안 동적대입 Name 들을 모은다(f-string/concat/+=/annot/튜플)."""
    from auditai.candidates import _dynamic_assigned_names

    fn = ast.parse(
        "def h(x, y):\n"
        "    a = f'sel {x}'\n"        # f-string
        "    b = 'p' + x\n"           # concat
        "    c = 'lit'\n"             # literal-only → 제외
        "    d = 'fmt %s' % x\n"      # % format
        "    e += f'{x}'\n"           # aug
        "    g: str = f'{y}'\n"       # annotated
        "    p, q = f'{x}', 'lit'\n"  # 튜플 언패킹(p 만 동적)
    ).body[0]
    got = _dynamic_assigned_names(fn)
    assert {"a", "b", "d", "e", "g", "p"} <= got
    assert "c" not in got and "q" not in got


def test_is_dynamic_string_name_with_tracking():
    """_is_dynamic_string(Name, dynamic_names): 추적 집합에 있으면 동적, 없으면 비동적(FP 차단)."""
    name = ast.parse("q", mode="eval").body
    assert _is_dynamic_string(name, frozenset({"q"}))
    assert not _is_dynamic_string(name, frozenset())
    assert not _is_dynamic_string(name)  # dynamic_names 없으면 Name 은 비동적(하위호환)


def test_edge_execute_preceding_dynamic_var_kept(monkeypatch):
    """codex S1 r5(상): `q = f\"..{x}\"; cur.execute(q)` (인자가 Name) — 선행변수 SQLi FN 차단.
    route 안이라 TAINT 후보로 유지(recall-first; 안전성은 S2/S3)."""
    src = ("@app.get('/x')\n"
           "def h(cur, x):\n"
           "    q = f\"SELECT * FROM u WHERE n='{x}'\"\n"
           "    return cur.execute(q)\n")
    scan = _scan_src(monkeypatch, src)
    ex = [c for c in scan.candidates if c.sink_spec_id == "sink.cursor.execute"]
    assert ex and any(c.candidate_type == CandidateType.TAINT_PATH for c in ex)


def test_edge_execute_preceding_concat_var_kept(monkeypatch):
    """선행변수가 concat(`q = "..." + x`)이어도 execute(q) 후보 유지(FN 차단)."""
    src = ("@app.get('/x')\n"
           "def h(cur, name):\n"
           "    q = \"SELECT * FROM u WHERE n='\" + name + \"'\"\n"
           "    return cur.execute(q)\n")
    scan = _scan_src(monkeypatch, src)
    assert any(c.sink_spec_id == "sink.cursor.execute" for c in scan.candidates)


def test_edge_execute_preceding_literal_var_not_candidate(monkeypatch):
    """선행변수가 literal-only(`q = 'SELECT 1'`)면 execute(q)는 dynamic_string 조건 불충족 → 후보 아님
    (recall-first 가 모든 Name 을 무조건 동적으로 보지는 않음 — 명백한 정적은 제외)."""
    src = ("@app.get('/x')\n"
           "def h(cur):\n"
           "    q = 'SELECT 1'\n"
           "    return cur.execute(q)\n")
    scan = _scan_src(monkeypatch, src)
    assert not any(c.sink_spec_id == "sink.cursor.execute" for c in scan.candidates)


def test_edge_execute_unrelated_var_not_candidate(monkeypatch):
    """동적대입이 **다른 이름**(p)일 때 execute(q)는 q 가 추적집합에 없어 후보 아님(이름 매칭 정확성)."""
    src = ("@app.get('/x')\n"
           "def h(cur, x):\n"
           "    p = f\"{x}\"\n"
           "    q = 'SELECT 1'\n"
           "    return cur.execute(q)\n")
    scan = _scan_src(monkeypatch, src)
    assert not any(c.sink_spec_id == "sink.cursor.execute" for c in scan.candidates)


def test_edge_execute_dynamic_var_reverse_order_kept(monkeypatch):
    """recall-first: assignment 가 call **뒤**에 와도(statement order 미추적) 후보 유지(reverse-order FN 차단)."""
    src = ("def h(cur, x):\n"
           "    cur.execute(q)\n"
           "    q = f\"SELECT {x}\"\n")
    scan = _scan_src(monkeypatch, src)
    assert any(c.sink_spec_id == "sink.cursor.execute" for c in scan.candidates)


def test_edge_sqlite_connection_execute_preceding_var_kept(monkeypatch):
    """확장 KB sink(sqlite3 connection.execute)도 선행변수 dynamic-string 으로 후보 유지."""
    src = ("import sqlite3\n@app.get('/x')\n"
           "def h(conn, x):\n"
           "    q = f\"SELECT {x}\"\n"
           "    return conn.execute(q)\n")
    scan = _scan_src(monkeypatch, src)
    assert any(c.capability_id == "sql_execution" for c in scan.candidates)


# --- codex b819cwlvl: 실 fixture 회수 검증(토큰 환상 대체) -------------------------- #
# 공유 `.execute(` 토큰 존재가 아니라 scan_candidates() 가 실제로 후보를 회수하는지,
# 한 call span 이 중복 안 되는지, safe TN span 이 후보에서 빠지는지를 잠근다.
def _scan_fixture(monkeypatch, rel: str):
    """실 eval_targets fixture 를 git-free 로 scan(파일 전체 added/AI 로 강제)."""
    from auditai.contracts import AILineAttribution
    from auditai.scope import AddedLineAttribution, DiffLine, DiffScope, FileDiff

    src = (Path(__file__).resolve().parent.parent / rel).read_text(encoding="utf-8")
    lines = src.splitlines()
    fd = FileDiff(file="m.py", added_lines=[
        DiffLine(change="added", new_lineno=i + 1, text=l) for i, l in enumerate(lines)])
    scope = DiffScope(repo="r", base_sha="b", head_sha="h", merge_base="mb",
                      pr_commit_count=1, files=[fd])
    monkeypatch.setattr("auditai.candidates._git", lambda repo, *a, **k: src)
    ai = set(range(1, len(lines) + 1))
    attribs = [AILineAttribution(file="m.py", line_range=(ln, ln), commit="h",
                                 attribution_state=AttributionState.CONFIRMED_AI,
                                 ai_confidence=0.95, label_source="blame") for ln in ai]
    added = AddedLineAttribution(ai_lines={"m.py": ai}, attributions=attribs, completed=True)
    return scan_candidates("r", scope, added, load_kb()), src


def _spans(cands):
    return [(c.sink_span.start_line, c.sink_span.start_col,
             c.sink_span.end_line, c.sink_span.end_col) for c in cands]


def test_fixture_sqlite_injection_recovery(monkeypatch):
    """sqlite_injection.py: 6개 위험 call span 각각 후보 1개(중복 0), safe parameterized 는 후보 아님."""
    scan, _ = _scan_fixture(monkeypatch, "eval_targets/synthetic_python/sqlite_injection.py")
    # 6개 동적 execute/executescript call span(line 4,6,8,10,12,14). line 16 은 parameterized(TN).
    danger_lines = {4, 6, 8, 10, 12, 14}
    cand_lines = sorted(c.sink_span.start_line for c in scan.candidates)
    assert cand_lines == sorted(danger_lines), cand_lines
    assert len(scan.candidates) == 6  # 한 call span = 후보 1개(dedup; 5중복 인플레이션 차단)
    # 한 call span 이 절대 2개 이상으로 분열되지 않음(span 유일성)
    assert len(_spans(scan.candidates)) == len(set(_spans(scan.candidates)))
    # 전부 sql_execution / CWE-89
    assert all(c.capability_id == "sql_execution" for c in scan.candidates)
    # NEGATIVE: parameterized safe query(line 16) span 은 후보/인벤토리에 없음
    assert 16 not in cand_lines
    assert 16 not in {i.line for i in scan.candidate_inventory}


def test_fixture_executescript_each_recovered_once(monkeypatch):
    """executescript sink(cursor/connection, line 6·10)이 각각 정확히 1번 회수(KB 장식 아님)."""
    scan, _ = _scan_fixture(monkeypatch, "eval_targets/synthetic_python/sqlite_injection.py")
    script_cands = [c for c in scan.candidates if "executescript" in c.sink_spec_id]
    # line 6(cursor.executescript), line 10(connection.executescript) → 각 1개
    assert {c.sink_span.start_line for c in script_cands} == {6, 10}
    assert len(script_cands) == 2  # 각 span 1개(중복 아님)


def test_fixture_unsafe_deserialization_recovery(monkeypatch):
    """unsafe_deserialization.py: 위험 sink 각각 후보 1개, yaml.safe_load(line 6)는 후보 아님(TN)."""
    scan, _ = _scan_fixture(monkeypatch, "eval_targets/synthetic_python/unsafe_deserialization.py")
    by_sink = {}
    for c in scan.candidates:
        by_sink.setdefault(c.sink_spec_id, []).append(c)
    # 각 위험 sink 정확히 1회 회수(per-sink-id 기대 수)
    expected_once = {
        "sink.pickle.loads", "sink.yaml.load", "sink.pickle.load",
        "sink.ormsgpack.unpackb", "sink.msgpack.unpackb", "sink.msgpack.loads",
        "sink.marshal.loads", "sink.marshal.load", "sink.dill.loads",
        "sink.dill.load", "sink.jsonpickle.decode",
    }
    for sid in expected_once:
        assert len(by_sink.get(sid, [])) == 1, (sid, by_sink.get(sid))
    assert len(scan.candidates) == len(expected_once)  # 한 call span = 후보 1
    # 한 call span 분열 없음
    assert len(_spans(scan.candidates)) == len(set(_spans(scan.candidates)))
    # NEGATIVE: yaml.safe_load(line 6) span 은 후보/인벤토리에 없음
    cand_lines = {c.sink_span.start_line for c in scan.candidates}
    assert 6 not in cand_lines
    assert 6 not in {i.line for i in scan.candidate_inventory}


def test_fixture_no_double_candidate_single_span(monkeypatch):
    """codex b819cwlvl 핵심: 한 `conn.execute(...)` call span 이 generic dbapi + sqlite3 + aiosqlite
    여러 sink 로 분열돼 다중 후보가 되면 안 된다(span 당 정확히 1 후보)."""
    src = ("import sqlite3\n@app.get('/x')\n"
           "def h(conn, x):\n"
           "    return conn.execute(f\"SELECT {x}\")\n")
    scan = _scan_src(monkeypatch, src)
    execs = [c for c in scan.candidates if c.capability_id == "sql_execution"]
    assert len(execs) == 1, [c.sink_spec_id for c in execs]  # 1개(5중복 아님)
    # duck-typed(receiver 변수) → 라이브러리 단정 불가 → generic dbapi 대표
    assert execs[0].sink_spec_id == "sink.cursor.execute"
