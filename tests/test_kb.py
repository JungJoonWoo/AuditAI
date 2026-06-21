"""Security KB seed 로드 + 교차참조 검증."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from auditai.contracts import EngineMappings
from auditai.kb import load_kb


def test_seed_loads_and_cross_refs():
    kb = load_kb()  # 내부 검증(validate_cross_refs) 포함; dangling 있으면 예외
    assert kb.capabilities
    assert kb.sinks
    assert kb.sources
    assert kb.sanitizers


def test_sink_capabilities_resolve():
    kb = load_kb()
    for sink in kb.sinks.values():
        assert sink.capability_id in kb.capabilities
        if sink.api_signature_id:
            assert sink.api_signature_id in kb.api_signatures


def test_required_meta_present():
    kb = load_kb()
    for cap in kb.capabilities.values():
        assert cap.meta.owner
        assert cap.meta.test_fixture
        assert cap.meta.expected_tp_fp


def test_mvp_capability_coverage():
    kb = load_kb()
    required = {
        "command_execution",
        "code_execution",
        "sql_execution",
        "path_traversal",
        "ssrf",
        "unsafe_deserialization",
    }
    assert required <= set(kb.capabilities)


def test_sanitizer_is_candidate_not_autocut():
    """sanitizer 는 이름 기반 자동 FP 제거가 아님(candidate 표시용)."""
    kb = load_kb()
    name_heuristic = kb.sanitizers.get("validate_prefix")
    assert name_heuristic is not None
    assert name_heuristic.strength == "candidate"


def test_missing_seed_file_raises(tmp_path: Path):
    """codex Q9: 필수 seed 파일 누락은 침묵하지 않고 실패."""
    with pytest.raises(FileNotFoundError):
        load_kb(tmp_path)  # 빈 디렉터리


def test_codeql_mapping_allowlist():
    """codex Q9/A9: engine_mappings.codeql 는 허용 모델 계열만."""
    EngineMappings(codeql="sinkModel: command injection")  # ok
    EngineMappings(codeql="summaryModel: taint preserving")  # ok
    with pytest.raises(ValidationError):
        EngineMappings(codeql="randomModel: nope")


def test_kb_models_forbid_extra():
    """codex Q6: KB 모델도 잉여 필드 거부."""
    with pytest.raises(ValidationError):
        EngineMappings(codeql="sinkModel: x", bogus_field=1)


def test_kb_default_fixtures_all_exist():
    """codex Q4: 기본 seed 의 모든 test_fixture 가 실제 존재(없으면 load_kb 가 실패)."""
    load_kb()  # validate_fixtures=True 기본 — 미존재 fixture 면 FileNotFoundError


def test_kb_fixture_validation_fails_on_missing(tmp_path: Path):
    """codex Q4: test_fixture 미존재 시 검증이 조용히 통과하지 않고 실패한다."""
    from auditai.kb.loader import _validate_test_fixtures

    kb = load_kb()
    with pytest.raises(FileNotFoundError):
        _validate_test_fixtures(kb, tmp_path)  # 빈 root → 모든 fixture 미존재


def test_kb_public_load_validates_fixtures(monkeypatch, tmp_path: Path):
    """codex Q4r2: public load_kb() 경로가 fixture 검증을 실제로 실행(private helper 만이 아님)."""
    monkeypatch.setattr("auditai.kb.loader._repo_root", lambda: tmp_path)  # 빈 root
    with pytest.raises(FileNotFoundError):
        load_kb()  # validate_fixtures=True 기본 → fixture 가 빈 root 기준 미존재


def test_kb_empty_test_fixture_rejected():
    """codex Q4r2: 빈 test_fixture 는 KBMeta 단계에서 거부(min_length=1)."""
    from auditai.contracts import KBMeta

    with pytest.raises(ValidationError):
        KBMeta(owner="x", version="1", test_fixture="", expected_tp_fp="tp")


def test_kb_directory_test_fixture_rejected():
    """codex Q4r3: test_fixture 가 파일 아닌 디렉토리를 가리키면 거부(is_file)."""
    from auditai.kb.loader import _repo_root, _validate_test_fixtures

    kb = load_kb()
    item = next(iter(kb.capabilities.values()))
    object.__setattr__(item.meta, "test_fixture", "eval_targets")  # 디렉토리(파일 아님)
    with pytest.raises(FileNotFoundError):
        _validate_test_fixtures(kb, _repo_root())


# --------------------------------------------------------------------------- #
# LangGraph PoC vuln class (Check Point chain): SQLi + deserialization -> RCE
# docs/06 §2 — P0 sink 추가 (CWE-502 / CWE-89). 모든 신규 sink 가 KB 에 등록되고
# api_signature/capability/cwe/fixture 가 정합하는지 잠근다(빈 결과 오독 금지).
# --------------------------------------------------------------------------- #

# 신규 deserialization P0 sink (pickle.loads 는 기존). CWE-502 -> unsafe_deserialization.
_P0_DESERIALIZATION_SINKS = {
    "sink.pickle.load",
    "sink.ormsgpack.unpackb",
    "sink.msgpack.unpackb",
    "sink.msgpack.loads",
    "sink.marshal.loads",
    "sink.marshal.load",
    "sink.dill.loads",
    "sink.dill.load",
    "sink.jsonpickle.decode",
}

# 신규 SQL P0 sink (sqlite3/aiosqlite 명시). CWE-89 -> sql_execution.
_P0_SQL_SINKS = {
    "sink.sqlite3.cursor.execute",
    "sink.sqlite3.cursor.executescript",
    "sink.sqlite3.connection.execute",
    "sink.sqlite3.connection.executescript",
    "sink.aiosqlite.cursor.execute",
    "sink.aiosqlite.connection.execute",
}


def test_langgraph_poc_deserialization_sinks_registered():
    """CWE-502 동족 sink 가 전부 등록 + unsafe_deserialization 으로 매핑."""
    kb = load_kb()
    assert _P0_DESERIALIZATION_SINKS <= set(kb.sinks)
    for sid in _P0_DESERIALIZATION_SINKS:
        sink = kb.sinks[sid]
        assert sink.cwe == "CWE-502", sid
        assert sink.capability_id == "unsafe_deserialization", sid
        assert sink.sink_kind == "deserialization", sid
    # pickle.loads 는 이미 존재 — 회귀 방지(삭제되면 LangGraph chain head 가 빠짐)
    assert "sink.pickle.loads" in kb.sinks


def test_langgraph_poc_sql_sinks_registered():
    """CWE-89 sqlite/aiosqlite sink 가 전부 등록 + sql_execution 으로 매핑."""
    kb = load_kb()
    assert _P0_SQL_SINKS <= set(kb.sinks)
    for sid in _P0_SQL_SINKS:
        sink = kb.sinks[sid]
        assert sink.cwe == "CWE-89", sid
        assert sink.capability_id == "sql_execution", sid
        assert sink.sink_kind == "sql", sid


def test_langgraph_poc_sinks_api_sig_and_capability_resolve():
    """신규 P0 sink 의 api_signature_id/capability_id 가 dangling 아님(loader cross-ref 보강)."""
    kb = load_kb()
    for sid in _P0_DESERIALIZATION_SINKS | _P0_SQL_SINKS:
        sink = kb.sinks[sid]
        assert sink.api_signature_id, sid
        assert sink.api_signature_id in kb.api_signatures, sid
        sig = kb.api_signatures[sink.api_signature_id]
        assert sig.capability_id == sink.capability_id, sid
        assert sink.capability_id in kb.capabilities, sid


def _scan_fixture_lines_by_capability(rel: str) -> dict[str, list[int]]:
    """실 fixture 를 git-free 로 scan → capability_id → 회수된 후보 라인들(codex b819cwlvl).

    공유 `.execute(` 토큰 존재가 아니라 **scan_candidates 가 실제로 후보를 회수**하는지로 검증.
    토큰 환상(decorated KB, 미회수)을 차단한다."""
    import ast as _ast

    from auditai.candidates import scan_candidates
    from auditai.contracts import AILineAttribution, AttributionState
    from auditai.scope import AddedLineAttribution, DiffLine, DiffScope, FileDiff

    repo_root = Path(__file__).resolve().parent.parent
    src = (repo_root / rel).read_text(encoding="utf-8")
    _ast.parse(src)  # 유효 Python
    lines = src.splitlines()
    fd = FileDiff(file="m.py", added_lines=[
        DiffLine(change="added", new_lineno=i + 1, text=l) for i, l in enumerate(lines)])
    scope = DiffScope(repo="r", base_sha="b", head_sha="h", merge_base="mb",
                      pr_commit_count=1, files=[fd])
    # _git 우회: m.py 내용을 그대로 반환(테스트 격리)
    import auditai.candidates as _C
    orig = _C._git
    _C._git = lambda repo, *a, **k: src
    try:
        ai = set(range(1, len(lines) + 1))
        attribs = [AILineAttribution(file="m.py", line_range=(ln, ln), commit="h",
                                     attribution_state=AttributionState.CONFIRMED_AI,
                                     ai_confidence=0.95, label_source="blame") for ln in ai]
        added = AddedLineAttribution(ai_lines={"m.py": ai}, attributions=attribs, completed=True)
        scan = scan_candidates("r", scope, added, load_kb())
    finally:
        _C._git = orig
    out: dict[str, list[int]] = {}
    for c in scan.candidates:
        out.setdefault(c.capability_id, []).append(c.sink_span.start_line)
    return out


def test_langgraph_poc_sink_fixtures_recovered_by_scanner():
    """codex b819cwlvl(토큰 환상 대체): 신규 P0 sink 가 fixture 에서 **실제 scan 으로 회수**된다.

    이전엔 `.execute(` 토큰 존재만 확인해 specific sink 가 실제 회수 안 돼도 통과(KB 장식).
    이제 scan_candidates() 결과로 capability/라인 회수를 직접 잠근다(빈 결과 오독 금지)."""
    # --- deserialization fixture: 위험 11 sink 각 1회, safe_load(line 6) 미회수 ---
    deser = _scan_fixture_lines_by_capability(
        "eval_targets/synthetic_python/unsafe_deserialization.py")
    deser_lines = sorted(deser.get("unsafe_deserialization", []))
    # line 4,5,7..15 = 위험(11). line 6 = yaml.safe_load(TN).
    assert deser_lines == [4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15], deser_lines
    assert 6 not in deser_lines  # NEGATIVE: safe_load 미회수
    assert len(deser_lines) == len(set(deser_lines))  # call span 중복 분열 없음

    # --- sqlite fixture: 6 위험 span(execute/executescript) 각 1회, parameterized(line 16) 미회수 ---
    sql = _scan_fixture_lines_by_capability(
        "eval_targets/synthetic_python/sqlite_injection.py")
    sql_lines = sorted(sql.get("sql_execution", []))
    assert sql_lines == [4, 6, 8, 10, 12, 14], sql_lines  # span 당 정확히 1(5중복 인플레 차단)
    assert 16 not in sql_lines  # NEGATIVE: parameterized query 미회수
    assert len(sql_lines) == len(set(sql_lines))


def test_langgraph_poc_executescript_recovered_once():
    """executescript sink(cursor/connection)이 scan 으로 각각 정확히 1번 회수(duck allowlist 누락 회귀 차단)."""
    from auditai.candidates import scan_candidates
    from auditai.contracts import AILineAttribution, AttributionState
    from auditai.scope import AddedLineAttribution, DiffLine, DiffScope, FileDiff

    repo_root = Path(__file__).resolve().parent.parent
    rel = "eval_targets/synthetic_python/sqlite_injection.py"
    src = (repo_root / rel).read_text(encoding="utf-8")
    lines = src.splitlines()
    fd = FileDiff(file="m.py", added_lines=[
        DiffLine(change="added", new_lineno=i + 1, text=l) for i, l in enumerate(lines)])
    scope = DiffScope(repo="r", base_sha="b", head_sha="h", merge_base="mb",
                      pr_commit_count=1, files=[fd])
    import auditai.candidates as _C
    orig = _C._git
    _C._git = lambda repo, *a, **k: src
    try:
        ai = set(range(1, len(lines) + 1))
        attribs = [AILineAttribution(file="m.py", line_range=(ln, ln), commit="h",
                                     attribution_state=AttributionState.CONFIRMED_AI,
                                     ai_confidence=0.95, label_source="blame") for ln in ai]
        added = AddedLineAttribution(ai_lines={"m.py": ai}, attributions=attribs, completed=True)
        scan = scan_candidates("r", scope, added, load_kb())
    finally:
        _C._git = orig
    script = [c for c in scan.candidates if "executescript" in c.sink_spec_id]
    assert {c.sink_span.start_line for c in script} == {6, 10}  # cursor/conn executescript
    assert len(script) == 2  # 각 span 1개(중복 아님)


def test_langgraph_poc_fixtures_parse_as_python():
    """신규 fixture 는 유효 Python(S1 AST 스캐너가 ast.parse 가능해야 후보 탐지)."""
    import ast

    repo_root = Path(__file__).resolve().parent.parent
    for rel in (
        "eval_targets/synthetic_python/unsafe_deserialization.py",
        "eval_targets/synthetic_python/sqlite_injection.py",
    ):
        src = (repo_root / rel).read_text(encoding="utf-8")
        ast.parse(src)  # SyntaxError 면 실패
