"""Track A CodeQL 통합 (codeql.py) 테스트.

SARIF 파서/필터는 CodeQL 없이도 테스트. run_track_a 는 CodeQL 설치 시에만(없으면 skip).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from auditai.codeql import (
    codeql_available,
    count_sarif_sources,
    default_validation_matrix,
    filter_findings_to_ai_lines,
    find_codeql,
    load_source_validation_matrix,
    parse_sarif_findings,
    parse_source_validation_matrix,
    run_track_a,
    source_validation_path,
    unvalidated_frameworks,
)

_SARIF = Path(__file__).parent / "fixtures" / "sample_codeql.sarif"
_FASTAPI = Path(__file__).parent / "framework_sources" / "fastapi_query_param"
_VALIDATION = source_validation_path()  # 패키지 동봉 런타임 리소스


def test_parse_real_sarif():
    """실제 CodeQL SARIF(fastapi command injection) 파싱."""
    sarif = json.loads(_SARIF.read_text(encoding="utf-8"))
    findings = parse_sarif_findings(sarif)
    assert findings, "최소 1개 finding"
    f = findings[0]
    assert f.file.endswith("vuln.py")
    assert f.line >= 1
    assert f.vulnerability_confirmed is False  # 사람검토 전
    assert f.cwe.startswith("CWE-")


def test_count_sources():
    sarif = json.loads(_SARIF.read_text(encoding="utf-8"))
    assert count_sarif_sources(sarif) >= 1


def test_rule_cwe_extraction():
    """_rule_cwe: SARIF tags → MITRE CWE 표기(선행 0 제거), 없으면 properties.cwe 폴백/빈값."""
    from auditai.codeql import _rule_cwe

    assert _rule_cwe({"properties": {"tags": ["external/cwe/cwe-078"]}}) == "CWE-78"
    assert _rule_cwe({"properties": {"tags": ["external/cwe/cwe-089"]}}) == "CWE-89"
    assert _rule_cwe({"properties": {"tags": ["external/cwe/cwe-1004"]}}) == "CWE-1004"
    assert _rule_cwe({"properties": {"tags": ["security", "external/cwe/cwe-022"]}}) == "CWE-22"
    assert _rule_cwe({"properties": {"tags": ["maintainability"]}}) == ""
    assert _rule_cwe({"properties": {"cwe": "CWE-99"}}) == "CWE-99"  # 폴백
    assert _rule_cwe({}) == ""


def test_severity_fallback_rule_default():
    """codex Q5-1: result.level 비면 rule.defaultConfiguration.level / problem.severity 로 fallback."""
    sarif = {"runs": [{"tool": {"driver": {"rules": [
        {"id": "r1", "defaultConfiguration": {"level": "error"}},
        {"id": "r2", "properties": {"problem.severity": "recommendation"}},
    ]}}, "results": [
        {"ruleId": "r1", "message": {"text": "m"},  # level 없음 → rule default error → high
         "locations": [{"physicalLocation": {"artifactLocation": {"uri": "a.py"},
                                             "region": {"startLine": 1}}}]},
        {"ruleId": "r2", "message": {"text": "n"},  # problem.severity recommendation → low
         "locations": [{"physicalLocation": {"artifactLocation": {"uri": "a.py"},
                                             "region": {"startLine": 2}}}]},
    ]}]}
    fs = parse_sarif_findings(sarif)
    assert fs[0].severity == "high" and fs[1].severity == "low"


def test_finding_id_unique_across_runs():
    """codex Q5-4: multi-run SARIF 에서 finding_id 가 전역 유일."""
    one = {"tool": {"driver": {"rules": []}}, "results": [
        {"ruleId": "x", "message": {"text": "m"}, "locations": [
            {"physicalLocation": {"artifactLocation": {"uri": "a.py"}, "region": {"startLine": 1}}}]}]}
    sarif = {"runs": [one, one]}  # 2 runs, 각 1 result
    ids = [f.finding_id for f in parse_sarif_findings(sarif)]
    assert len(ids) == 2 and len(set(ids)) == 2


def test_norm_only_strips_dotslash():
    """codex Q5-3: _norm 은 선행 './' 만 제거(../, /abs, .hidden 보존)."""
    from auditai.codeql import _norm

    assert _norm("./src/a.py") == "src/a.py"
    assert _norm(".\\src\\a.py") == "src/a.py"
    assert _norm("../a.py") == "../a.py"
    assert _norm("/abs/a.py") == "/abs/a.py"
    assert _norm(".hidden/a.py") == ".hidden/a.py"


def test_filter_basename_collision_no_false_match():
    """codex Q5-2: 다른 디렉토리 동일 basename → basename 폴백 금지(full-path 만)."""
    sarif = {"runs": [{"tool": {"driver": {"rules": []}}, "results": [
        {"ruleId": "x", "message": {"text": "m"}, "locations": [
            {"physicalLocation": {"artifactLocation": {"uri": "src/util.py"}, "region": {"startLine": 5}}}]}]}]}
    fs = parse_sarif_findings(sarif)
    # ai_lines 에 util.py 가 두 디렉토리 → basename 모호 → src/util.py:5 가 full-path 로만 매칭
    ai = {"test/util.py": {5}, "other/util.py": {5}}
    assert filter_findings_to_ai_lines(fs, ai) == []  # basename 폴백 금지(false match 없음)
    # 단일 디렉토리(유일 basename)면 폴백 허용
    assert filter_findings_to_ai_lines(fs, {"test/util.py": {5}})  # basename 유일 → 매칭
    # full-path 일치는 항상
    assert filter_findings_to_ai_lines(fs, {"src/util.py": {5}})


def test_filter_no_basename_fallback_for_escape_paths():
    """codex Q5r2-1/Q5r3-1: ../·POSIX/Windows absolute·URI finding 경로는 basename 폴백 금지."""
    for uri in ("../a.py", "/abs/a.py", "C:/repo/a.py", "C:\\repo\\a.py", "file:///C:/repo/a.py"):
        sarif = {"runs": [{"tool": {"driver": {"rules": []}}, "results": [
            {"ruleId": "x", "message": {"text": "m"}, "locations": [
                {"physicalLocation": {"artifactLocation": {"uri": uri}, "region": {"startLine": 5}}}]}]}]}
        fs = parse_sarif_findings(sarif)
        # basename "a.py" 가 전역 유일이어도 ../·absolute 면 매칭 안 됨
        assert filter_findings_to_ai_lines(fs, {"src/a.py": {5}}) == [], uri


def test_severity_from_level():
    sarif = {"runs": [{"tool": {"driver": {"rules": []}}, "results": [
        {"ruleId": "x", "level": "error", "message": {"text": "m"},
         "locations": [{"physicalLocation": {"artifactLocation": {"uri": "a.py"},
                                             "region": {"startLine": 3}}}]},
        {"ruleId": "y", "level": "note", "message": {"text": "n"},
         "locations": [{"physicalLocation": {"artifactLocation": {"uri": "a.py"},
                                             "region": {"startLine": 4}}}]},
    ]}]}
    fs = parse_sarif_findings(sarif)
    assert fs[0].severity == "high"  # error
    assert fs[1].severity == "low"   # note


def test_filter_path_normalization():
    sarif = {"runs": [{"tool": {"driver": {"rules": []}}, "results": [
        {"ruleId": "x", "message": {"text": "m"},
         "locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/a.py"},
                                             "region": {"startLine": 5}}}]},
    ]}]}
    fs = parse_sarif_findings(sarif)
    # backslash 키여도 정규화 후 매칭
    assert filter_findings_to_ai_lines(fs, {"src\\a.py": {5}})
    assert filter_findings_to_ai_lines(fs, {"./src/a.py": {5}})
    assert filter_findings_to_ai_lines(fs, {"src/a.py": {99}}) == []


def test_filter_to_ai_lines():
    sarif = json.loads(_SARIF.read_text(encoding="utf-8"))
    findings = parse_sarif_findings(sarif)
    line = findings[0].line
    fname = findings[0].file
    # AI 라인에 해당 라인 포함 → 통과
    kept = filter_findings_to_ai_lines(findings, {fname: {line}})
    assert kept
    # AI 라인이 다른 곳 → 제외
    dropped = filter_findings_to_ai_lines(findings, {fname: {line + 999}})
    assert dropped == []


# --- framework source-model 검증 매트릭스 로더 (순수, CodeQL 불필요) -------- #
def test_validation_matrix_real_file():
    """실제 동봉 source_validation.json: fastapi=검증됨, starlette/strawberry=미검증."""
    matrix = load_source_validation_matrix(_VALIDATION)
    assert matrix == {"fastapi": True, "starlette": False, "strawberry": False}


def test_validation_matrix_all_fixtures_must_detect():
    """프레임워크는 그 fixture 가 '전부' detected 여야 검증됨(하나라도 미검출이면 False)."""
    doc = {"status": "run", "results": {
        "a": {"framework": "fw1", "detected": True},
        "b": {"framework": "fw1", "detected": False},  # 같은 fw 의 다른 fixture 미검출
        "c": {"framework": "fw2", "detected": True},
    }}
    assert parse_source_validation_matrix(doc) == {"fw1": False, "fw2": True}


def test_validation_matrix_status_not_run_is_none():
    """status!='run' → None(검증 미실행, G2 NOT_RUN 으로 이어져야 함 — 빈 결과 오독 금지)."""
    assert parse_source_validation_matrix({"status": "skipped", "results": {}}) is None


def test_validation_matrix_strict_bool_detected():
    """codex Q1 F5: `detected` 는 엄격히 JSON true 만 검증됨. 문자열 "false"/"true" 는 미검증(False)."""
    doc = {"status": "run", "results": {
        "a": {"framework": "fw1", "detected": "false"},  # 문자열 → bool("false")=True 버그 방지
        "b": {"framework": "fw2", "detected": "true"},    # 문자열 → 여전히 미검증
        "c": {"framework": "fw3", "detected": 1},          # 비-bool → 미검증
        "d": {"framework": "fw4", "detected": True},       # 진짜 bool True
    }}
    assert parse_source_validation_matrix(doc) == {
        "fw1": False, "fw2": False, "fw3": False, "fw4": True}


def test_default_validation_matrix():
    """동봉 매트릭스 로드 → fastapi 검증, starlette/strawberry 미검증."""
    assert default_validation_matrix() == {
        "fastapi": True, "starlette": False, "strawberry": False}


def test_validation_resource_is_package_data():
    """검증 매트릭스는 패키지 내부 리소스여야 wheel 에 동봉됨(codex Q1r2 [중]: tests/ 아님)."""
    import auditai

    p = source_validation_path()
    assert p.exists()
    assert p.parts[-2:] == ("codeql", "source_validation.json")
    # auditai 패키지 디렉토리 하위 → 설치 시 함께 배포(wheel 빌드로 확인됨)
    assert Path(auditai.__file__).parent in p.parents


def test_validation_matrix_missing_file_is_none():
    assert load_source_validation_matrix(Path("does/not/exist.json")) is None


def test_unvalidated_frameworks():
    matrix = {"fastapi": True, "starlette": False}
    # starlette=미검증, django=매트릭스에 없음(미등록=미검증)
    assert unvalidated_frameworks({"fastapi"}, matrix) == set()
    assert unvalidated_frameworks({"fastapi", "starlette"}, matrix) == {"starlette"}
    assert unvalidated_frameworks({"django"}, matrix) == {"django"}
    # matrix=None → None(검증 미실행)
    assert unvalidated_frameworks({"fastapi"}, None) is None


# --- 실제 CodeQL (설치 시에만) --------------------------------------------- #
@pytest.mark.skipif(not codeql_available(), reason="CodeQL CLI not installed")
def test_run_track_a_fastapi(tmp_path: Path):
    """실제 CodeQL: fastapi fixture → command injection finding (built-in FastAPI source model)."""
    findings = run_track_a(str(_FASTAPI), str(tmp_path / "db"), find_codeql())
    assert findings is not None, "CodeQL 실행 성공"
    assert any("78" in f.cwe or "command" in f.title.lower() for f in findings)


# --- S2: CodeQLTaintResult 파서 + exact-overlap 상관 (codex MVP S2) ---------- #
def _taint_sarif(uri="api.py", sink_line=10, sink_col=12):
    return {"runs": [{"tool": {"driver": {"rules": [
        {"id": "py/command-line-injection", "properties": {"tags": ["external/cwe/cwe-078"]}}]}},
        "results": [{
            "ruleId": "py/command-line-injection", "level": "error", "message": {"text": "cmd inj"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri},
                          "region": {"startLine": sink_line, "startColumn": sink_col, "endColumn": sink_col + 20}}}],
            "codeFlows": [{"threadFlows": [{"locations": [
                {"location": {"physicalLocation": {"artifactLocation": {"uri": uri},
                              "region": {"startLine": 5, "startColumn": 4}}}},
                {"location": {"physicalLocation": {"artifactLocation": {"uri": uri},
                              "region": {"startLine": sink_line, "startColumn": sink_col, "endColumn": sink_col + 20}}}},
            ]}]}],
        }]}]}


def test_parse_codeql_taint_results():
    from auditai.codeql import parse_codeql_taint_results

    res = parse_codeql_taint_results(_taint_sarif())
    assert len(res) == 1
    r = res[0]
    assert r.cwe == "CWE-78" and r.rule_id == "py/command-line-injection"
    assert r.sink_start_line == 10 and r.sink_start_col == 12
    assert r.path_nodes and r.path_nodes[-1].role == "sink"


def _cand(file="api.py", line=10, col=12, cwe="CWE-78"):
    from auditai.contracts import (
        CandidateSource, CandidateType, EvidenceKind, FindingCandidate, LocationSpan, Track,
    )
    return FindingCandidate(
        candidate_id=f"S1-{file}-{line}", candidate_type=CandidateType.TAINT_PATH, track=Track.A,
        repo="r", commit_sha="h", file=file, sink_loc=f"{file}:{line}",
        sink_span=LocationSpan(file=file, start_line=line, end_line=line, start_col=col, end_col=col + 20),
        candidate_source=CandidateSource.AST, evidence_kind=EvidenceKind.REQUIRES_CODEQL_VALIDATION,
        recall_reason=f"KB sink x ({cwe})", source_nearby=True,
    )


def test_correlate_exact_overlap_builds_evidence():
    from auditai.codeql import correlate_candidate_evidence, parse_codeql_taint_results

    results = parse_codeql_taint_results(_taint_sarif())
    ev = correlate_candidate_evidence([_cand()], results, "2.25.6")
    assert len(ev) == 1
    fe = next(iter(ev.values()))
    assert fe.source_to_sink_flow_exists and fe.static_path_confirmed
    assert fe.approximation_kind == "generic_codeql_ai_sink_intersection"
    assert fe.confidence < 1.0 and fe.evidence_backend_version == "2.25.6"


def test_correlate_no_span_rejects():
    """sink_span None → exact-overlap 불가 → evidence 없음(codex S0 M1)."""
    from auditai.codeql import correlate_candidate_evidence, parse_codeql_taint_results

    c = _cand()
    c.sink_span = None
    ev = correlate_candidate_evidence([c], parse_codeql_taint_results(_taint_sarif()), "2.25.6")
    assert ev == {}


def test_correlate_line_mismatch_no_evidence():
    """후보 sink 라인과 CodeQL sink 라인이 다르면 상관 안 됨(heuristic 으로 남음)."""
    from auditai.codeql import correlate_candidate_evidence, parse_codeql_taint_results

    results = parse_codeql_taint_results(_taint_sarif(sink_line=10))
    ev = correlate_candidate_evidence([_cand(line=99)], results, "2.25.6")
    assert ev == {}


def test_correlate_ambiguous_rejects():
    """한 후보에 2건 모호 매칭 → reject(오귀속 차단)."""
    from auditai.codeql import correlate_candidate_evidence, parse_codeql_taint_results

    sarif = _taint_sarif()
    sarif["runs"][0]["results"].append(sarif["runs"][0]["results"][0])  # 같은 위치 중복 result
    results = parse_codeql_taint_results(sarif)
    assert len(results) == 2
    ev = correlate_candidate_evidence([_cand()], results, "2.25.6")
    assert ev == {}  # 모호 → 상관 거부


# --- codex S2func CODE QA: fail-open 경계 회귀 테스트 (r1 → 35%/머지불가 지적 반영) --- #

def _taint_sarif_split(uri="api.py", primary_line=5, sink_line=10, cwe_tag="cwe-089",
                       rule="py/sql-injection"):
    """primary location ≠ codeFlow sink. primary 만 겹쳐도 evidence 가 새는지(prim_hit) 검증용."""
    return {"runs": [{"tool": {"driver": {"rules": [
        {"id": rule, "properties": {"tags": [f"external/cwe/{cwe_tag}"]}}]}},
        "results": [{
            "ruleId": rule, "level": "error", "message": {"text": "x"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri},
                          "region": {"startLine": primary_line, "startColumn": 4, "endColumn": 20}}}],
            "codeFlows": [{"threadFlows": [{"locations": [
                {"location": {"physicalLocation": {"artifactLocation": {"uri": uri},
                              "region": {"startLine": primary_line, "startColumn": 4}}}},
                {"location": {"physicalLocation": {"artifactLocation": {"uri": uri},
                              "region": {"startLine": sink_line, "startColumn": 4, "endColumn": 24}}}},
            ]}]}],
        }]}]}


def test_correlate_primary_only_no_evidence():
    """후보가 primary(5)에만 맞고 codeFlow sink(10)엔 안 맞으면 evidence 없음(prim_hit 제거)."""
    from auditai.codeql import correlate_candidate_evidence, parse_codeql_taint_results

    results = parse_codeql_taint_results(_taint_sarif_split(primary_line=5, sink_line=10))
    assert correlate_candidate_evidence([_cand(line=5, col=4, cwe="CWE-89")], results, "2.25.6") == {}
    # 실제 sink(10)에 맞으면 evidence 생성(상관 자체는 동작)
    ev = correlate_candidate_evidence([_cand(line=10, col=4, cwe="CWE-89")], results, "2.25.6")
    assert len(ev) == 1


def test_correlate_col_disjoint_no_match():
    """같은 라인이라도 col 범위가 완전히 어긋나면 다른 sink → no evidence(부분 col 통과 차단)."""
    from auditai.codeql import correlate_candidate_evidence, parse_codeql_taint_results

    results = parse_codeql_taint_results(_taint_sarif(sink_line=10, sink_col=12))  # sink col 12..32
    ev = correlate_candidate_evidence([_cand(line=10, col=50)], results, "2.25.6")  # 후보 col 50..70
    assert ev == {}


def test_correlate_missing_region_no_match():
    """region 누락 result 는 line 0 sentinel → 후보(line 1)와 가짜 매칭 금지(fail-closed)."""
    from auditai.codeql import correlate_candidate_evidence, parse_codeql_taint_results

    sarif = {"runs": [{"tool": {"driver": {"rules": [
        {"id": "py/command-line-injection", "properties": {"tags": ["external/cwe/cwe-078"]}}]}},
        "results": [{"ruleId": "py/command-line-injection", "level": "error", "message": {"text": "x"},
                     "locations": [{"physicalLocation": {"artifactLocation": {"uri": "api.py"}}}]}]}]}
    results = parse_codeql_taint_results(sarif)
    assert len(results) == 1 and results[0].sink_start_line == 0
    assert correlate_candidate_evidence([_cand(line=1)], results, "2.25.6") == {}


def test_correlate_multi_threadflow_ambiguous():
    """한 result 에 2 threadFlow(둘 다 후보 sink 도달) → threadFlow 별 분리 → 모호 reject."""
    from auditai.codeql import correlate_candidate_evidence, parse_codeql_taint_results

    tf = {"locations": [{"location": {"physicalLocation": {"artifactLocation": {"uri": "api.py"},
          "region": {"startLine": 10, "startColumn": 12, "endColumn": 32}}}}]}
    sarif = {"runs": [{"tool": {"driver": {"rules": [
        {"id": "py/command-line-injection", "properties": {"tags": ["external/cwe/cwe-078"]}}]}},
        "results": [{"ruleId": "py/command-line-injection", "level": "error", "message": {"text": "x"},
                     "locations": [{"physicalLocation": {"artifactLocation": {"uri": "api.py"},
                                   "region": {"startLine": 10, "startColumn": 12, "endColumn": 32}}}],
                     "codeFlows": [{"threadFlows": [tf, tf]}]}]}]}
    results = parse_codeql_taint_results(sarif)
    assert len(results) == 2  # threadFlow 별 분리
    assert correlate_candidate_evidence([_cand()], results, "2.25.6") == {}  # 둘 다 매칭 → 모호


def test_correlate_cwe_mismatch_no_evidence():
    """후보 CWE-89 ≠ result CWE-78 → evidence 없음."""
    from auditai.codeql import correlate_candidate_evidence, parse_codeql_taint_results

    results = parse_codeql_taint_results(_taint_sarif())  # CWE-78
    assert correlate_candidate_evidence([_cand(cwe="CWE-89")], results, "2.25.6") == {}


def test_correlate_no_version_no_evidence():
    """codeql_ver 없으면 'unknown' 위조 대신 근사 evidence 미산출(fail-closed)."""
    from auditai.codeql import correlate_candidate_evidence, parse_codeql_taint_results

    results = parse_codeql_taint_results(_taint_sarif())
    assert correlate_candidate_evidence([_cand()], results, None) == {}
    assert correlate_candidate_evidence([_cand()], results, "") == {}


def test_cwe_compatible_exact_no_prefix_or_unknown():
    """CWE 호환은 정확 일치(접두 오매칭·CWE-unknown 통과 금지, 선행 0 동등)."""
    from auditai.codeql import _cwe_compatible
    from auditai.contracts import CodeQLTaintResult

    def res(cwe):
        return CodeQLTaintResult(result_id="x", rule_id="r", cwe=cwe,
                                 primary_file="a.py", primary_start_line=1, primary_end_line=1)

    assert _cwe_compatible(_cand(cwe="CWE-78"), res("CWE-78")) is True
    assert _cwe_compatible(_cand(cwe="CWE-78"), res("CWE-7")) is False    # 접두 오매칭 차단
    assert _cwe_compatible(_cand(cwe="CWE-78"), res("CWE-789")) is False  # 접미 오매칭 차단
    assert _cwe_compatible(_cand(cwe="CWE-78"), res("CWE-unknown")) is False  # 미상 fail-closed
    assert _cwe_compatible(_cand(cwe="CWE-078"), res("CWE-78")) is True   # 선행 0 동등


def test_correlate_broad_region_no_multi_attribution():
    """broad SARIF region(한 줄 전체 col 1..999)이 같은 줄 복수 call 후보에 무차별 evidence 를
    부여하지 않는다 — sink 시작 col 이 후보 call span 안에 있어야(codex S2func2 #2)."""
    from auditai.codeql import correlate_candidate_evidence, parse_codeql_taint_results

    sarif = _taint_sarif(sink_line=10, sink_col=1)  # broad: startColumn=1
    sink_region = (sarif["runs"][0]["results"][0]["codeFlows"][0]["threadFlows"][0]
                   ["locations"][-1]["location"]["physicalLocation"]["region"])
    sink_region["endColumn"] = 999  # 한 줄 전체를 덮는 넓은 region
    results = parse_codeql_taint_results(sarif)
    assert results[0].sink_start_col == 1 and results[0].sink_end_col == 999
    # 같은 줄(10)의 두 call 후보(cols 12..32, 50..70). broad region 시작 col(1)은 둘 다 밖.
    c1 = _cand(line=10, col=12)
    c2 = _cand(line=10, col=50)
    c2.candidate_id = "S1-api.py-10b"  # 후보 id 유일화
    ev = correlate_candidate_evidence([c1, c2], results, "2.25.6")
    assert ev == {}  # broad region → 무차별 매칭 차단(예전 disjoint 로직이면 둘 다 매칭됐음)


def test_correlate_result_no_col_with_precise_candidate_rejects():
    """후보가 col 정밀(단일 라인)인데 CodeQL sink 에 col 이 없으면 exact-overlap 불가 → reject(codex S2func3)."""
    from auditai.codeql import correlate_candidate_evidence, parse_codeql_taint_results

    sarif = _taint_sarif(sink_line=10, sink_col=12)
    # sink region 에서 col 제거(라인만)
    sink_region = (sarif["runs"][0]["results"][0]["codeFlows"][0]["threadFlows"][0]
                   ["locations"][-1]["location"]["physicalLocation"]["region"])
    sink_region.pop("startColumn", None)
    sink_region.pop("endColumn", None)
    results = parse_codeql_taint_results(sarif)
    assert results[0].sink_start_col is None
    assert correlate_candidate_evidence([_cand(line=10, col=12)], results, "2.25.6") == {}


def test_parse_empty_threadflow_yields_no_result():
    """locations 가 빈 threadFlow 만 있는 result 는 sink 가 없으므로 미산출(codex S2func2 #4 fail-closed)."""
    from auditai.codeql import parse_codeql_taint_results

    sarif = {"runs": [{"tool": {"driver": {"rules": [
        {"id": "py/command-line-injection", "properties": {"tags": ["external/cwe/cwe-078"]}}]}},
        "results": [{"ruleId": "py/command-line-injection", "level": "error", "message": {"text": "x"},
                     "locations": [{"physicalLocation": {"artifactLocation": {"uri": "api.py"},
                                   "region": {"startLine": 10, "startColumn": 12}}}],
                     "codeFlows": [{"threadFlows": [{"locations": []}]}]}]}]}
    assert parse_codeql_taint_results(sarif) == []


def test_parse_codeflow_present_but_empty_threadflows_fail_closed():
    """codeFlows 는 있는데 threadFlows 가 비어 있으면(malformed) primary-as-sink 위조 금지 → 미산출
    (codex S2func4: codeFlow 부재[정상]와 codeFlow-있으나-path-없음[malformed]을 구분)."""
    from auditai.codeql import parse_codeql_taint_results

    base = {"ruleId": "py/command-line-injection", "level": "error", "message": {"text": "x"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": "api.py"},
                          "region": {"startLine": 10, "startColumn": 12}}}]}
    rules = [{"id": "py/command-line-injection", "properties": {"tags": ["external/cwe/cwe-078"]}}]
    # codeFlows 존재하나 threadFlows 빈 → fail-closed(미산출)
    malformed = {**base, "codeFlows": [{"threadFlows": []}]}
    assert parse_codeql_taint_results(
        {"runs": [{"tool": {"driver": {"rules": rules}}, "results": [malformed]}]}) == []
    # codeFlows 키 자체가 없으면 정상 단순 finding → primary-as-sink 1건
    simple = parse_codeql_taint_results(
        {"runs": [{"tool": {"driver": {"rules": rules}}, "results": [base]}]})
    assert len(simple) == 1 and simple[0].sink_start_line == 10
    # codex S2func5: codeFlows=[] (빈 배열, 부재와 구분) → malformed → fail-closed(미산출)
    empty_arr = {**base, "codeFlows": []}
    assert parse_codeql_taint_results(
        {"runs": [{"tool": {"driver": {"rules": rules}}, "results": [empty_arr]}]}) == []


def test_correlate_sink_uri_missing_no_primary_substitution():
    """codeFlow sink node 의 URI 가 비면 primary 파일로 대체하지 않는다(교차파일 오귀속 차단, codex S2func6)."""
    from auditai.codeql import correlate_candidate_evidence, parse_codeql_taint_results

    sarif = _taint_sarif(sink_line=10, sink_col=12)
    sink_loc = (sarif["runs"][0]["results"][0]["codeFlows"][0]["threadFlows"][0]
                ["locations"][-1]["location"]["physicalLocation"])
    sink_loc["artifactLocation"] = {}  # sink node URI 없음
    results = parse_codeql_taint_results(sarif)
    assert results[0].sink_file == ""  # primary 파일로 대체 안 됨(fail-closed)
    # 후보 file/line/col 이 맞아도 sink 파일 불명이므로 evidence 없음
    assert correlate_candidate_evidence([_cand(line=10, col=12)], results, "2.25.6") == {}
