"""Track A — CodeQL 통합 (P0-3b). DB 빌드 → 내장 security suite → SARIF 파싱 → AI 라인 필터.

핵심 정직성: CodeQL CLI 가 없으면 실행하지 않고 그 사실을 그대로 반환한다("빈 결과 오독 금지").
CLI 가 있으면 `codeql database create --language=python` 후 내장 python-security-extended
suite 를 돌려 SARIF 를 FindingReport 로 파싱하고, AI 귀속 라인(diff added)과 교차하는 finding
만 남긴다(`filter_findings_to_ai_lines`, 01 C1 heuristic_positive_only). 항상
vulnerability_confirmed=False(사람검토 전).

NOTE(MVP 한계 — 정직 고지): split-config SourceToAi/AiToSink AiOnFlow QL
(docs/01-direction-review.md §5 Step3)은 V1.5 설계이고 **현재 Track A 에는 미구현**이다.
지금은 그 split-config 쿼리가 아니라 generic suite + 사후 AI-라인 필터를 쓴다 — 즉
'AI 라인 ∩ taint path' 가 아니라 'AI 라인 ∩ finding 위치' 의 근사다. 전용 .ql 는 아직 없다.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

from .contracts import (
    CodeQLTaintResult,
    FindingCandidate,
    FlowEvidence,
    LocationSpan,
    PathLeg,
    PathNode,
)
from .contracts import FindingReport


def find_codeql() -> str | None:
    """PATH 또는 .tools/codeql 에서 codeql 실행파일 탐색. 없으면 None."""
    exe = shutil.which("codeql")
    if exe:
        return exe
    here = Path(__file__).resolve().parent.parent
    for cand in (
        here / ".tools" / "codeql" / "codeql" / "codeql.exe",
        here / ".tools" / "codeql" / "codeql" / "codeql",
        here / ".tools" / "codeql" / "codeql.exe",
    ):
        if cand.exists():
            return str(cand)
    return None


def codeql_available() -> bool:
    return find_codeql() is not None


def codeql_version(codeql: str | None = None) -> str | None:
    codeql = codeql or find_codeql()
    if not codeql:
        return None
    try:
        out = subprocess.run([codeql, "version", "--format=terse"], capture_output=True,
                             text=True, timeout=60)
        return out.stdout.strip() or None
    except (subprocess.SubprocessError, OSError):
        return None


# --------------------------------------------------------------------------- #
# SARIF 파싱 (CodeQL 없이도 단위 테스트 가능 — 순수 함수)
# --------------------------------------------------------------------------- #
def _rule_cwe(rule: dict) -> str:
    """SARIF rule.tags 에서 CWE 추출. 'external/cwe/cwe-078' → 'CWE-78'(MITRE 표기, 선행 0 제거)."""
    for tag in rule.get("properties", {}).get("tags", []):
        if isinstance(tag, str) and "cwe-" in tag.lower():
            num = tag.lower().split("cwe-")[-1].lstrip("0") or "0"
            return f"CWE-{num}"
    return rule.get("properties", {}).get("cwe", "") or ""


_LEVEL_SEVERITY = {"error": "high", "warning": "medium", "note": "low"}
_PROBLEM_SEVERITY = {"error": "high", "warning": "medium", "recommendation": "low"}


def _severity_of(res: dict, rule: dict) -> str:
    """codex Q5-1: result.level → rule.defaultConfiguration.level → rule.properties['problem.severity']
    순으로 fallback. CodeQL SARIF 는 result level 이 비고 rule default 가 error 인 경우가 흔하다."""
    lvl = res.get("level") or rule.get("defaultConfiguration", {}).get("level")
    if lvl in _LEVEL_SEVERITY:
        return _LEVEL_SEVERITY[lvl]
    ps = rule.get("properties", {}).get("problem.severity")
    if ps in _PROBLEM_SEVERITY:
        return _PROBLEM_SEVERITY[ps]
    return "medium"


def parse_sarif_findings(sarif: dict) -> list[FindingReport]:
    """CodeQL SARIF → FindingReport[]. severity 는 result/rule level fallback 으로 매핑.
    항상 vulnerability_confirmed=False(사람검토 전). codex Q5-4: finding_id 는 run 경계 넘어 전역 유일."""
    findings: list[FindingReport] = []
    seq = 0
    for ri, run in enumerate(sarif.get("runs", [])):
        rules = {r.get("id"): r for r in run.get("tool", {}).get("driver", {}).get("rules", [])}
        for res in run.get("results", []):
            seq += 1
            loc = (res.get("locations") or [{}])[0].get("physicalLocation", {})
            uri = loc.get("artifactLocation", {}).get("uri", "")
            line = loc.get("region", {}).get("startLine", 0) or 1
            rule_id = res.get("ruleId", "")
            rule = rules.get(rule_id, {})
            cwe = _rule_cwe(rule) or "CWE-unknown"
            msg = res.get("message", {}).get("text", "") or rule_id
            severity = _severity_of(res, rule)
            path: list[str] = []
            for cf in res.get("codeFlows", []):
                for tf in cf.get("threadFlows", []):
                    for tl in tf.get("locations", []):
                        pl = tl.get("location", {}).get("physicalLocation", {})
                        u = pl.get("artifactLocation", {}).get("uri", "")
                        ln = pl.get("region", {}).get("startLine", "")
                        path.append(f"{u}:{ln}")
            findings.append(FindingReport(
                finding_id=f"TA-R{ri}-F{seq:04d}", title=(msg[:80] or rule_id),
                severity=severity, cwe=cwe, file=uri, line=line,
                source_to_sink_path=path, evidence_snippets=[msg],
            ))
    return findings


def count_sarif_sources(sarif: dict) -> int:
    """source-listing 쿼리 SARIF 의 결과 개수(프레임워크 source 검증용)."""
    return sum(len(run.get("results", [])) for run in sarif.get("runs", []))


# --------------------------------------------------------------------------- #
# S2 — CodeQLTaintResult 파서 + S1 후보 exact-overlap 상관 (codex MVP S1/S2)
# FindingReport 를 evidence 로 재사용하지 않는다 — codeFlow sink node·region 보존.
# --------------------------------------------------------------------------- #
def _region(phys: dict) -> tuple[int, int, int | None, int | None]:
    """physicalLocation → (start_line, end_line, start_col, end_col).

    codex S2func MAJOR(FAIL-OPEN): startLine 누락 시 1 로 위조하면 후보 line 1 과 가짜
    매칭(FP 제조기). 누락은 0(sentinel)으로 두고 상관 단계(_spans_overlap)에서 fail-closed
    reject 한다. col 은 없으면 None(라인 단위 비교)."""
    r = phys.get("region", {})
    sl = r.get("startLine") or 0
    el = r.get("endLine") or sl
    sc = r.get("startColumn")
    ec = r.get("endColumn")
    return sl, (el if el >= sl else sl), sc, ec


def parse_codeql_taint_results(sarif: dict) -> list[CodeQLTaintResult]:
    """SARIF → CodeQLTaintResult[]. **threadFlow 마다 1개** result 를 만들고 각 threadFlow 의
    마지막 node 를 그 path 의 sink 로 보존한다.

    codex S2func MAJOR(AMBIGUITY): 다중 codeFlow/threadFlow 를 1개로 뭉개 마지막 node 만 sink 로
    덮어쓰면, 한 result 안의 서로 다른 sink 를 구분 못 해 오귀속이 새 나간다. threadFlow 별로
    분리해 두면 correlate 단계의 'len(matches)!=1 → reject' 가 그 모호성을 그대로 잡는다.
    codeFlow 가 없으면 primary location 을 sink 로 하는 단일 result."""
    out: list[CodeQLTaintResult] = []
    seq = 0
    for ri, run in enumerate(sarif.get("runs", [])):
        rules = {r.get("id"): r for r in run.get("tool", {}).get("driver", {}).get("rules", [])}
        for res in run.get("results", []):
            seq += 1
            rule_id = res.get("ruleId", "")
            rule = rules.get(rule_id, {})
            cwe = _rule_cwe(rule) or "CWE-unknown"
            severity = _severity_of(res, rule)
            pl = (res.get("locations") or [{}])[0].get("physicalLocation", {})
            pfile = pl.get("artifactLocation", {}).get("uri", "")
            psl, pel, psc, pec = _region(pl)
            codeflows = res.get("codeFlows")
            if codeflows is None:  # codeFlows 키 부재/null → 정상 단순 finding → primary 가 sink
                out.append(CodeQLTaintResult(
                    result_id=f"R{ri}-F{seq:04d}", rule_id=rule_id, cwe=cwe, severity=severity,
                    primary_file=pfile, primary_start_line=psl, primary_end_line=pel,
                    primary_start_col=psc, primary_end_col=pec,
                    sink_file=pfile, sink_start_line=psl, sink_end_line=pel,
                    sink_start_col=psc, sink_end_col=pec, flow_path=[], path_nodes=[]))
                continue
            # codex S2func5: codeFlows present(빈 [] 포함)인데 path 없음 → malformed → fail-closed.
            # (부재/null 만 단순 finding 으로 primary-as-sink, 빈 배열은 '경로 주장하나 없음' 취급)
            threadflows = [tf for cf in codeflows for tf in cf.get("threadFlows", [])]
            if not threadflows:
                continue          # primary-as-sink 위조 금지(fail-closed, 미산출)
            for pi, tf in enumerate(threadflows):
                locs = tf.get("locations", [])
                if not locs:  # codex S2func2 #4: 빈 threadFlow 는 sink 없음 → primary 차용 금지(fail-closed)
                    continue
                nodes: list[PathNode] = []
                flow_path: list[str] = []
                for si, tl in enumerate(locs):
                    loc = tl.get("location", {}).get("physicalLocation", {})
                    u = loc.get("artifactLocation", {}).get("uri", "")
                    nsl, nel, nsc, nec = _region(loc)
                    flow_path.append(f"{u}:{nsl}")
                    nodes.append(PathNode(
                        engine="codeql", node_id=f"R{ri}F{seq}P{pi}N{si}", file=u,
                        start_line=nsl, end_line=nel, start_col=nsc, end_col=nec,
                        role=("sink" if si == len(locs) - 1 else "step"),
                        path_leg=PathLeg.AI_TO_SINK, sequence=si, path_id=f"R{ri}F{seq}P{pi}",
                    ))
                # locs 비어있지 않음(위 `if not locs: continue`) → 마지막 location = 이 path 의 sink.
                # codex S2func6: sink node URI 누락 시 primary 파일로 대체하지 않는다(교차파일 오귀속
                # 금지). URI 없으면 sfile="" → correlate 의 파일 매칭에서 fail-closed reject.
                sink_pl = locs[-1].get("location", {}).get("physicalLocation", {})
                sfile = sink_pl.get("artifactLocation", {}).get("uri", "")
                ssl, sel, ssc, sec = _region(sink_pl)
                out.append(CodeQLTaintResult(
                    result_id=f"R{ri}-F{seq:04d}-P{pi}", rule_id=rule_id, cwe=cwe,
                    severity=severity, primary_file=pfile, primary_start_line=psl,
                    primary_end_line=pel, primary_start_col=psc, primary_end_col=pec,
                    sink_file=sfile, sink_start_line=ssl, sink_end_line=sel,
                    sink_start_col=ssc, sink_end_col=sec,
                    flow_path=flow_path, path_nodes=nodes,
                ))
    return out


def _spans_overlap(a: LocationSpan, rfile: str, rsl: int, rel: int,
                   rsc: int | None, rec: int | None) -> bool:
    """CodeQL result sink 가 후보 sink_span(=call 전체) 안에 위치하는가(정밀 포함 판정).

    codex S2func CRITICAL(FAIL-OPEN): 단순 라인 범위 교차/부분 col 교차는 'exact-overlap' 이
    아니라 fail-open 이다. 후보 sink_span 은 bounded call span 이므로 'result sink **시작점**(line+col)이
    후보 call span 안에 포함' 됨을 요구한다(line 정책과 col 정책 동형). 누락 region(rsl<=0)은
    fail-closed reject. col exact 동일까지 요구하지 않는 것은 의도적 — AST call span 과 CodeQL sink 가
    sub-node(인자 등) 앵커링으로 col 이 달라질 수 있어 exact 는 전면 FN 을 부른다. 단, codex S2func2 #2:
    '교차(disjoint reject)'는 broad region(한 줄 전체)이 같은 줄 복수 call 에 무차별 매칭되므로,
    sink 시작 col 이 후보 span **안**(`start_col<=rsc<=end_col`)임을 요구해 오귀속을 막는다."""
    if _norm(a.file) != _norm(rfile):
        return False
    if rsl <= 0:  # 누락 region sentinel → 위조 매칭 차단(fail-closed)
        return False
    if not (a.start_line <= rsl <= a.end_line):  # result sink 시작이 후보 call span 라인 안
        return False
    if (a.start_col is not None and a.end_col is not None
            and rsl == a.start_line == a.end_line):
        # codex S2func3: 후보가 단일 라인 + col 정밀인데 result sink 에 col 이 없으면(rsc None)
        # exact-overlap 확인 불가 → fail-closed reject('exact-overlap' 이름값 유지). 있으면 span 포함.
        if rsc is None or not (a.start_col <= rsc <= a.end_col):
            return False
    return True


def correlate_candidate_evidence(
    candidates: list[FindingCandidate], results: list[CodeQLTaintResult],
    codeql_ver: str | None,
) -> dict[str, FlowEvidence]:
    """S1 taint 후보 ↔ CodeQL result **sink** 를 exact-overlap 상관 → FlowEvidence.

    규칙(전부 fail-closed): ① candidate.sink_span 必須(None→reject). ② result **sink** span 이
    후보 call span 안에 위치(primary 만 겹치는 건 불인정 — codex S2func CRITICAL: primary 는 sink
    가 아니다). ③ CWE 정확 호환(CWE-unknown/미상→reject). ④ 한 후보에 2건 이상 매칭→reject(오귀속).
    ⑤ codeql_ver 없으면 근사 evidence 산출 불가 → 전체 skip('unknown' 위조 금지, codex S2func).
    approximation_kind 로 '근사' 임을 정직 표기.
    """
    if not codeql_ver:  # 버전 없는 근사 evidence 는 정직하지 않다 → 미산출(fail-closed)
        return {}
    evidence: dict[str, FlowEvidence] = {}
    for cand in candidates:
        span = cand.sink_span
        if span is None:
            continue  # span 없으면 exact-overlap 불가 → 상관 안 함(reject)
        matches = [
            r for r in results
            if _cwe_compatible(cand, r) and _spans_overlap(
                span, r.sink_file or "", r.sink_start_line or 0,
                r.sink_end_line or 0, r.sink_start_col, r.sink_end_col)
        ]
        if len(matches) != 1:
            continue  # 0=evidence 없음(heuristic 으로 남음), >1=모호 → reject(오귀속 금지)
        r = matches[0]
        evidence[cand.candidate_id] = FlowEvidence(
            candidate_id=cand.candidate_id, source_to_sink_flow_exists=True,
            static_path_confirmed=True,
            approximation_kind="generic_codeql_ai_sink_intersection",
            confidence=0.6, evidence_backend_version=codeql_ver,
            sink=f"{r.sink_file}:{r.sink_start_line}", flow_path=r.flow_path,
            path_nodes=r.path_nodes, engine="codeql", query_id=r.rule_id,
        )
    return evidence


_CWE_RE = re.compile(r"CWE-0*(\d+)", re.IGNORECASE)


def _cwe_compatible(cand: FindingCandidate, r: CodeQLTaintResult) -> bool:
    """후보 recall_reason 의 CWE 와 CodeQL result CWE 가 **정확히** 일치하는가.

    codex S2func MAJOR(FAIL-OPEN): 기존 `r.cwe in recall_reason` 부분문자열 검사는 CWE-7 ⊂ CWE-78
    오매칭이고, `CWE-unknown` 우회·capability_id 없으면 무조건 통과까지 겹쳐 CWE 차단이 사실상
    깨져 있었다. 이제 정규식으로 CWE 번호만 뽑아 집합 일치(선행 0 무시), 미상 CWE→fail-closed."""
    rc = _CWE_RE.search(r.cwe or "")
    if not rc:  # CWE-unknown / 빈 값 → 호환 판정 불가 → fail-closed
        return False
    cand_nums = {m.group(1) for m in _CWE_RE.finditer(cand.recall_reason or "")}
    return rc.group(1) in cand_nums


# --------------------------------------------------------------------------- #
# Framework source-model 검증 매트릭스 (source_validation.json → {framework: bool})
#
# 순수 파서. G2 가 이 매트릭스를 '어떻게' 소비할지(gate_g2 시그니처)는 별개 설계 결정으로
# codex 판정 대기(docs/CODEX_VERIFICATION_QUEUE.md ★G2 공백). 이 로더의 출력 형식
# {framework: validated_bool} 은 어느 해석에서든 동일하게 필요하므로 먼저 박제한다.
#
# 검증됨(validated=True)의 정의(보수적): 그 프레임워크의 fixture 가 >=1개 있고 '전부' detected=true.
# 하나라도 미검출이면 source model 이 불완전 → False(예: starlette/strawberry).
# "빈 결과 오독 금지": 미검증 프레임워크의 taint finding=0 은 신뢰 불가 신호다.
# --------------------------------------------------------------------------- #
def parse_source_validation_matrix(doc: dict) -> dict[str, bool] | None:
    """source_validation.json(dict) → {framework: validated_bool}. status!='run' 이면 None.

    `detected` 는 **엄격히 JSON true** 만 검증됨으로 본다(codex Q1 F5: `bool("false")` 는 True 라
    문자열 "false" 가 통과하는 버그 방지). bool 이 아닌 값은 미검증(False)으로 강등.
    """
    if doc.get("status") != "run":
        return None  # 검증 자체가 수행 안 됨 → 매트릭스 없음(G2 NOT_RUN 으로 이어져야 함)
    per_fw_all: dict[str, bool] = {}
    seen: set[str] = set()
    for entry in doc.get("results", {}).values():
        fw = entry.get("framework")
        if not fw:
            continue
        detected = entry.get("detected") is True  # 엄격 비교(비-bool/문자열 "false" → False)
        per_fw_all[fw] = per_fw_all.get(fw, True) and detected  # AND: 전부 detected 여야 True
        seen.add(fw)
    return {fw: per_fw_all[fw] for fw in seen}


def load_source_validation_matrix(path: str | Path) -> dict[str, bool] | None:
    """검증 JSON 파일 경로 → {framework: validated_bool}. 파일 없음/파싱실패 시 None(정직히 미검증 취급)."""
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return parse_source_validation_matrix(doc)


# 패키지 동봉 검증 매트릭스(런타임 source-of-truth). CodeQL 2.25.6 으로 검증됨.
_VALIDATION_RESOURCE = Path(__file__).parent / "codeql" / "source_validation.json"


def source_validation_path() -> Path:
    """동봉된 framework source 검증 매트릭스(JSON) 경로."""
    return _VALIDATION_RESOURCE


def default_validation_matrix() -> dict[str, bool] | None:
    """동봉 매트릭스 → {framework: validated_bool}. (CLI `--run-codeql` 기본 검증입력)."""
    return load_source_validation_matrix(_VALIDATION_RESOURCE)


def source_validation_codeql_version(path: str | Path) -> str | None:
    """검증 매트릭스가 '어느 CodeQL 버전으로' 검증됐는지(codex Q1r2 [상]: 버전 결합).

    매트릭스의 detected 결과는 CodeQL 버전별 source model 에 의존하므로, 런타임 CodeQL 버전이
    이와 다르면 매트릭스를 신뢰할 수 없다(거짓 정직성 방지). status!='run'/누락 시 None.
    """
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if doc.get("status") != "run":
        return None
    v = doc.get("codeql_version")
    return v if isinstance(v, str) and v else None


def default_validation_codeql_version() -> str | None:
    """동봉 매트릭스가 검증된 CodeQL 버전."""
    return source_validation_codeql_version(_VALIDATION_RESOURCE)


def unvalidated_frameworks(frameworks: set[str], matrix: dict[str, bool] | None) -> set[str] | None:
    """detected frameworks 중 매트릭스에서 검증 안 된(False/미등록) 것들. matrix=None 이면 None(검증 미실행)."""
    if matrix is None:
        return None
    return {f for f in frameworks if not matrix.get(f, False)}


# --------------------------------------------------------------------------- #
# DB 빌드 / 쿼리 실행 (CLI 있을 때만)
# --------------------------------------------------------------------------- #
def _record(status: dict | None, **kw) -> None:
    if status is not None:
        status.update(kw)


def build_python_db(source_root: str, db_dir: str, codeql: str | None = None,
                    status: dict | None = None) -> bool:
    """codeql database create --language=python. 실패 시 False (codex Q5-5: 실패 원인을 status 에 기록).

    codex Q5-7: 임의 db_dir 선삭제(rmtree) 제거 — `--overwrite` 에 맡긴다(파괴적 부작용 방지)."""
    codeql = codeql or find_codeql()
    if not codeql:
        _record(status, stage="build", error="codeql not found")
        return False
    Path(db_dir).parent.mkdir(parents=True, exist_ok=True)  # CodeQL 은 부모 dir 존재 요구
    try:
        proc = subprocess.run(
            [codeql, "database", "create", db_dir, "--language=python",
             "--source-root", source_root, "--overwrite"],
            capture_output=True, text=True, timeout=600,
        )
        _record(status, stage="build", returncode=proc.returncode,
                stderr_tail=(proc.stderr or "")[-2000:])
        return proc.returncode == 0
    except subprocess.TimeoutExpired:
        _record(status, stage="build", timed_out=True)
        return False
    except (subprocess.SubprocessError, OSError) as e:
        _record(status, stage="build", error=str(e))
        return False


def run_query_sarif(db_dir: str, query_path: str, codeql: str | None = None,
                    status: dict | None = None) -> dict | None:
    """쿼리 실행 → SARIF dict. 실패 시 None (codex Q5-5: 실패 원인을 status 에 기록)."""
    codeql = codeql or find_codeql()
    if not codeql:
        _record(status, stage="analyze", error="codeql not found")
        return None
    out_sarif = str(Path(db_dir).parent / "results.sarif")
    try:
        proc = subprocess.run(
            [codeql, "database", "analyze", db_dir, query_path,
             "--format=sarif-latest", "--output", out_sarif, "--rerun"],
            capture_output=True, text=True, timeout=900,
        )
        _record(status, stage="analyze", returncode=proc.returncode,
                stderr_tail=(proc.stderr or "")[-2000:])
        if proc.returncode != 0 or not Path(out_sarif).exists():
            return None
        return json.loads(Path(out_sarif).read_text(encoding="utf-8"))
    except subprocess.TimeoutExpired:
        _record(status, stage="analyze", timed_out=True)
        return None
    except (subprocess.SubprocessError, OSError, json.JSONDecodeError) as e:
        _record(status, stage="analyze", error=str(e))
        return None


_DEFAULT_SUITE = "codeql/python-queries:codeql-suites/python-security-extended.qls"


def run_track_a(
    source_root: str,
    db_dir: str,
    codeql: str | None = None,
    suite: str = _DEFAULT_SUITE,
    status: dict | None = None,
) -> list[FindingReport] | None:
    """source_root 에 DB 빌드 + security suite 실행 + SARIF 파싱. CodeQL 없으면 None.

    codex Q5-5/6: status(dict) 에 stage/returncode/stderr_tail/timed_out + codeql_version 기록(재현성·진단)."""
    sarif = run_track_a_sarif(source_root, db_dir, codeql, suite, status=status)
    if sarif is None:
        return None
    findings = parse_sarif_findings(sarif)
    _record(status, finding_count=len(findings))
    return findings


def run_track_a_sarif(
    source_root: str,
    db_dir: str,
    codeql: str | None = None,
    suite: str = _DEFAULT_SUITE,
    status: dict | None = None,
) -> dict | None:
    """DB 빌드 + suite 실행 후 **raw SARIF** 반환(없으면 None). S2 가 CodeQLTaintResult 로 파싱하려면 필요.

    `run_track_a` 는 이걸 호출해 FindingReport 로 파싱한다(하위호환 — 동작 동일)."""
    codeql = codeql or find_codeql()
    _record(status, codeql=codeql, codeql_version=codeql_version(codeql), suite=suite)
    if not codeql:
        _record(status, stage="find", error="codeql not found")
        return None
    if not build_python_db(source_root, db_dir, codeql, status=status):
        return None
    return run_query_sarif(db_dir, suite, codeql, status=status)


def _norm(p: str) -> str:
    """경로 정규화: 백슬래시→슬래시 + 선행 './' 만 제거(codex Q5-3: lstrip('./') 는 모든 선행
    '.'/'/' 를 깎아 `.hidden/`/`../`/`/abs` 를 변형 → '..'·absolute 는 그대로 둬 정규 매칭 실패로 남김)."""
    p = p.replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    return p


def filter_findings_to_ai_lines(
    findings: list[FindingReport], ai_lines: dict[str, set[int]]
) -> list[FindingReport]:
    """Track A finding 중 AI 귀속 라인(파일→라인집합)과 교차하는 것만 (01 C1 MVP 휴리스틱:
    heuristic_positive_only — '경로에 AI 없음'을 음성 판정으로 쓰지 말 것).

    full-path(repo-relative) 우선 매칭. basename 폴백은 codex Q5-2: 그 basename 이 ai_lines 전역에서
    **유일**할 때만(다른 디렉토리 동일 파일명 false match 방지). 충돌 basename 은 full-path 매칭만.
    """
    norm_lines = {_norm(k): v for k, v in ai_lines.items()}
    # basename → (라인집합, 출처 full-path 개수). 개수>1 이면 모호 → fallback 불가.
    base_lines: dict[str, set[int]] = {}
    base_count: dict[str, int] = {}
    for k, v in norm_lines.items():
        b = k.split("/")[-1]
        base_lines.setdefault(b, set()).update(v)
        base_count[b] = base_count.get(b, 0) + 1
    out: list[FindingReport] = []
    for f in findings:
        nf = _norm(f.file)
        lines = norm_lines.get(nf)
        if lines is None and _plain_rel(nf):  # codex Q5r2: ../·absolute 경로는 basename 폴백 금지
            b = nf.split("/")[-1]
            if base_count.get(b) == 1:  # 전역 유일 basename 만 폴백 허용
                lines = base_lines.get(b)
        if lines and f.line in lines:
            out.append(f)
    return out


_ABS_OR_URI_RE = re.compile(r"^(/|[a-zA-Z]:[/\\]|[a-zA-Z][a-zA-Z0-9+.\-]*://)")


def _plain_rel(p: str) -> bool:
    """평범한 repo-relative 경로인가(absolute/URI 아님 + '..' 세그먼트 없음). codex Q5r2/Q5r3:
    '../'·POSIX absolute(`/`)·Windows drive(`C:/`)·URI(`file://`) finding 경로는 basename 폴백
    false match 를 막기 위해 full-path 매칭만 허용."""
    if _ABS_OR_URI_RE.match(p):
        return False
    return ".." not in p.split("/")
