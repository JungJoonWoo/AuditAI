"""S1 — known-KB AST seed scanner (docs/06 §1).

**정직한 범위**: high-recall candidate discovery 가 아니라 **KB 등록 sink 한정 AST seed 스캐너**다.
Semgrep / LLM candidate miner / unknown-surface inventory 는 이후 phase. KB 미등록 sink, bare-param
(source 미명시), 변수 추적 필요한 dynamic string 은 미탐지 — `fn_note` 로 정직 표기(codex MVP r1 M3).

codex MVP S1 QA 반영:
- import alias 정규화(`from subprocess import run` / `import x as y`) → known sink FN 차단.
- duck-typed method 매칭은 **required_conditions 있는 sink 만**(예: cursor.execute) — 조건 없는 method
  (requests.get 류)의 `dict.get` FP 차단.
- `required_conditions`: equals / dynamic_string / absent_or_unsafe(yaml Loader) 평가.
- 멀티라인 call: call 이 걸친 라인 중 하나라도 AI/UNKNOWN 이면 매칭(시작 줄만 보지 않음).
- `ai_attribution_refs` 는 원본 blame attribution 을 참조(commit/confidence 왜곡 금지).
- source_nearby = route 데코레이터(app/router 등)일 때만 TAINT_PATH(param 만으론 과대분류 → STATIC_PATTERN_RISK).
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field

from .attribution import GitError, _git
from .contracts import (
    AILineAttribution,
    AttributionState,
    CandidateInventoryItem,
    CandidateSource,
    CandidateType,
    EvidenceKind,
    FindingCandidate,
    LocationSpan,
    Track,
)
from .kb.loader import SecurityKB
from .scope import AddedLineAttribution, DiffScope

_TRACK = {CandidateType.TAINT_PATH: Track.A, CandidateType.STATIC_PATTERN_RISK: Track.A_PRIME}
_EVIDENCE = {
    CandidateType.TAINT_PATH: EvidenceKind.REQUIRES_CODEQL_VALIDATION,
    CandidateType.STATIC_PATTERN_RISK: EvidenceKind.PATTERN_ONLY,
}
_ROUTE_VERBS = ("get", "post", "put", "delete", "patch", "route", "websocket", "options", "head")
_ROUTE_RECEIVERS = ("app", "router", "api", "blueprint", "bp", "application")
_REQUEST_NAMES = ("request", "req", "flask_request")
# duck-typed method 매칭 allowlist (codex S1 r2 상): receiver 가 본질적으로 인스턴스 변수인 것만.
# `run`/`get`/`load`/`system` 같은 generic verb 는 제외 → exact/import-resolved 호출만(FP 차단).
# codex b819cwlvl: KB 에 등록된 신규 method-name sink(sqlite3/aiosqlite executescript)도 duck 으로
# 회수해야 'KB 장식'이 안 됨 → execute + executescript 둘 다 allowlist(둘 다 required_conditions 있음).
_DUCK_METHODS = ("execute", "executescript")  # DB cursor/conn .execute|.executescript (provenance 불명)
_SAFE_YAML_LOADERS_CANON = (
    "yaml.SafeLoader", "yaml.CSafeLoader", "yaml.BaseLoader", "yaml.CBaseLoader",
    "yaml.loader.SafeLoader", "yaml.loader.CSafeLoader",
    "yaml.loader.BaseLoader", "yaml.loader.CBaseLoader",
)


@dataclass
class ScanResult:
    candidates: list[FindingCandidate] = field(default_factory=list)  # AI-귀속 FindingCandidate
    taint_candidates: list[FindingCandidate] = field(default_factory=list)  # AI-귀속 TAINT_PATH → S2
    candidate_inventory: list[CandidateInventoryItem] = field(default_factory=list)  # static + UNKNOWN
    unknown_sink_candidate_count: int = 0
    fn_note: str = (
        "S1=known-KB AST seed scanner(청사진 §S1 'recall-first, 1차 FP 제거 금지'). FP 는 의도적으로 "
        "S2(CodeQL evidence)/S3(LLM)/사람 검토로 미룬다. "
        "구현(codex S1 r5 상): 선행변수 dynamic-string 추적 — enclosing 함수 안 `q=f\"..{x}\"; execute(q)` "
        "처럼 동적문자열을 대입받은 Name 인자도 dynamic_string 조건 충족으로 보고 후보 유지(recall-first; "
        "statement order/재바인딩/scope·branch 는 미추적이라 함수 내 1회 동적대입이면 동적으로 봄 — over-keep, "
        "안전성은 S2/S3 가 판정). 미구현(post-MVP): Semgrep/LLM-miner/unknown-surface; 정밀 name-resolution"
        "(lexical scope·statement order·For/With-as/NamedExpr/destructuring 재바인딩); 변수의 cross-function/"
        "전역 dynamic-string 전파; yaml module-attr rebinding; KB 미등록 sink·bare-param. 안전성(예: yaml "
        "SafeLoader, sanitizer)은 S3 가 판정."
    )


# --------------------------------------------------------------------------- #
# AST 헬퍼
# --------------------------------------------------------------------------- #
def _dotted_name(func: ast.expr) -> str | None:
    """Call.func 의 dotted name (`a.b.c` / `name`). receiver 가 호출/첨자면 None."""
    parts: list[str] = []
    cur = func
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
        return ".".join(reversed(parts))
    return None


def _build_import_table(tree: ast.AST) -> dict[str, str]:
    """local name → canonical dotted (codex S1: import alias 정규화로 known sink FN 차단).

    codex S1 r2: `from x import *`(star)는 미지원(fn_note). 모듈 레벨 assignment/def/class 가 import
    이름을 shadowing 하면 alias 제거(local `run = f` 가 subprocess.run 으로 오매칭되는 FP 차단)."""
    table: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.asname:
                    table[a.asname] = a.name  # import a.b as x → x=a.b
                else:
                    table[a.name.split(".")[0]] = a.name.split(".")[0]  # import a.b → a 사용
        elif isinstance(node, ast.ImportFrom):
            if node.level != 0:
                continue  # 상대 import 는 로컬 모듈 → skip
            mod = node.module or ""
            for a in node.names:
                if a.name == "*":
                    continue  # star import 미지원(fn_note)
                local = a.asname or a.name
                table[local] = f"{mod}.{a.name}" if mod else a.name
    # codex S1 r4: recall-first — shadowing/scope 추적 안 함(제거하면 FN). 재바인딩으로 인한 FP 는
    # S2(CodeQL evidence)가 거른다(청사진 §S1). 미추적 한계는 fn_note.
    return table


def _resolve_dotted(dotted: str | None, table: dict[str, str]) -> str | None:
    """dotted name 의 첫 토큰을 import table 로 canonical 화."""
    if not dotted:
        return dotted
    parts = dotted.split(".")
    if parts[0] in table:
        base = table[parts[0]]
        return ".".join([base, *parts[1:]]) if len(parts) > 1 else base
    return dotted


def _is_literal_str(node: ast.expr) -> bool:
    """완전 literal 식인가 (codex S1 r3/r4: 재귀 — f-string 보간/format_spec/tuple·list 컨테이너 포함)."""
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, ast.JoinedStr):
        for v in node.values:
            if isinstance(v, ast.Constant):
                continue
            if isinstance(v, ast.FormattedValue):
                if not _is_literal_str(v.value):
                    return False
                if v.format_spec is not None and not _is_literal_str(v.format_spec):
                    return False
            else:
                return False
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return _is_literal_str(node.left) and _is_literal_str(node.right)
    if isinstance(node, (ast.Tuple, ast.List)):  # "fmt" % (a, b) 의 RHS
        return all(_is_literal_str(e) for e in node.elts)
    return False


def _is_dynamic_string(node: ast.expr, dynamic_names: frozenset[str] | None = None) -> bool:
    """동적(주입 위험) 문자열인가. literal-only 는 제외(codex S1 r3).

    codex S1 r5(상): `dynamic_names` 가 주어지면 **선행변수 SQLi FN** 을 막는다 — 직접 식이 아니라
    `q = f"..{x}"; cur.execute(q)` 처럼 인자가 동적문자열을 담은 `Name` 일 때(함수 내 assignment 추적
    결과)도 동적으로 본다(recall-first: 후보 유지, 안전성은 S2/S3 가 판정). 그 외 변수추적은 미구현(fn_note)."""
    if dynamic_names and isinstance(node, ast.Name) and node.id in dynamic_names:
        return True  # 선행 assignment 가 동적문자열(intra-function tracking)
    if isinstance(node, ast.JoinedStr):  # f-string: 비-literal 보간이 하나라도 있으면 동적
        return not _is_literal_str(node)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return not (_is_literal_str(node.left) and _is_literal_str(node.right))
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        recv_lit = _is_literal_str(node.func.value)
        args_lit = all(_is_literal_str(a) for a in node.args) and \
            all(_is_literal_str(k.value) for k in node.keywords)
        return not (recv_lit and args_lit)
    return False


def _dynamic_assigned_names(fn: ast.AST | None) -> frozenset[str]:
    """enclosing 함수 안에서 **동적문자열을 대입받은 local Name** 들 (codex S1 r5 상: 선행변수 SQLi FN 차단).

    `q = f"..{x}"`, `q = "a"+x`, `q += f"{x}"`, `q: str = "..%s"%x`, 다중타깃(`a=b=f"{x}"`)·튜플
    언패킹(`a,b = f"{x}", y`) 모두 포착. recall-first 라 statement order/재바인딩/scope 는 추적하지 않는다
    (함수 안 어디서든 한 번이라도 동적 대입되면 그 이름은 동적으로 본다) — 제거하면 reverse-order FN.
    부정확(다른 동명 변수에 안전 대입)으로 인한 FP 는 S2(CodeQL evidence)/S3 가 거른다(청사진 §S1)."""
    if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return frozenset()
    names: set[str] = set()

    def _all_targets(tgt: ast.expr) -> list[str]:
        if isinstance(tgt, ast.Name):
            return [tgt.id]
        if isinstance(tgt, (ast.Tuple, ast.List)):
            out: list[str] = []
            for e in tgt.elts:
                out.extend(_all_targets(e))
            return out
        return []

    def _bind(tgt: ast.expr, val: ast.expr | None) -> None:
        """tgt = val 의 동적 binding 수집. 병렬 튜플(`a,b = x, y`)은 원소별로 매칭해
        `q` 가 literal 이면 제외(과대 keep 줄임). 길이 불일치/별표 등은 보수적으로 전 타깃 keep."""
        if (isinstance(tgt, (ast.Tuple, ast.List))
                and isinstance(val, (ast.Tuple, ast.List))
                and len(tgt.elts) == len(val.elts)
                and not any(isinstance(e, ast.Starred) for e in tgt.elts)):
            for te, ve in zip(tgt.elts, val.elts):
                _bind(te, ve)
            return
        if val is not None and _is_dynamic_string(val):
            names.update(_all_targets(tgt))

    for sub in ast.walk(fn):
        if isinstance(sub, ast.Assign):  # a = b = <expr> (다중타깃)
            for t in sub.targets:
                _bind(t, sub.value)
        elif isinstance(sub, ast.AugAssign):  # q += f"{x}"
            if _is_dynamic_string(sub.value):
                names.update(_all_targets(sub.target))
        elif isinstance(sub, ast.AnnAssign):  # q: str = f"{x}"
            _bind(sub.target, sub.value)
    return frozenset(names)


def _safe_yaml_loader(node: ast.expr, imports: dict[str, str]) -> bool:
    """Loader 인자가 **직접 식으로** yaml 안전 Loader 인가 (codex S1 r4: recall-first, name-trust 제거).

    `yaml.SafeLoader`/`yaml.loader.SafeLoader` 같은 Attribute 가 canonical safe 로 resolve 될 때만 safe(drop).
    bare Name/표현식/호출 은 출처를 단정할 수 없으므로 **safe 로 보지 않고 후보 유지**(fail-closed) — 이렇게
    하면 로컬 재바인딩 fail-open 자체가 사라지고, 안전성 확정은 S3 가 한다(청사진 §S1)."""
    if isinstance(node, ast.Attribute):
        dotted = _dotted_name(node)
        return dotted is not None and _resolve_dotted(dotted, imports) in _SAFE_YAML_LOADERS_CANON
    return False


def _arg_node(call: ast.Call, key: str) -> tuple[ast.expr | None, bool]:
    """(arg 노드, present). 위치 인덱스 문자열 또는 keyword 이름. (codex S1 r2: keyword|positional alias)."""
    if key.isdigit():
        idx = int(key)
        return (call.args[idx], True) if idx < len(call.args) else (None, False)
    for kw in call.keywords:
        if kw.arg == key:
            return kw.value, True
    return None, False


def _conditions_met(
    call: ast.Call, conditions: list[dict], imports: dict[str, str],
    dynamic_names: frozenset[str] | None = None,
) -> bool:
    """SinkSpec.required_conditions 전부 충족? (codex S1: absent_or_unsafe + positional + canonical).

    codex S1 r5(상): `dynamic_names`(enclosing 함수에서 동적문자열 대입된 Name)는 dynamic_string 평가에
    넘겨 `q=f"..{x}"; execute(q)` 선행변수 SQLi 후보를 유지한다(recall-first)."""
    for cond in conditions:
        key = str(cond.get("arg", ""))
        node, present = _arg_node(call, key)
        if "equals" in cond:
            if not present or not (isinstance(node, ast.Constant) and node.value == cond["equals"]):
                return False
        if cond.get("dynamic_string"):
            if not present or not _is_dynamic_string(node, dynamic_names):
                return False
        if cond.get("absent_or_unsafe"):
            # codex S1 r2 상: Loader 를 keyword 와 positional(예: yaml.load(x, Loader)) 둘 다 확인.
            lnode, lpresent = node, present
            if not lpresent:  # keyword 미존재 → positional index 1(stream 다음) 시도
                lnode, lpresent = _arg_node(call, "1")
            # 생략 → unsafe(통과). 있으면 직접 canonical SafeLoader Attribute 만 안전(미통과).
            if lpresent and _safe_yaml_loader(lnode, imports):
                return False
    return True


def _route_handler(node: ast.AST) -> bool:
    """함수가 HTTP route 핸들러인가 — @app.get/@router.post/@app.route 등(app/router receiver)."""
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return False
    for deco in node.decorator_list:
        target = deco.func if isinstance(deco, ast.Call) else deco
        if isinstance(target, ast.Attribute) and target.attr in _ROUTE_VERBS:
            recv = target.value
            recv_name = (recv.attr if isinstance(recv, ast.Attribute)
                         else getattr(recv, "id", "")).lower()
            if any(r in recv_name for r in _ROUTE_RECEIVERS):
                return True
    return False


def _has_request_ref(node: ast.AST) -> bool:
    """함수 본문이 request/req 객체를 참조하나(framework source 신호)."""
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name) and sub.id in _REQUEST_NAMES:
            return True
        if isinstance(sub, ast.Attribute) and isinstance(sub.value, ast.Name) and sub.value.id in _REQUEST_NAMES:
            return True
    return False


def _is_generic_dbapi(sig) -> bool:
    """generic DBAPI cursor sink(sqlite3/aiosqlite 아님) — module=='dbapi'."""
    return getattr(sig, "module", None) == "dbapi"


def _sink_more_specific(new: tuple, cur: tuple, duck: bool) -> bool:
    """같은 call span + capability 의 후보 중 대표 선택 우선순위(codex b819cwlvl, recall-first).

    duck-typed(receiver 변수) 매칭은 어떤 DB 라이브러리인지 단정 못 한다 → **generic dbapi sink**
    (`cursor.execute`)를 대표로(라이브러리 특정 주장은 근거 없음, 가장 정직). generic 이 없으면(예:
    executescript) sink.id 사전순으로 결정론적 선택. exact 매칭(by_qual)은 보통 qualified name 당 sink
    1개라 충돌이 없으나 동일하게 결정론적으로 처리한다. 어느 쪽이든 coverage 는 줄지 않고(같은 span+cap
    은 본래 1 후보가 맞음) 중복만 제거된다."""
    new_sink, new_sig = new
    cur_sink, cur_sig = cur
    if duck:
        new_generic, cur_generic = _is_generic_dbapi(new_sig), _is_generic_dbapi(cur_sig)
        if new_generic != cur_generic:
            return new_generic  # generic dbapi 가 대표
    return new_sink.id < cur_sink.id  # 결정론적 tie-break


def _build_index(kb: SecurityKB):
    by_qual: dict[str, list] = {}
    by_method: dict[str, list] = {}
    for sink in kb.sinks.values():
        sig = kb.api_signatures.get(sink.api_signature_id) if sink.api_signature_id else None
        if sig is None or sig.language != "python":
            continue
        by_qual.setdefault(sig.qualified_name, []).append((sink, sig))
        # duck-typed method 매칭은 **allowlist(_DUCK_METHODS) + required_conditions** 있는 sink 만
        # (codex S1 r2 상: generic verb run/get 의 obj.run/dict.get FP 차단; exact 매칭은 그대로).
        if sig.method_name in _DUCK_METHODS and sink.required_conditions:
            by_method.setdefault(sig.method_name, []).append((sink, sig))
    return by_qual, by_method


def scan_candidates(
    repo: str, scope: DiffScope, added_attr: AddedLineAttribution, kb: SecurityKB
) -> ScanResult:
    by_qual, by_method = _build_index(kb)
    res = ScanResult()
    seen: set[str] = set()

    for fd in scope.files:
        if fd.is_delete or fd.is_binary or not fd.file.endswith(".py"):
            continue
        ai = added_attr.ai_lines.get(fd.file, set())
        unknown = added_attr.unknown_lines.get(fd.file, set())
        if not ai and not unknown:
            continue
        try:
            content = _git(repo, "show", f"{scope.head_sha}:{fd.file}")
        except GitError:
            content = "\n".join(a.text for a in fd.added_lines)
        try:
            tree = ast.parse(content)
        except SyntaxError:
            continue
        clines = content.splitlines()
        imports = _build_import_table(tree)
        # 라인 → 원본 attribution (commit/confidence 보존, codex S1 중)
        attr_by_line = {a.line_range[0]: a for a in added_attr.attributions if a.file == fd.file}

        funcstack: list[ast.AST] = []
        scanner = _CallScanner(
            fd=fd, repo=repo, scope=scope, ai=ai, unknown=unknown, clines=clines,
            imports=imports, attr_by_line=attr_by_line,
            by_qual=by_qual, by_method=by_method, funcstack=funcstack, res=res, seen=seen,
        )
        scanner.visit(tree)
    return res


class _CallScanner(ast.NodeVisitor):
    def __init__(self, **kw):
        self.__dict__.update(kw)

    def visit_FunctionDef(self, node):  # noqa: N802
        self.funcstack.append(node)
        self.generic_visit(node)
        self.funcstack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef  # noqa: N815

    def visit_Call(self, node):  # noqa: N802
        self._match(node)
        self.generic_visit(node)

    def _candidate_lines(self, node: ast.Call) -> set[int]:
        return set(range(node.lineno, (getattr(node, "end_lineno", None) or node.lineno) + 1))

    def _match(self, node: ast.Call):
        dotted = _dotted_name(node.func)
        resolved = _resolve_dotted(dotted, self.imports)
        cands = []
        duck = False
        if resolved and resolved in self.by_qual:
            cands = self.by_qual[resolved]
        elif isinstance(node.func, ast.Attribute) and node.func.attr in self.by_method:
            # duck-typed(allowlist=execute): receiver 가 import 된 모듈이 아닐 때만(변수/호출체인).
            # codex S1 r2: `cursor.execute`/`conn.cursor().execute`(변수·call receiver) → 매칭;
            #   `json.load`(head 'json' import) 는 exact 만, `obj.run` 은 by_method 에 없어 제외.
            head = dotted.split(".")[0] if dotted else None
            if head is None or head not in self.imports:
                cands = self.by_method[node.func.attr]
                duck = True  # codex S1 r3: provenance 불명 → TAINT 아닌 static/저신뢰로 낮춤
        if not cands:
            return

        call_lines = self._candidate_lines(node)
        ai_hit = sorted(call_lines & self.ai)
        unk_hit = sorted(call_lines & self.unknown)
        if ai_hit:
            anchor, in_unknown = ai_hit[0], False  # 첫 AI 교차 라인을 표시 anchor 로(codex S1 r2)
        elif unk_hit:
            anchor, in_unknown = unk_hit[0], True
        else:
            return

        lineno = node.lineno  # call 시작(=sink_span/S2 overlap 기준)
        col = node.col_offset + 1
        end_line = getattr(node, "end_lineno", None) or lineno
        end_col = (getattr(node, "end_col_offset", None) + 1
                   if getattr(node, "end_col_offset", None) is not None else None)
        # enclosing 함수 1회 산출 — source_nearby + 선행변수 dynamic-string 추적 공용(codex S1 r5 상).
        fn = next((n for n in reversed(self.funcstack)
                   if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))), None)
        dynamic_names = _dynamic_assigned_names(fn)
        # codex b819cwlvl: 한 call span 이 여러 sink(generic dbapi + sqlite3/aiosqlite)에 매칭돼도
        # **후보 1개**여야 한다(중복 인플레이션 금지). 조건충족 sink 를 capability 별로 묶어 대표 1개만
        # 선택(specific-wins)하고, dedup 키에서 sink.id 를 뺀다(=같은 call span+capability → 후보 1).
        qualifying = [(s, sg) for s, sg in cands
                      if _conditions_met(node, s.required_conditions, self.imports, dynamic_names)]
        by_cap: dict[str, tuple] = {}
        for sink, sig in qualifying:
            chosen = by_cap.get(sink.capability_id)
            if chosen is None or _sink_more_specific((sink, sig), chosen, duck):
                by_cap[sink.capability_id] = (sink, sig)
        for sink, _sig in by_cap.values():
            # dedup 키: (file,start_line,start_col,end_line,end_col,capability) — sink.id 제외(중복 차단).
            key = f"{self.fd.file}:{lineno}:{col}:{end_line}:{end_col}:{sink.capability_id}"
            if key in self.seen:
                continue
            self.seen.add(key)
            span = LocationSpan(  # sink_span = call 전체(S2 exact-overlap 기준)
                file=self.fd.file, start_line=lineno, end_line=end_line,
                start_col=col, end_col=end_col,
            )
            snippet = self.clines[anchor - 1].strip() if 1 <= anchor <= len(self.clines) else ""
            if in_unknown:
                self.res.unknown_sink_candidate_count += 1
                self.res.candidate_inventory.append(CandidateInventoryItem(
                    candidate_id=key, candidate_type=CandidateType.STATIC_PATTERN_RISK,
                    file=self.fd.file, line=anchor, sink_span=span,
                    capability_id=sink.capability_id, sink_spec_id=sink.id,
                    reason=f"KB sink {sink.id} on UNKNOWN-attributed line ({sink.cwe})",
                    ai_attribution_state=AttributionState.UNKNOWN_DUE_TO_HISTORY_LOSS,
                ))
                continue
            # AI-귀속: 원본 attribution 참조(codex S1 중)
            refs = [self.attr_by_line[ln] for ln in sorted(call_lines)
                    if ln in self.attr_by_line and self.attr_by_line[ln].is_ai]
            state = (AttributionState.CONFIRMED_AI
                     if any(r.attribution_state == AttributionState.CONFIRMED_AI for r in refs)
                     else AttributionState.PROBABLE_AI)
            # source_nearby = route handler 또는 request 참조(codex S1 중: param 만으론 taint 안 함)
            source_nearby = bool(fn and (_route_handler(fn) or _has_request_ref(fn)))
            # codex S1 r4: recall-first — duck-matched(.execute)도 route 면 TAINT 후보로(강등 철회).
            # provenance 없는 비-SQL execute(template.execute 등)는 S2 CodeQL evidence 가 거른다.
            ctype = CandidateType.TAINT_PATH if source_nearby else CandidateType.STATIC_PATTERN_RISK
            risk = 0.4 if duck else 0.5  # duck 은 약간 낮은 신뢰(여전히 후보)
            cand = FindingCandidate(
                candidate_id=key, candidate_type=ctype, track=_TRACK[ctype], repo=self.repo,
                commit_sha=self.scope.head_sha, file=self.fd.file, sink_loc=f"{self.fd.file}:{anchor}",
                sink_span=span, code_snippet=snippet, capability_id=sink.capability_id,
                sink_spec_id=sink.id, source_nearby=source_nearby,
                candidate_source=CandidateSource.AST, evidence_kind=_EVIDENCE[ctype],
                risk_score=risk, recall_reason=f"KB sink {sink.id} ({sink.cwe})",
                ai_attribution_refs=refs,
            )
            self.res.candidates.append(cand)
            if ctype == CandidateType.TAINT_PATH:
                self.res.taint_candidates.append(cand)
            else:
                self.res.candidate_inventory.append(CandidateInventoryItem(
                    candidate_id=key, candidate_type=ctype, file=self.fd.file, line=anchor,
                    sink_span=span, capability_id=sink.capability_id, sink_spec_id=sink.id,
                    reason=f"static pattern risk: {sink.id} ({sink.cwe})",
                    ai_attribution_state=state,
                ))
