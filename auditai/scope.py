"""S0 — PR-diff primary scope selection (계획 docs/05-p0-blockers.md §2).

primary source = `git diff <merge-base>..<head>` (blame 아님). blame 은 살아있는 라인만
보므로 삭제된 보안 가드/validator/authz 를 못 본다. 여기서 added/deleted hunk 를 구조화하고,
삭제 라인의 귀속(어느 commit 이 지웠는가)을 정직하게 결정한다.

codex(scope1) 반영: 파서는 in_hunk 상태기계(헤더/본문 구분), 경로는 ---/+++ 라인에서,
삭제 귀속은 `git log -S` 결과를 **실제 삭제 검증**(git show)한 뒤에만 commit_walk_unique,
squash 휴리스틱(다중 Co-authored-by)으로 강등, 실패는 UNKNOWN(약한 귀속과 구분).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field as _dc_field

from pydantic import Field

from .attribution import (
    AttributionConfig,
    AttributionState,
    GitError,
    _COAUTHOR,
    _CommitMeta,
    _get_commit_meta,
    _git,
    attribute_scope,
    classify_commit,
    normalize_path,
)
from .contracts import (
    AILineAttribution,
    DeletionAttribution,
    DeletionAttributionSource,
    StrictModel,
)

_HUNK_RE = re.compile(r"^@@ -(?P<o>\d+)(?:,\d+)? \+(?P<n>\d+)(?:,\d+)? @@")


# --------------------------------------------------------------------------- #
# diff 데이터 모델 (artifact 직렬화)
# --------------------------------------------------------------------------- #
class DiffLine(StrictModel):
    change: str  # "added" | "deleted"
    old_lineno: int | None = None
    new_lineno: int | None = None
    text: str


class FileDiff(StrictModel):
    file: str  # 신규 경로 (forward-slash repo-relative). 삭제 파일이면 old 경로.
    old_file: str | None = None
    is_rename: bool = False
    is_delete: bool = False
    is_binary: bool = False
    added_lines: list[DiffLine] = Field(default_factory=list)
    deleted_lines: list[DiffLine] = Field(default_factory=list)


class DiffScope(StrictModel):
    repo: str
    base_sha: str
    head_sha: str
    merge_base: str
    pr_commit_count: int
    files: list[FileDiff] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# git helpers
# --------------------------------------------------------------------------- #
def _rev(repo: str, ref: str) -> str:
    return _git(repo, "rev-parse", "--verify", f"{ref}^{{commit}}").strip()


def compute_merge_base(repo: str, base: str, head: str) -> str:
    return _git(repo, "merge-base", base, head).strip()


def pr_commits(repo: str, merge_base: str, head: str) -> list[str]:
    out = _git(repo, "rev-list", f"{merge_base}..{head}").strip()
    return out.split() if out else []


def _strip_ab(path: str) -> str:
    """'a/x'|'b/x' → 'x'. trailing tab-timestamp 제거, 따옴표 기본 제거."""
    p = path.split("\t", 1)[0].strip()
    if len(p) >= 2 and p[0] == '"' and p[-1] == '"':
        p = p[1:-1]  # 기본 unquote (c-escape 완전처리는 아님 — 제한 문서화)
    if p.startswith(("a/", "b/")):
        p = p[2:]
    return normalize_path(p)


# --------------------------------------------------------------------------- #
# unified diff 파서 (in_hunk 상태기계 — codex scope1 P1)
# --------------------------------------------------------------------------- #
def parse_unified_diff(text: str) -> list[FileDiff]:
    files: list[FileDiff] = []
    cur: FileDiff | None = None
    in_hunk = False
    old_no = new_no = 0

    for line in text.splitlines():
        if line.startswith("diff --git "):
            if cur is not None:
                files.append(cur)
            cur = FileDiff(file="")
            in_hunk = False
            old_no = new_no = 0
            continue
        if cur is None:
            continue

        if not in_hunk:
            # --- 파일 헤더 영역 ---
            if line.startswith("rename from "):
                cur.old_file = normalize_path(line[len("rename from ") :])
                cur.is_rename = True
            elif line.startswith("rename to "):
                cur.file = normalize_path(line[len("rename to ") :])
                cur.is_rename = True
            elif line.startswith("deleted file mode"):
                cur.is_delete = True
            elif line.startswith("Binary files") or line.startswith("GIT binary patch"):
                cur.is_binary = True
            elif line.startswith("--- "):
                p = line[4:].strip()
                cur.old_file = None if p == "/dev/null" else _strip_ab(p)
            elif line.startswith("+++ "):
                p = line[4:].strip()
                cur.file = "" if p == "/dev/null" else _strip_ab(p)
            else:
                hm = _HUNK_RE.match(line)
                if hm:
                    in_hunk = True
                    old_no = int(hm.group("o"))
                    new_no = int(hm.group("n"))
            continue

        # --- hunk 본문 ---
        hm = _HUNK_RE.match(line)
        if hm:
            old_no = int(hm.group("o"))
            new_no = int(hm.group("n"))
        elif line.startswith("+"):
            cur.added_lines.append(DiffLine(change="added", new_lineno=new_no, text=line[1:]))
            new_no += 1
        elif line.startswith("-"):
            cur.deleted_lines.append(DiffLine(change="deleted", old_lineno=old_no, text=line[1:]))
            old_no += 1
        elif line.startswith(" "):
            old_no += 1
            new_no += 1
        # '\ No newline...' 및 기타는 무시

    if cur is not None:
        files.append(cur)

    # 삭제 파일(+++ /dev/null)이면 file 이 빈 문자열 → old 경로로 보정
    for f in files:
        if not f.file and f.old_file:
            f.file = f.old_file
            f.is_delete = True
    return files


def build_diff_scope(repo: str, base: str, head: str) -> DiffScope:
    base_sha = _rev(repo, base)
    head_sha = _rev(repo, head)
    mb = compute_merge_base(repo, base_sha, head_sha)
    # quotePath=false 로 경로 quoting 최소화
    diff_text = _git(repo, "-c", "core.quotePath=false", "diff", "--find-renames", f"{mb}..{head_sha}")
    files = parse_unified_diff(diff_text)
    return DiffScope(
        repo=repo,
        base_sha=base_sha,
        head_sha=head_sha,
        merge_base=mb,
        pr_commit_count=len(pr_commits(repo, mb, head_sha)),
        files=files,
    )


# --------------------------------------------------------------------------- #
# 삭제 귀속 (어느 commit 이 이 라인을 지웠는가 — 검증 포함)
# --------------------------------------------------------------------------- #
# weak source: confirmed 로 올리지 않는다 (단, commit_walk_unique 는 실제 삭제 검증 후라 strong)
_WEAK_SOURCES = {
    DeletionAttributionSource.PR_METADATA_ONLY,
    DeletionAttributionSource.UNKNOWN_DUE_TO_HISTORY_LOSS,
}


def _map_state(
    state: AttributionState, source: DeletionAttributionSource
) -> DeletionAttribution | None:
    weak = source in _WEAK_SOURCES
    if state == AttributionState.CONFIRMED_AI:
        return DeletionAttribution.PROBABLE_AI_FROM_PR_METADATA if weak else DeletionAttribution.CONFIRMED_AI
    if state == AttributionState.PROBABLE_AI:
        return DeletionAttribution.PROBABLE_AI_FROM_PR_METADATA if weak else DeletionAttribution.PROBABLE_AI
    return None  # HUMAN/불명 → 호출부에서 제외


def _looks_squashed(meta: _CommitMeta) -> bool:
    """다중 Co-authored-by 트레일러 = GitHub squash merge 시그니처 (codex scope1 P1-5)."""
    emails = {m.group("email").strip().lower() for m in _COAUTHOR.finditer(meta.body or "")}
    return len(emails) >= 2 or "squash" in (meta.body or "").lower()


def _commit_deletes_line(repo: str, sha: str, file: str, text: str) -> bool:
    """commit 이 실제로 그 라인을 삭제했는지 검증 (codex scope1 P1-4: log -S 과신 방지)."""
    try:
        out = _git(repo, "show", "--format=", "--unified=0", sha, "--", file)
    except GitError:
        return False
    target = "-" + text
    return any(ln == target for ln in out.splitlines())


_STRONG_SOURCES = {
    DeletionAttributionSource.SINGLE_COMMIT_PR,
    DeletionAttributionSource.COMMIT_WALK_UNIQUE,
}


def _attr_from_commit(
    repo: str, commit: str, cfg: AttributionConfig, cache: dict,
    source: DeletionAttributionSource, signals: list[str],
) -> tuple[DeletionAttribution | None, DeletionAttributionSource, list[str]]:
    meta = _get_commit_meta(repo, commit, cache)
    # squash 시그니처면 strong source 도 강등 (line-level authorship 불확실)
    if source in _STRONG_SOURCES and _looks_squashed(meta):
        source = DeletionAttributionSource.PR_METADATA_ONLY
        signals = signals + ["possible_squash_multi_coauthor"]
    state, _ = classify_commit(meta, cfg)
    mapped = _map_state(state, source)
    if mapped is None:
        return None, source, signals + [f"author={meta.author_email}"]
    return mapped, source, signals + [f"author={meta.author_email}"]


def attribute_addition(
    repo: str,
    head_sha: str,
    file: str,
    new_lineno: int,
    cfg: AttributionConfig | None = None,
    _cache: dict[str, _CommitMeta] | None = None,
) -> tuple[DeletionAttribution | None, DeletionAttributionSource, list[str]]:
    """추가/변경된 라인 귀속 — 라인이 head 에 존재하므로 blame 으로 추가 commit 특정
    (codex scope2: 약화는 삭제 로직이 아니라 추가 라인 귀속이어야 함)."""
    cfg = cfg or AttributionConfig()
    cache = _cache if _cache is not None else {}
    try:
        out = _git(
            repo, "blame", "-L", f"{new_lineno},{new_lineno}", "--porcelain", head_sha, "--", file
        )
    except GitError:
        return _attr_from_pr_metadata(
            repo, head_sha, cfg, cache,
            DeletionAttributionSource.UNKNOWN_DUE_TO_HISTORY_LOSS, ["blame_failed"],
        )
    first = out.splitlines()[0].split() if out.strip() else []
    if not first:
        return _attr_from_pr_metadata(
            repo, head_sha, cfg, cache,
            DeletionAttributionSource.UNKNOWN_DUE_TO_HISTORY_LOSS, ["blame_empty"],
        )
    sha = first[0]
    return _attr_from_commit(
        repo, sha, cfg, cache,
        DeletionAttributionSource.COMMIT_WALK_UNIQUE, [f"blame_commit={sha[:10]}"],
    )


def _attr_from_pr_metadata(
    repo: str, head_sha: str, cfg: AttributionConfig, cache: dict,
    source: DeletionAttributionSource, signals: list[str],
) -> tuple[DeletionAttribution | None, DeletionAttributionSource, list[str]]:
    try:
        head_meta = _get_commit_meta(repo, head_sha, cache)
        state, _ = classify_commit(head_meta, cfg)
    except GitError:
        # 진짜 분석 실패만 UNKNOWN (codex scope3 H1)
        return DeletionAttribution.UNKNOWN_DUE_TO_HISTORY_LOSS, source, signals + ["classify_failed"]
    if state in (AttributionState.CONFIRMED_AI, AttributionState.PROBABLE_AI):
        return DeletionAttribution.PROBABLE_AI_FROM_PR_METADATA, source, signals
    return None, source, signals + ["head_human"]  # HUMAN → AI 스코프 밖 (제외)


def attribute_deletion(
    repo: str,
    merge_base: str,
    head_sha: str,
    file: str,
    deleted_text: str,
    pr_commit_shas: list[str],
    cfg: AttributionConfig | None = None,
    _cache: dict[str, _CommitMeta] | None = None,
) -> tuple[DeletionAttribution | None, DeletionAttributionSource, list[str]]:
    """삭제 라인 귀속 → (ai_attribution|None, source, signals). None = AI 스코프 밖."""
    cfg = cfg or AttributionConfig()
    cache = _cache if _cache is not None else {}

    if len(pr_commit_shas) == 1:
        return _attr_from_commit(
            repo, pr_commit_shas[0], cfg, cache,
            DeletionAttributionSource.SINGLE_COMMIT_PR, [f"commit={pr_commit_shas[0][:10]}"],
        )

    token = deleted_text.strip()
    if token:
        try:
            out = _git(repo, "log", "-S", token, "--pretty=%H", f"{merge_base}..{head_sha}", "--", file)
            shas = out.split()
        except GitError:
            return _attr_from_pr_metadata(
                repo, head_sha, cfg, cache,
                DeletionAttributionSource.UNKNOWN_DUE_TO_HISTORY_LOSS, ["log_S_failed"],
            )
        # 실제 삭제한 commit 만 (검증 — codex P1-4)
        verified = [s for s in shas if _commit_deletes_line(repo, s, file, deleted_text)]
        if len(verified) == 1:
            return _attr_from_commit(
                repo, verified[0], cfg, cache,
                DeletionAttributionSource.COMMIT_WALK_UNIQUE,
                [f"commit={verified[0][:10]}", "verified_deletion"],
            )

    # 다중/모호 → PR metadata fallback
    return _attr_from_pr_metadata(
        repo, head_sha, cfg, cache, DeletionAttributionSource.PR_METADATA_ONLY, ["ambiguous"]
    )


# --------------------------------------------------------------------------- #
# S0 — added-line AI 귀속 (codex MVP r2 M1: attribute_scope × diff added-line 교차)
# --------------------------------------------------------------------------- #
@dataclass
class AddedLineAttribution:
    """diff 의 added .py 라인을 head blame 으로 귀속한 결과.

    blame AILineAttribution(head 파일 전체)을 diff added new_lineno 와 교차해 added 라인별 상태를 정한다.
    blame status != ok(error/missing)인 파일의 added 라인은 UNKNOWN 으로 정직 표기하고 completed=False.
    (codex MVP r2 C2: UNKNOWN sink 가 clean 으로 빠지지 않도록 호출측이 unknown_lines 를 fail-closed 입력으로 사용.)
    """

    ai_lines: dict[str, set[int]] = _dc_field(default_factory=dict)       # is_ai(confirmed/probable)
    unknown_lines: dict[str, set[int]] = _dc_field(default_factory=dict)  # UNKNOWN 귀속
    human_lines: dict[str, set[int]] = _dc_field(default_factory=dict)    # human 귀속
    attributions: list[AILineAttribution] = _dc_field(default_factory=list)  # added-line 귀속(artifact/refs)
    completed: bool = True  # 모든 변경 .py 가 blame "ok"


def attribute_added_lines(
    repo: str, scope: DiffScope, cfg: AttributionConfig | None = None
) -> AddedLineAttribution:
    """S0: diff 의 added .py 라인을 head blame 으로 귀속. `scope.attribute_addition`(삭제 귀속)과 무관."""
    cfg = cfg or AttributionConfig()
    py = [
        fd for fd in scope.files
        if not fd.is_delete and not fd.is_binary and fd.file.endswith(".py") and fd.added_lines
    ]
    results = attribute_scope(repo, scope.head_sha, [fd.file for fd in py], cfg) if py else {}
    out = AddedLineAttribution()
    for fd in py:
        added = {dl.new_lineno for dl in fd.added_lines if dl.new_lineno is not None}
        if not added:
            continue
        res = results.get(fd.file)
        if res is None or res.status != "ok":
            # blame 미완(error/missing/excluded) → 그 파일 added 라인 전부 UNKNOWN(정직), completed=False
            out.completed = False
            out.unknown_lines.setdefault(fd.file, set()).update(added)
            for ln in sorted(added):
                out.attributions.append(AILineAttribution(
                    file=fd.file, line_range=(ln, ln), commit=scope.head_sha,
                    attribution_state=AttributionState.UNKNOWN_DUE_TO_HISTORY_LOSS,
                    ai_confidence=0.0, label_source="blame_unavailable",
                ))
            continue
        # blame range → added line 별 귀속 소스
        src_by_line: dict[int, AILineAttribution] = {}
        for a in res.attributions:
            lo, hi = a.line_range
            for ln in range(lo, hi + 1):
                if ln in added:
                    src_by_line[ln] = a
        for ln in sorted(added):
            src = src_by_line.get(ln)
            if src is None:  # added 라인인데 blame 이 안 덮음 → 보수적 UNKNOWN
                out.unknown_lines.setdefault(fd.file, set()).add(ln)
                out.attributions.append(AILineAttribution(
                    file=fd.file, line_range=(ln, ln), commit=scope.head_sha,
                    attribution_state=AttributionState.UNKNOWN_DUE_TO_HISTORY_LOSS,
                    ai_confidence=0.0, label_source="blame_uncovered",
                ))
                continue
            st = src.attribution_state
            if st in (AttributionState.CONFIRMED_AI, AttributionState.PROBABLE_AI):
                out.ai_lines.setdefault(fd.file, set()).add(ln)
            elif st == AttributionState.HUMAN:
                out.human_lines.setdefault(fd.file, set()).add(ln)
            else:
                out.unknown_lines.setdefault(fd.file, set()).add(ln)
            out.attributions.append(AILineAttribution(
                file=fd.file, line_range=(ln, ln), commit=src.commit,
                attribution_state=st, ai_confidence=src.ai_confidence,
                label_source="blame", loss_modes=list(src.loss_modes),
            ))
    return out
