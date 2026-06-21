"""S0 — AI 라인 귀속 (청사진 docs/03-blueprint.md §5 Stage 0).

`git blame --line-porcelain` 로 line->commit 매핑 후, commit 메타(author/committer/
Co-authored-by 트레일러)로 AI 여부를 분류한다.

사용자 결정(2026-06-19): confirmed_ai + probable_ai 둘 다 분석 대상(저신뢰 버킷 분리).
등급(codex Q8 tiered):
- confirmed_ai : author/committer identity 가 Claude — anthropic 이메일(noreply@anthropic.com)
                 또는 claude[bot] 봇 계정. (가장 안정적 키)
- probable_ai  : (a) author/committer 이름에 'claude' 가 있으나 위 강한 신호는 아님(저신뢰),
                 또는 (b) Co-authored-by 트레일러에 Claude (anthropic 이메일/이름).
- human        : AI 신호 없음 (subject 에 'claude' 언급만 있는 워크플로 커밋 포함).

codex 보존 계약:
- file 경로는 forward-slash repo-relative 로 정규화(bp1-4). './' prefix 만 제거(Q3).
- git 실패를 빈 결과로 삼키지 않음(Q1): FileAttributionResult.status 로 구분, strict 시 예외.
- blame porcelain 파서는 stale state 오염 방지(Q4): content 라인 전 header 강제, SHA-1/256.
- provenance 손실(loss_modes)은 숨기지 않고 노출. 탐지 가능한 file_move/generated/vendored 만
  기록, squash/rebase/reformat 등은 미탐지 잔여 FN 리스크(문서화).
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from fnmatch import fnmatch

from .contracts import AILineAttribution, AttributionState, LossMode

_ANTHROPIC_EMAIL = "noreply@anthropic.com"
_CLAUDE_NAME = re.compile(r"\bclaude\b", re.IGNORECASE)
_CLAUDE_BOT = re.compile(r"claude\[bot\]", re.IGNORECASE)
_COAUTHOR = re.compile(r"^\s*co-authored-by:\s*(?P<name>.*?)\s*<(?P<email>[^>]*)>", re.I | re.M)
_BLAME_HEADER = re.compile(r"^(?P<sha>[0-9a-f]{40,64})(?: \d+){2,3}$")

_GIT_TIMEOUT = 60  # seconds (codex Q10)

_DEFAULT_GENERATED = (
    "*/__generated__/*",
    "*_pb2.py",
    "*.pb.py",
    "*/migrations/*",
)
_DEFAULT_VENDORED = (
    "*/node_modules/*",
    "*/vendor/*",
    "*/.venv/*",
    "*/site-packages/*",
    "*/dist/*",
    "*/build/*",
)


@dataclass(frozen=True)
class AttributionConfig:
    anthropic_email: str = _ANTHROPIC_EMAIL
    generated_globs: tuple[str, ...] = _DEFAULT_GENERATED
    vendored_globs: tuple[str, ...] = _DEFAULT_VENDORED
    confirmed_confidence: float = 1.0
    probable_confidence: float = 0.6


@dataclass
class _CommitMeta:
    sha: str
    author_name: str
    author_email: str
    committer_name: str
    committer_email: str
    body: str


@dataclass
class _BlameLine:
    sha: str
    final_line: int
    filename: str
    moved: bool


@dataclass
class FileAttributionResult:
    """파일 단위 귀속 결과 (codex Q1: 침묵 FN 제거 — 상태를 명시 구분)."""

    file: str
    status: str  # "ok" | "excluded" | "missing" | "error"
    attributions: list[AILineAttribution] = field(default_factory=list)
    excluded_reason: LossMode | None = None
    error: str | None = None


class GitError(RuntimeError):
    pass


class BlamePorcelainError(RuntimeError):
    pass


# --------------------------------------------------------------------------- #
# git helpers
# --------------------------------------------------------------------------- #
def _git(repo: str, *args: str) -> str:
    try:
        proc = subprocess.run(
            ["git", "-C", repo, *args],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=_GIT_TIMEOUT,
        )
    except subprocess.TimeoutExpired as e:
        raise GitError(f"git {' '.join(args)} timed out after {_GIT_TIMEOUT}s") from e
    if proc.returncode != 0:
        raise GitError(f"git {' '.join(args)} failed: {proc.stderr.strip()}")
    return proc.stdout


def _verify_rev(repo: str, rev: str) -> None:
    """rev 가 실제 커밋인지 검증 (codex C2-Q1: invalid rev 를 missing 으로 접지 않음)."""
    try:
        proc = subprocess.run(
            ["git", "-C", repo, "rev-parse", "--verify", "--quiet", f"{rev}^{{commit}}"],
            capture_output=True,
            text=True,
            timeout=_GIT_TIMEOUT,
        )
    except subprocess.TimeoutExpired as e:
        raise GitError(f"git rev-parse timed out for rev {rev}") from e
    if proc.returncode != 0:
        raise GitError(f"invalid rev: {rev!r}")


def _path_exists_at_rev(repo: str, rev: str, norm: str) -> bool:
    """해당 rev 에 path 가 존재하는지. rev 자체는 _verify_rev 로 먼저 검증되어 있어야 한다."""
    try:
        proc = subprocess.run(
            ["git", "-C", repo, "cat-file", "-e", f"{rev}:{norm}"],
            capture_output=True,
            text=True,
            timeout=_GIT_TIMEOUT,
        )
    except subprocess.TimeoutExpired as e:
        raise GitError(f"git cat-file timed out for {rev}:{norm}") from e
    return proc.returncode == 0


def normalize_path(path: str) -> str:
    """OS 경로를 forward-slash repo-relative 로 정규화 (codex bp1-4/Q3).

    './' prefix 만 제거한다. 선행 '.' 또는 '/' 를 무차별 제거하지 않음
    (예: '.github/x' 는 그대로 유지).
    """
    p = path.replace("\\", "/")
    if p.startswith("./"):
        p = p[2:]
    return p


# --------------------------------------------------------------------------- #
# commit classification (tiered — codex Q8)
# --------------------------------------------------------------------------- #
def _is_confirmed_identity(name: str, email: str, cfg: AttributionConfig) -> bool:
    """강한 AI 신호: anthropic 이메일 또는 claude[bot] 봇 계정."""
    if (email or "").strip().lower() == cfg.anthropic_email:
        return True
    return bool(_CLAUDE_BOT.search(name or ""))


def _has_claude_name(name: str) -> bool:
    return bool(_CLAUDE_NAME.search(name or ""))


def classify_commit(
    meta: _CommitMeta, cfg: AttributionConfig
) -> tuple[AttributionState, float]:
    identities = [
        (meta.author_name, meta.author_email),
        (meta.committer_name, meta.committer_email),
    ]
    # 1) confirmed: author/committer 가 강한 AI 신호
    for nm, em in identities:
        if _is_confirmed_identity(nm, em, cfg):
            return AttributionState.CONFIRMED_AI, cfg.confirmed_confidence
    # 2) probable: author/committer 이름에 'claude' (강한 신호 아님 — 저신뢰)
    for nm, _em in identities:
        if _has_claude_name(nm):
            return AttributionState.PROBABLE_AI, cfg.probable_confidence
    # 3) probable: Co-authored-by 트레일러에 Claude
    for m in _COAUTHOR.finditer(meta.body or ""):
        if _is_confirmed_identity(m.group("name"), m.group("email"), cfg) or _has_claude_name(
            m.group("name")
        ):
            return AttributionState.PROBABLE_AI, cfg.probable_confidence
    return AttributionState.HUMAN, 0.0


_META_FMT = "%H%x00%an%x00%ae%x00%cn%x00%ce%x00%B"


def _get_commit_meta(repo: str, sha: str, cache: dict[str, _CommitMeta]) -> _CommitMeta:
    if sha in cache:
        return cache[sha]
    out = _git(repo, "show", "-s", f"--format={_META_FMT}", sha)
    parts = out.split("\x00")
    meta = _CommitMeta(
        sha=parts[0].strip(),
        author_name=parts[1] if len(parts) > 1 else "",
        author_email=parts[2] if len(parts) > 2 else "",
        committer_name=parts[3] if len(parts) > 3 else "",
        committer_email=parts[4] if len(parts) > 4 else "",
        body=parts[5] if len(parts) > 5 else "",
    )
    cache[sha] = meta
    return meta


# --------------------------------------------------------------------------- #
# blame parsing (codex Q4: header 강제, stale state 방지)
# --------------------------------------------------------------------------- #
def _parse_blame_porcelain(output: str, queried: str) -> list[_BlameLine]:
    lines: list[_BlameLine] = []
    cur_sha: str | None = None
    cur_final = 0
    cur_filename = queried
    cur_moved = False
    header_seen = False

    for raw in output.splitlines():
        m = _BLAME_HEADER.match(raw)
        if m:
            cur_sha = m.group("sha")
            cur_final = int(raw.split()[2])
            cur_filename = queried
            cur_moved = False
            header_seen = True
            continue
        if raw.startswith("filename "):
            cur_filename = raw[len("filename ") :].strip()
            if normalize_path(cur_filename) != queried:
                cur_moved = True
            continue
        if raw.startswith("previous "):
            cur_moved = True
            continue
        if raw.startswith("\t"):
            if not header_seen or cur_sha is None:
                raise BlamePorcelainError(
                    "content line without a preceding valid header (parser desync)"
                )
            lines.append(
                _BlameLine(
                    sha=cur_sha,
                    final_line=cur_final,
                    filename=normalize_path(cur_filename),
                    moved=cur_moved,
                )
            )
            cur_sha = None  # 다음 entry 까지 stale 재사용 방지
            header_seen = False
            continue
    return lines


# --------------------------------------------------------------------------- #
# public API
# --------------------------------------------------------------------------- #
def is_excluded(path: str, cfg: AttributionConfig) -> LossMode | None:
    norm = normalize_path(path)
    if any(fnmatch(norm, g) for g in cfg.generated_globs):
        return LossMode.GENERATED
    if any(fnmatch(norm, g) for g in cfg.vendored_globs):
        return LossMode.VENDORED
    return None


def _group(rows: list[tuple[int, str, AttributionState, float, tuple[LossMode, ...]]], norm: str):
    grouped: list[AILineAttribution] = []
    i = 0
    while i < len(rows):
        j = i
        while (
            j + 1 < len(rows)
            and rows[j + 1][0] == rows[j][0] + 1
            and rows[j + 1][1] == rows[i][1]
            and rows[j + 1][2] == rows[i][2]
            and rows[j + 1][4] == rows[i][4]
        ):
            j += 1
        grouped.append(
            AILineAttribution(
                file=norm,
                line_range=(rows[i][0], rows[j][0]),
                commit=rows[i][1],
                attribution_state=rows[i][2],
                ai_confidence=rows[i][3],
                label_source="blame",
                loss_modes=list(rows[i][4]),
            )
        )
        i = j + 1
    return grouped


def attribute_file(
    repo: str,
    rev: str,
    path: str,
    cfg: AttributionConfig | None = None,
    *,
    strict: bool = True,
) -> FileAttributionResult:
    """단일 파일 귀속. status 로 ok/excluded/missing/error 를 구분(codex Q1).

    strict=True(기본): git/parse 실패 시 예외(침묵 FN 방지).
    strict=False: 실패를 status='error' 로 담아 반환(scope 일괄 처리용).
    excluded/missing 은 항상 예외 없이 status 로 반환.
    """
    cfg = cfg or AttributionConfig()
    norm = normalize_path(path)

    excl = is_excluded(norm, cfg)
    if excl is not None:
        return FileAttributionResult(norm, "excluded", excluded_reason=excl)

    # 모든 git 단계(rev 검증/존재확인/blame/parse/meta lookup)를 한 번에 감싼다
    # (codex C2-Q1b: strict=False 에서 어느 단계 실패든 error status 로 흡수).
    try:
        _verify_rev(repo, rev)  # invalid rev -> GitError (missing 으로 접지 않음, C2-Q1)
        if not _path_exists_at_rev(repo, rev, norm):
            return FileAttributionResult(norm, "missing")
        out = _git(repo, "blame", "--line-porcelain", rev, "--", norm)
        blame = _parse_blame_porcelain(out, norm)
        if not blame:
            return FileAttributionResult(norm, "ok", attributions=[])
        meta_cache: dict[str, _CommitMeta] = {}
        rows: list[tuple[int, str, AttributionState, float, tuple[LossMode, ...]]] = []
        for bl in blame:
            meta = _get_commit_meta(repo, bl.sha, meta_cache)
            state, conf = classify_commit(meta, cfg)
            loss = (LossMode.FILE_MOVE,) if bl.moved else ()
            rows.append((bl.final_line, bl.sha, state, conf, loss))
    except (GitError, BlamePorcelainError) as e:
        if strict:
            raise
        return FileAttributionResult(norm, "error", error=str(e))

    rows.sort(key=lambda r: r[0])
    return FileAttributionResult(norm, "ok", attributions=_group(rows, norm))


def attribute_scope(
    repo: str,
    rev: str,
    files: list[str],
    cfg: AttributionConfig | None = None,
) -> dict[str, FileAttributionResult]:
    """여러 파일 귀속. 한 파일 실패가 전체를 멈추지 않도록 strict=False 로 결과 수집."""
    cfg = cfg or AttributionConfig()
    out: dict[str, FileAttributionResult] = {}
    for f in files:
        res = attribute_file(repo, rev, f, cfg, strict=False)
        out[res.file] = res
    return out


@dataclass
class AttributionStats:
    total_lines: int = 0
    confirmed_ai_lines: int = 0
    probable_ai_lines: int = 0
    human_lines: int = 0
    moved_lines: int = 0
    ok_files: int = 0
    excluded_files: list[str] = field(default_factory=list)
    missing_files: list[str] = field(default_factory=list)
    error_files: list[str] = field(default_factory=list)

    @property
    def ai_lines(self) -> int:
        return self.confirmed_ai_lines + self.probable_ai_lines

    @property
    def has_errors(self) -> bool:
        """codex C2-Q1b: 호출자가 error 를 무시해 침묵 FN 으로 빠지지 않도록 노출."""
        return bool(self.error_files)


def summarize(results: dict[str, FileAttributionResult]) -> AttributionStats:
    """T2 평가용 집계 (귀속 분포 + 손실/상태 신호)."""
    stats = AttributionStats()
    for res in results.values():
        if res.status == "excluded":
            stats.excluded_files.append(res.file)
            continue
        if res.status == "missing":
            stats.missing_files.append(res.file)
            continue
        if res.status == "error":
            stats.error_files.append(res.file)
            continue
        stats.ok_files += 1
        for a in res.attributions:
            n = a.line_range[1] - a.line_range[0] + 1
            stats.total_lines += n
            if a.attribution_state == AttributionState.CONFIRMED_AI:
                stats.confirmed_ai_lines += n
            elif a.attribution_state == AttributionState.PROBABLE_AI:
                stats.probable_ai_lines += n
            else:
                stats.human_lines += n
            if LossMode.FILE_MOVE in a.loss_modes:
                stats.moved_lines += n
    return stats
