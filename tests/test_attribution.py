"""S0 귀속 단위 테스트."""

from __future__ import annotations

from pathlib import Path

import pytest

from auditai.attribution import (
    AttributionConfig,
    BlamePorcelainError,
    GitError,
    _CommitMeta,
    _parse_blame_porcelain,
    attribute_file,
    attribute_scope,
    classify_commit,
    is_excluded,
    normalize_path,
    summarize,
)
from auditai.contracts import AttributionState, LossMode


def _attrs(repo: Path, path: str):
    res = attribute_file(str(repo), "HEAD", path)
    assert res.status == "ok", f"unexpected status {res.status} ({res.error})"
    return res.attributions


def _state_at(attrs, line: int) -> AttributionState:
    for a in attrs:
        if a.line_range[0] <= line <= a.line_range[1]:
            return a.attribution_state
    raise AssertionError(f"line {line} not attributed")


def test_attribution_states_per_line(git_repo: Path):
    attrs = _attrs(git_repo, "app.py")
    assert _state_at(attrs, 1) == AttributionState.HUMAN
    assert _state_at(attrs, 3) == AttributionState.HUMAN
    assert _state_at(attrs, 4) == AttributionState.CONFIRMED_AI  # author=Claude(anthropic)
    assert _state_at(attrs, 5) == AttributionState.CONFIRMED_AI
    assert _state_at(attrs, 6) == AttributionState.PROBABLE_AI  # Co-authored-by 트레일러
    assert _state_at(attrs, 7) == AttributionState.PROBABLE_AI
    assert _state_at(attrs, 8) == AttributionState.CONFIRMED_AI  # claude[bot]
    assert _state_at(attrs, 9) == AttributionState.HUMAN  # subject 'claude' 언급만


def test_workflow_mention_is_not_ai(git_repo: Path):
    attrs = _attrs(git_repo, "app.py")
    assert _state_at(attrs, 9) == AttributionState.HUMAN


def test_confidence_buckets(git_repo: Path):
    attrs = _attrs(git_repo, "app.py")
    conf = {a.line_range[0]: a.ai_confidence for a in attrs}
    assert conf[4] == 1.0
    assert conf[6] == 0.6
    assert conf[1] == 0.0


# --- tiered classification (codex Q8) -------------------------------------- #
def _meta(an, ae, cn=None, ce=None, body=""):
    cn = cn if cn is not None else an
    ce = ce if ce is not None else ae
    return _CommitMeta("sha", an, ae, cn, ce, body)


def test_anthropic_email_is_confirmed():
    st, _ = classify_commit(_meta("Claude", "noreply@anthropic.com"), AttributionConfig())
    assert st == AttributionState.CONFIRMED_AI


def test_claude_bot_is_confirmed():
    st, _ = classify_commit(
        _meta("claude[bot]", "41898282+claude[bot]@users.noreply.github.com"),
        AttributionConfig(),
    )
    assert st == AttributionState.CONFIRMED_AI


def test_name_only_claude_human_email_is_probable():
    """사람 이름 'Claude' + 비-anthropic 이메일 → confirmed 오탐 방지, probable 로 강등."""
    st, _ = classify_commit(_meta("Claude", "claude.human@example.com"), AttributionConfig())
    assert st == AttributionState.PROBABLE_AI


def test_coauthor_trailer_is_probable():
    body = "feat: x\n\nCo-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>\n"
    st, _ = classify_commit(_meta("Mikyo", "m@example.com", body=body), AttributionConfig())
    assert st == AttributionState.PROBABLE_AI


def test_claudia_is_not_ai():
    st, _ = classify_commit(_meta("Claudia Smith", "claudia@example.com"), AttributionConfig())
    assert st == AttributionState.HUMAN


# --- exclusion / paths ----------------------------------------------------- #
def test_generated_file_excluded(git_repo: Path):
    res = attribute_file(str(git_repo), "HEAD", "pkg/__generated__/api.py")
    assert res.status == "excluded"
    assert res.excluded_reason == LossMode.GENERATED
    assert res.attributions == []


def test_vendored_excluded():
    cfg = AttributionConfig()
    assert is_excluded("a/node_modules/b.py", cfg) == LossMode.VENDORED
    assert is_excluded("src/app.py", cfg) is None


def test_path_normalization_keeps_dot_dirs():
    assert normalize_path("a\\b\\c.py") == "a/b/c.py"
    assert normalize_path("./a/b.py") == "a/b.py"
    assert normalize_path(".github/workflows/x.yml") == ".github/workflows/x.yml"  # codex Q3


def test_dotdir_file_attributed(git_repo: Path):
    res = attribute_file(str(git_repo), "HEAD", ".github/workflows/ci.yml")
    assert res.status == "ok"
    assert res.file == ".github/workflows/ci.yml"


# --- status semantics (codex Q1: 침묵 FN 제거) ----------------------------- #
def test_missing_file_status(git_repo: Path):
    res = attribute_file(str(git_repo), "HEAD", "does_not_exist.py")
    assert res.status == "missing"
    assert res.attributions == []


def test_invalid_rev_raises_in_strict(git_repo: Path):
    """codex C2-Q1: invalid rev 를 missing 으로 접지 않고 예외(침묵 FN 방지)."""
    with pytest.raises(GitError):
        attribute_file(str(git_repo), "deadbeefdeadbeef", "app.py")  # strict=True


def test_invalid_rev_is_error_status_non_strict(git_repo: Path):
    res = attribute_file(str(git_repo), "deadbeefdeadbeef", "app.py", strict=False)
    assert res.status == "error"
    assert res.error


def test_scope_surfaces_errors(git_repo: Path):
    """codex C2-Q1b: scope 가 error 를 status 로 노출, has_errors 로 무시 방지."""
    results = attribute_scope(str(git_repo), "deadbeefdeadbeef", ["app.py"])
    stats = summarize(results)
    assert stats.has_errors
    assert "app.py" in stats.error_files


def test_malformed_porcelain_raises():
    """codex Q4/C2-Q7: header 없는 content 라인 → desync 감지."""
    with pytest.raises(BlamePorcelainError):
        _parse_blame_porcelain("\tcode line without preceding header\n", "app.py")


# --- file move (codex Q7) -------------------------------------------------- #
def test_file_move_loss_mode(moved_repo: Path):
    res = attribute_file(str(moved_repo), "HEAD", "renamed.py")
    assert res.status == "ok"
    assert any(LossMode.FILE_MOVE in a.loss_modes for a in res.attributions)


# --- summary / scope ------------------------------------------------------- #
def test_summary_stats(git_repo: Path):
    results = attribute_scope(str(git_repo), "HEAD", ["app.py"])
    stats = summarize(results)
    assert stats.total_lines == 9
    assert stats.confirmed_ai_lines == 3  # L4,L5,L8
    assert stats.probable_ai_lines == 2  # L6,L7
    assert stats.human_lines == 4  # L1-3, L9
    assert stats.ai_lines == 5
    assert stats.ok_files == 1


def test_scope_collects_statuses(git_repo: Path):
    results = attribute_scope(
        str(git_repo),
        "HEAD",
        ["app.py", "pkg/__generated__/api.py", "nope.py"],
    )
    stats = summarize(results)
    assert "pkg/__generated__/api.py" in stats.excluded_files
    assert "nope.py" in stats.missing_files
