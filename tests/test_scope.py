"""S0 PR-diff scope (scope.py) 테스트."""

from __future__ import annotations

from pathlib import Path

from auditai.contracts import AttributionState, DeletionAttribution, DeletionAttributionSource
from auditai.scope import (
    attribute_added_lines,
    attribute_deletion,
    build_diff_scope,
    compute_merge_base,
    parse_unified_diff,
    pr_commits,
)

_SAMPLE_DIFF = """diff --git a/app.py b/app.py
index 111..222 100644
--- a/app.py
+++ b/app.py
@@ -1,5 +1,3 @@
 def handler(req):
-    if not req.user.is_admin:
-        raise PermissionError
     data = req.args.get('q')
-    run(data)
+    subprocess.run(data, shell=True)
"""


def test_parse_unified_diff_added_deleted():
    files = parse_unified_diff(_SAMPLE_DIFF)
    assert len(files) == 1
    fd = files[0]
    assert fd.file == "app.py"
    deleted = [d.text for d in fd.deleted_lines]
    added = [a.text for a in fd.added_lines]
    assert "    if not req.user.is_admin:" in deleted
    assert "        raise PermissionError" in deleted
    assert "    run(data)" in deleted
    assert "    subprocess.run(data, shell=True)" in added


def test_parse_line_numbers():
    files = parse_unified_diff(_SAMPLE_DIFF)
    fd = files[0]
    # deleted 라인은 old 파일 기준 라인번호
    by_text = {d.text: d.old_lineno for d in fd.deleted_lines}
    assert by_text["    if not req.user.is_admin:"] == 2
    assert by_text["        raise PermissionError"] == 3


def test_parse_rename():
    diff = (
        "diff --git a/old.py b/new.py\n"
        "similarity index 90%\n"
        "rename from old.py\n"
        "rename to new.py\n"
        "--- a/old.py\n"
        "+++ b/new.py\n"
        "@@ -1,1 +1,1 @@\n"
        "-x = 1\n"
        "+x = 2\n"
    )
    fd = parse_unified_diff(diff)[0]
    assert fd.is_rename
    assert fd.file == "new.py"
    assert fd.old_file == "old.py"


# --- real git repo ---------------------------------------------------------- #
def test_build_diff_scope(diff_repo: Path):
    scope = build_diff_scope(str(diff_repo), "HEAD~1", "HEAD")
    assert scope.pr_commit_count == 1
    assert len(scope.files) == 1
    fd = scope.files[0]
    assert fd.file == "app.py"
    deleted = [d.text for d in fd.deleted_lines]
    assert any("is_admin" in d for d in deleted)
    assert any("PermissionError" in d for d in deleted)
    added = [a.text for a in fd.added_lines]
    assert any("subprocess.run" in a for a in added)


def test_attribute_deletion_single_commit_claude(diff_repo: Path):
    """단일 Claude commit PR → single_commit_pr + confirmed_ai."""
    mb = compute_merge_base(str(diff_repo), "HEAD~1", "HEAD")
    head = "HEAD"
    shas = pr_commits(str(diff_repo), mb, head)
    assert len(shas) == 1
    attr, source, _ = attribute_deletion(
        str(diff_repo), mb, head, "app.py", "        raise PermissionError", shas
    )
    assert source == DeletionAttributionSource.SINGLE_COMMIT_PR
    assert attr == DeletionAttribution.CONFIRMED_AI


def test_parse_inhunk_dashdash_content_not_lost():
    """codex P1: hunk 본문의 '-- '/'++' 시작 삭제/추가가 헤더로 오인되어 유실되면 안 됨."""
    diff = (
        "diff --git a/q.sql b/q.sql\n"
        "--- a/q.sql\n"
        "+++ b/q.sql\n"
        "@@ -1,2 +1,2 @@\n"
        "-- WHERE tenant_id = :tid\n"
        "+++ unsafe marker\n"
        " SELECT 1\n"
    )
    fd = parse_unified_diff(diff)[0]
    deleted = [d.text for d in fd.deleted_lines]
    added = [a.text for a in fd.added_lines]
    assert "- WHERE tenant_id = :tid" in deleted  # '-' prefix 제거된 본문
    assert "++ unsafe marker" in added


def test_parse_multi_hunk_line_numbers():
    diff = (
        "diff --git a/m.py b/m.py\n"
        "--- a/m.py\n"
        "+++ b/m.py\n"
        "@@ -1,1 +1,1 @@\n"
        "-a = 1\n"
        "+a = 2\n"
        "@@ -10,1 +10,1 @@\n"
        "-z = 9\n"
        "+z = 8\n"
    )
    fd = parse_unified_diff(diff)[0]
    dn = {d.text: d.old_lineno for d in fd.deleted_lines}
    assert dn["a = 1"] == 1
    assert dn["z = 9"] == 10


def test_parse_new_and_deleted_file():
    new = (
        "diff --git a/new.py b/new.py\n"
        "new file mode 100644\n"
        "--- /dev/null\n"
        "+++ b/new.py\n"
        "@@ -0,0 +1,1 @@\n"
        "+x = 1\n"
    )
    fd = parse_unified_diff(new)[0]
    assert fd.file == "new.py"
    assert fd.old_file is None
    assert [a.text for a in fd.added_lines] == ["x = 1"]

    deleted = (
        "diff --git a/gone.py b/gone.py\n"
        "deleted file mode 100644\n"
        "--- a/gone.py\n"
        "+++ /dev/null\n"
        "@@ -1,1 +0,0 @@\n"
        "-secret = 1\n"
    )
    fd2 = parse_unified_diff(deleted)[0]
    assert fd2.file == "gone.py"  # /dev/null → old 경로로 보정
    assert fd2.is_delete


def test_looks_squashed_multi_coauthor():
    from auditai.attribution import _CommitMeta
    from auditai.scope import _looks_squashed

    body = (
        "squash: combined\n\n"
        "Co-authored-by: Claude <noreply@anthropic.com>\n"
        "Co-authored-by: Someone <a@b.com>\n"
    )
    meta = _CommitMeta("s", "Mikyo", "m@x.com", "Mikyo", "m@x.com", body)
    assert _looks_squashed(meta)
    single = _CommitMeta("s", "Mikyo", "m@x.com", "Mikyo", "m@x.com", "feat: x\n")
    assert not _looks_squashed(single)


def test_attribute_deletion_multi_commit_verified(multi_commit_repo: Path):
    """codex P1-4: 다중 commit 에서 log -S + 실제 삭제 검증 → commit_walk_unique."""
    mb = compute_merge_base(str(multi_commit_repo), "HEAD~2", "HEAD")
    shas = pr_commits(str(multi_commit_repo), mb, "HEAD")
    assert len(shas) == 2
    attr, source, signals = attribute_deletion(
        str(multi_commit_repo), mb, "HEAD", "app.py",
        "GUARD_CHECK_TOKEN = require_admin()", shas,
    )
    assert source == DeletionAttributionSource.COMMIT_WALK_UNIQUE
    assert "verified_deletion" in signals
    assert attr == DeletionAttribution.CONFIRMED_AI  # Claude 가 삭제


def test_attribute_deletion_human_returns_none(diff_repo: Path):
    """human 삭제는 AI 스코프 밖 → None."""
    # base commit(human)을 단일 PR 로 가정
    mb = compute_merge_base(str(diff_repo), "HEAD~1", "HEAD")
    base_sha = __import__("subprocess").run(
        ["git", "-C", str(diff_repo), "rev-parse", "HEAD~1"],
        capture_output=True, text=True,
    ).stdout.strip()
    attr, _, _ = attribute_deletion(
        str(diff_repo), mb, "HEAD", "app.py", "nonexistent", [base_sha]
    )
    # base_sha 는 human author → None
    assert attr is None


# --- S0 added-line AI 귀속 (codex MVP r2 M1) -------------------------------- #
def test_attribute_added_lines_claude(diff_repo: Path):
    """diff_repo: head 가 Claude 단일 commit → added .py 라인이 is_ai(confirmed)로 귀속, completed=True."""
    scope = build_diff_scope(str(diff_repo), "HEAD~1", "HEAD")
    res = attribute_added_lines(str(diff_repo), scope)
    assert res.completed is True
    assert res.ai_lines.get("app.py")  # Claude 추가 라인 존재
    assert not res.unknown_lines  # blame ok → UNKNOWN 없음
    # 모든 added-line 귀속은 confirmed/probable
    assert all(a.attribution_state in (AttributionState.CONFIRMED_AI, AttributionState.PROBABLE_AI)
               for a in res.attributions)
    assert all(a.label_source == "blame" for a in res.attributions)


def test_attribute_added_lines_blame_error_is_unknown(diff_repo: Path, monkeypatch):
    """blame status != ok(error) → 그 파일 added 라인 전부 UNKNOWN, completed=False(fail-closed 입력)."""
    from auditai.attribution import FileAttributionResult

    def _err(repo, rev, files, cfg=None):
        return {f: FileAttributionResult(f, "error", error="blame failed") for f in files}

    monkeypatch.setattr("auditai.scope.attribute_scope", _err)
    scope = build_diff_scope(str(diff_repo), "HEAD~1", "HEAD")
    res = attribute_added_lines(str(diff_repo), scope)
    assert res.completed is False
    assert res.unknown_lines.get("app.py")
    assert not res.ai_lines
    assert all(a.attribution_state == AttributionState.UNKNOWN_DUE_TO_HISTORY_LOSS
               for a in res.attributions)


def test_attribute_added_lines_mixed(git_repo: Path):
    """git_repo: 라인별 human/claude 혼재 → ai_lines 와 human_lines 가 모두 채워질 수 있다(혼재 정직 분리)."""
    scope = build_diff_scope(str(git_repo), "HEAD~5", "HEAD")
    res = attribute_added_lines(str(git_repo), scope)
    # 최소한 Claude 작성 라인은 ai_lines 에 잡힌다
    ai_total = sum(len(v) for v in res.ai_lines.values())
    assert ai_total >= 1
