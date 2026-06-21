"""삭제/약화 보안 통제 휴리스틱 (security_controls.py) 테스트."""

from __future__ import annotations

from pathlib import Path

from auditai.contracts import (
    DeletionAttribution,
    Priority,
    RiskTrack,
    SecurityControlKind,
)
from auditai.scope import build_diff_scope
from auditai.security_controls import (
    _is_excluded,
    _priority,
    classify_deleted_line,
    detect_removed_controls,
    detect_weakened_controls,
)


# --- 순수 휴리스틱 (git 불필요) --------------------------------------------- #
def test_classify_authz():
    assert classify_deleted_line("    if not req.user.is_admin:") == SecurityControlKind.AUTHZ_CHECK
    assert classify_deleted_line("    @login_required") == SecurityControlKind.AUTHZ_CHECK
    assert classify_deleted_line("    if obj.owner_id != user.id:") == SecurityControlKind.AUTHZ_CHECK


def test_classify_exception_guard():
    assert classify_deleted_line("        raise PermissionError") == SecurityControlKind.EXCEPTION_GUARD


def test_classify_sanitizer():
    assert classify_deleted_line("    val = bleach.clean(x)") == SecurityControlKind.SANITIZER


def test_classify_none_for_benign():
    assert classify_deleted_line("    total = a + b") is None


def test_excluded_paths():
    assert _is_excluded("tests/test_x.py")
    assert _is_excluded("app/__generated__/api.py")
    assert _is_excluded("a/node_modules/b.py")
    assert not _is_excluded("src/app.py")


def test_priority_bare_raise_is_low():
    """codex scope3 M4: 보안 컨텍스트 없는 bare raise/return False 는 HIGH 아님."""
    assert _priority(SecurityControlKind.EXCEPTION_GUARD, True, "raise ValueError('bad')") == Priority.LOW
    assert _priority(SecurityControlKind.DEFAULT_DENY, True, "return False") == Priority.LOW


def test_priority_security_context_is_high():
    assert _priority(SecurityControlKind.EXCEPTION_GUARD, True, "raise PermissionError") == Priority.HIGH
    assert _priority(SecurityControlKind.AUTHZ_CHECK, True, "if not user.is_admin:") == Priority.HIGH
    # 구조 아니면 LOW
    assert _priority(SecurityControlKind.AUTHZ_CHECK, False, "x = is_admin") == Priority.LOW


# --- 통합 (diff_repo: authz 가드 삭제) -------------------------------------- #
def test_detect_removed_authz_guard(diff_repo: Path):
    scope = build_diff_scope(str(diff_repo), "HEAD~1", "HEAD")
    removed = detect_removed_controls(str(diff_repo), scope)
    assert removed, "삭제된 authz 가드를 잡아야 함"
    kinds = {c.security_control_kind for c in removed}
    assert SecurityControlKind.AUTHZ_CHECK in kinds or SecurityControlKind.EXCEPTION_GUARD in kinds
    c = removed[0]
    assert c.risk_track == RiskTrack.TRACK_B
    assert c.auto_confirmed is False
    assert c.requires_manual_review is True
    assert c.ai_attribution == DeletionAttribution.CONFIRMED_AI  # 단일 Claude commit
    # authz 가드 + 구조(if/raise)는 high priority
    assert any(c.priority == Priority.HIGH for c in removed)


# --- 통합 (weaken_repo: verify/safe_load 약화) ----------------------------- #
def test_detect_weakened_controls(weaken_repo: Path):
    scope = build_diff_scope(str(weaken_repo), "HEAD~1", "HEAD")
    weakened = detect_weakened_controls(str(weaken_repo), scope)
    kinds = {c.weakening_kind for c in weakened}
    assert "verify_disabled" in kinds
    assert "safe_to_unsafe_loader" in kinds
    for c in weakened:
        assert c.risk_track == RiskTrack.TRACK_B
        assert c.auto_confirmed is False


def test_weakened_requires_safe_removed(danger_add_repo: Path):
    """codex scope3 H2: 안전형 제거 없이 위험 라인만 추가는 약화 아님(Track A taint 대상)."""
    scope = build_diff_scope(str(danger_add_repo), "HEAD~1", "HEAD")
    weakened = detect_weakened_controls(str(danger_add_repo), scope)
    assert weakened == []
