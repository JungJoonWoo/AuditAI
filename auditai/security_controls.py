"""삭제/약화된 보안 통제 휴리스틱 탐지 (계획 docs/05-p0-blockers.md §2.3~2.6).

blame-only 가 못 보는 "AI 가 지운 보안 가드/validator/authz" 를 PR diff 의 삭제 라인에서
패턴으로 수집한다. 휴리스틱이라 FP/FN 불가피 → 전부 Track B(자동확정 아님, manual review).
2-tier noise 경계(codex r2-4): high=구조+keyword+delta, low=구조 또는 keyword(버리지 않음).

정책: 삭제/약화형은 source→sink taint 가 없어도 candidate 다(authz/IDOR/guard removal 은
taint 취약점이 아님). "AI line 이 flow path 에 있어야 한다" 필터를 적용하지 않는다.
"""

from __future__ import annotations

import re

from .attribution import AttributionConfig
from .contracts import (
    Priority,
    RemovedSecurityControlCandidate,
    SecurityControlKind,
    WeakenedControlCandidate,
)
from .scope import DiffScope, FileDiff, attribute_addition, attribute_deletion

# 보안 통제 종류별 키워드 패턴 (deleted 라인 텍스트에 매칭)
_KIND_PATTERNS: list[tuple[SecurityControlKind, re.Pattern]] = [
    (SecurityControlKind.AUTHZ_CHECK, re.compile(
        r"\b(is_admin|is_superuser|is_staff|is_authenticated|has_perm|has_permission|"
        r"permission_required|login_required|current_user|require_role|require_auth|"
        r"check_permission|authorize|tenant_id|owner_id|is_owner|can_access)\b", re.I)),
    (SecurityControlKind.SANITIZER, re.compile(
        r"\b(sanitize|bleach|shlex\.quote|html\.escape|markupsafe|clean_html|escape)\b", re.I)),
    (SecurityControlKind.PATH_NORMALIZATION, re.compile(
        r"\b(realpath|abspath|normpath|os\.path\.normpath|safe_join|secure_filename)\b", re.I)),
    (SecurityControlKind.PARAMETERIZATION, re.compile(
        r"(execute\([^,]+,\s|parameterize|bindparam|%\(|\?\s*,)", re.I)),
    (SecurityControlKind.INPUT_VALIDATION, re.compile(
        r"\b(validate|is_valid|\.clean\(|schema\.load|pydantic|assert_|check_input)\b", re.I)),
    (SecurityControlKind.DEFAULT_DENY, re.compile(
        r"\b(default[_\s]*deny|deny_all|abort\(403|abort\(401|return\s+False|PermissionDenied)\b", re.I)),
    (SecurityControlKind.EXCEPTION_GUARD, re.compile(
        r"\b(raise|abort\(|HTTPException|PermissionError|Forbidden|Unauthorized)\b", re.I)),
]

# 구조적 신호 (if-guard / raise / assert / decorator / return-deny / middleware)
_STRUCT_RE = re.compile(
    r"^\s*(if\s|elif\s|raise\b|assert\b|@|return\s+(False|None)\b|abort\(|"
    r"with\s.*lock|require)", re.I)

# 약화(modified) 패턴: (deleted 안전형, added 위험형) 마커
_WEAKEN_PAIRS = [
    ("verify_disabled", re.compile(r"verify\s*=\s*True", re.I), re.compile(r"verify\s*=\s*False", re.I)),
    ("safe_to_unsafe_loader", re.compile(r"safe_load|SafeLoader", re.I),
     re.compile(r"yaml\.load\((?!.*Safe)|Loader\s*=\s*yaml\.Loader|UnsafeLoader|pickle\.load", re.I)),
    ("debug_enabled", re.compile(r"debug\s*=\s*False", re.I), re.compile(r"debug\s*=\s*True", re.I)),
    ("parameterized_to_raw", re.compile(r"execute\([^,]+,", re.I),
     re.compile(r"execute\(\s*f[\"']|execute\([^,)]*\+", re.I)),
]

_EXCLUDE_RE = re.compile(
    r"(^|/)(tests?|__generated__|node_modules|vendor|migrations|\.venv|site-packages|dist|build)/",
    re.I)


def _is_excluded(path: str) -> bool:
    return bool(_EXCLUDE_RE.search(path)) or path.endswith(("_test.py", "_pb2.py"))


def classify_deleted_line(text: str) -> SecurityControlKind | None:
    """deleted 라인 → 보안 통제 종류 (우선순위 순 첫 매칭). 없으면 None."""
    for kind, pat in _KIND_PATTERNS:
        if pat.search(text):
            return kind
    return None


def _is_structural(text: str) -> bool:
    return bool(_STRUCT_RE.search(text))


# bare raise/return False 과탐 방지 (codex scope3 M4): 강한 보안 kind 또는 보안 컨텍스트일 때만 HIGH
_HIGH_KINDS = {
    SecurityControlKind.AUTHZ_CHECK,
    SecurityControlKind.SANITIZER,
    SecurityControlKind.PATH_NORMALIZATION,
    SecurityControlKind.PARAMETERIZATION,
}
_SEC_CONTEXT_RE = re.compile(
    r"(403|401|forbidden|unauthorized|permission|permitted|authoriz|authenticat|"
    r"tenant|owner|denied|csrf|\badmin\b|\brole\b)", re.I)


def _priority(kind: SecurityControlKind | None, structural: bool, text: str) -> Priority:
    if structural and kind in _HIGH_KINDS:
        return Priority.HIGH
    if (
        structural
        and kind in {SecurityControlKind.EXCEPTION_GUARD, SecurityControlKind.DEFAULT_DENY}
        and _SEC_CONTEXT_RE.search(text)
    ):
        return Priority.HIGH
    return Priority.LOW  # low bucket: 버리지 않음(삭제형 누락 방지), 우선순위만 낮춤


def detect_removed_controls(
    repo: str,
    scope: DiffScope,
    cfg: AttributionConfig | None = None,
) -> list[RemovedSecurityControlCandidate]:
    """diff 의 삭제 라인에서 제거된 보안 통제 후보 수집 (Track B)."""
    cfg = cfg or AttributionConfig()
    out: list[RemovedSecurityControlCandidate] = []
    pr_shas = _pr_shas(repo, scope)
    cache: dict = {}
    seen: set[tuple] = set()

    for fd in scope.files:
        if _is_excluded(fd.file):
            continue
        # 연속 삭제 라인을 (kind) 단위로 그룹화
        for grp in _group_deletions(fd):
            kind = grp["kind"]
            structural = grp["structural"]
            text = grp["text"]
            # 보안 키워드 라인을 귀속 기준으로 (codex scope3 M3)
            token = grp["sec_text"] or grp["first_text"]
            attr, source, signals = attribute_deletion(
                repo, scope.merge_base, scope.head_sha, fd.file, token,
                pr_shas, cfg, _cache=cache,
            )
            if attr is None:
                continue  # human/AI 아님 → 스코프 밖
            dedup = (scope.base_sha, fd.file, grp["start"], grp["end"], (kind or SecurityControlKind.UNKNOWN))
            if dedup in seen:
                continue
            seen.add(dedup)
            out.append(RemovedSecurityControlCandidate(
                candidate_id=f"RSC-{len(out) + 1:03d}",
                repo=repo, base_sha=scope.base_sha, head_sha=scope.head_sha,
                file=fd.file,
                deleted_line_start=grp["start"], deleted_line_end=grp["end"],
                deleted_code=text,
                security_control_kind=kind or SecurityControlKind.UNKNOWN,
                ai_attribution=attr, deletion_attribution_source=source,
                attribution_signals=signals,
                risk_reason=f"deleted {(kind.value if kind else 'unknown')} control",
                priority=_priority(kind, structural, text),
            ))
    return out


def _group_deletions(fd: FileDiff) -> list[dict]:
    """연속 삭제 라인을 보안 신호가 있는 구간으로 그룹화."""
    groups: list[dict] = []
    cur: dict | None = None
    for dl in sorted(fd.deleted_lines, key=lambda d: d.old_lineno or 0):
        kind = classify_deleted_line(dl.text)
        structural = _is_structural(dl.text)
        relevant = kind is not None or structural
        if not relevant:
            cur = None
            continue
        ln = dl.old_lineno or 0
        # 같은 kind 연속만 병합 (codex scope3 M2: 복합 제거가 한 후보로 뭉개지지 않게)
        if cur and ln == cur["end"] + 1 and cur["kind"] == kind:
            cur["end"] = ln
            cur["text"] += "\n" + dl.text
            cur["structural"] = cur["structural"] or structural
            if cur["sec_text"] is None and kind is not None:
                cur["sec_text"] = dl.text
        else:
            cur = {
                "start": ln, "end": ln, "text": dl.text, "first_text": dl.text,
                "sec_text": dl.text if kind is not None else None,
                "kind": kind, "structural": structural,
            }
            groups.append(cur)
    return groups


def detect_weakened_controls(
    repo: str,
    scope: DiffScope,
    cfg: AttributionConfig | None = None,
) -> list[WeakenedControlCandidate]:
    """파일별로 (삭제 안전형 + 추가 위험형) 쌍을 약화 후보로 수집."""
    cfg = cfg or AttributionConfig()
    out: list[WeakenedControlCandidate] = []
    cache: dict = {}
    for fd in scope.files:
        if _is_excluded(fd.file):
            continue
        del_text = "\n".join(d.text for d in fd.deleted_lines)
        for kind, safe_re, danger_re in _WEAKEN_PAIRS:
            added_hit = next((a for a in fd.added_lines if danger_re.search(a.text)), None)
            if added_hit is None:
                continue
            # 약화 = 안전형이 실제로 제거됨 + 위험형 추가 (codex scope3 H2: 순수 위험 추가는
            # 약화가 아니라 Track A taint 대상 → safe 제거 없으면 제외).
            if not safe_re.search(del_text):
                continue
            # 추가된 위험 라인은 blame 으로 귀속 (codex scope2: 삭제 로직 아님)
            attr, source, signals = attribute_addition(
                repo, scope.head_sha, fd.file, added_hit.new_lineno or 0, cfg, _cache=cache,
            )
            if attr is None:
                continue  # human → AI 스코프 밖 (codex scope3 M1: unknown 오염 금지)
            out.append(WeakenedControlCandidate(
                candidate_id=f"WC-{len(out) + 1:03d}",
                repo=repo, base_sha=scope.base_sha, head_sha=scope.head_sha,
                file=fd.file,
                line_start=added_hit.new_lineno or 0, line_end=added_hit.new_lineno or 0,
                before_code="(safe form removed)",
                after_code=added_hit.text,
                weakening_kind=kind,
                ai_attribution=attr, deletion_attribution_source=source,
                attribution_signals=signals,
                risk_reason=f"weakened control: {kind}",
                priority=Priority.HIGH,  # safe 제거 + 위험 추가 = 명확한 약화
            ))
    return out


def _pr_shas(repo: str, scope: DiffScope) -> list[str]:
    from .scope import pr_commits

    return pr_commits(repo, scope.merge_base, scope.head_sha)
