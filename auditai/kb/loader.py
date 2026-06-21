"""Security KB 로더 + 교차참조 검증 (청사진 §6/§7)."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from ..contracts import (
    ApiSignature,
    Capability,
    PropagatorSpec,
    SanitizerSpec,
    SinkSpec,
    SourceSpec,
)

# 파일명 -> (top-level key, model)
_KB_FILES = {
    "capabilities.yaml": ("capabilities", Capability),
    "api_signatures.yaml": ("api_signatures", ApiSignature),
    "sources.yaml": ("sources", SourceSpec),
    "sinks.yaml": ("sinks", SinkSpec),
    "sanitizers.yaml": ("sanitizers", SanitizerSpec),
    "propagators.yaml": ("propagators", PropagatorSpec),
}


def seed_dir() -> Path:
    return Path(__file__).parent / "seed"


@dataclass
class SecurityKB:
    capabilities: dict[str, Capability]
    api_signatures: dict[str, ApiSignature]
    sources: dict[str, SourceSpec]
    sinks: dict[str, SinkSpec]
    sanitizers: dict[str, SanitizerSpec]
    propagators: dict[str, PropagatorSpec]

    def validate_cross_refs(self) -> None:
        """dangling 참조 검출 — seed 무결성 보장."""
        for sig in self.api_signatures.values():
            if sig.capability_id not in self.capabilities:
                raise ValueError(
                    f"api_signature {sig.id}: unknown capability_id {sig.capability_id}"
                )
        for sink in self.sinks.values():
            if sink.capability_id not in self.capabilities:
                raise ValueError(f"sink {sink.id}: unknown capability_id {sink.capability_id}")
            if sink.api_signature_id and sink.api_signature_id not in self.api_signatures:
                raise ValueError(
                    f"sink {sink.id}: unknown api_signature_id {sink.api_signature_id}"
                )
        for san in self.sanitizers.values():
            if san.applies_to_capability not in self.capabilities:
                raise ValueError(
                    f"sanitizer {san.id}: unknown applies_to_capability "
                    f"{san.applies_to_capability}"
                )


def _load_one(path: Path, key: str, model) -> dict[str, object]:
    # codex Q9: 필수 seed 파일/키 누락은 침묵하지 말고 실패시킨다.
    if not path.exists():
        raise FileNotFoundError(f"required KB seed file missing: {path}")
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or key not in data:
        raise ValueError(f"KB seed {path.name} missing top-level key '{key}'")
    items = data[key]
    if not isinstance(items, list):
        raise ValueError(f"KB seed {path.name} key '{key}' must be a list")
    out: dict[str, object] = {}
    for raw in items:
        obj = model.model_validate(raw)  # extra='forbid' → 오타/잉여 필드 거부
        if obj.id in out:
            raise ValueError(f"duplicate id {obj.id} in {path.name}")
        out[obj.id] = obj
    return out


def _repo_root() -> Path:
    # auditai/kb/loader.py → auditai/kb → auditai → repo root
    return Path(__file__).resolve().parent.parent.parent


def _validate_test_fixtures(kb: SecurityKB, repo_root: Path) -> None:
    """모든 KB 항목의 meta.test_fixture 가 실제 존재하는 **파일**을 가리키는지 검증 (codex Q4).

    'test_fixture' 라고 선언만 하고 파일이 없으면 '검증된 registry' 주장이 거짓이 되므로 실패시킨다.
    codex Q4r2: 빈 값도 실패(skip 금지), `is_file()` 로 디렉토리 통과 차단."""
    for coll in (kb.capabilities, kb.api_signatures, kb.sources, kb.sinks,
                 kb.sanitizers, kb.propagators):
        for item in coll.values():
            fx_path = getattr(getattr(item, "meta", None), "test_fixture", "") or ""
            if not fx_path.strip():
                raise ValueError(f"KB item {item.id}: empty test_fixture")
            if not (repo_root / fx_path).is_file():
                raise FileNotFoundError(
                    f"KB item {item.id}: test_fixture not a file: {fx_path}"
                )


def load_kb(directory: str | Path | None = None, *, validate_fixtures: bool = True) -> SecurityKB:
    base = Path(directory) if directory else seed_dir()
    loaded: dict[str, dict] = {}
    for fname, (key, model) in _KB_FILES.items():
        loaded[key] = _load_one(base / fname, key, model)
    kb = SecurityKB(
        capabilities=loaded["capabilities"],
        api_signatures=loaded["api_signatures"],
        sources=loaded["sources"],
        sinks=loaded["sinks"],
        sanitizers=loaded["sanitizers"],
        propagators=loaded["propagators"],
    )
    kb.validate_cross_refs()
    if validate_fixtures:  # codex Q4r2: public API(custom dir 포함)에서도 검증 (test_fixture 는 repo-root 상대)
        _validate_test_fixtures(kb, _repo_root())
    return kb
