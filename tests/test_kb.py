"""Security KB seed 로드 + 교차참조 검증."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from auditai.contracts import EngineMappings
from auditai.kb import load_kb


def test_seed_loads_and_cross_refs():
    kb = load_kb()  # 내부 검증(validate_cross_refs) 포함; dangling 있으면 예외
    assert kb.capabilities
    assert kb.sinks
    assert kb.sources
    assert kb.sanitizers


def test_sink_capabilities_resolve():
    kb = load_kb()
    for sink in kb.sinks.values():
        assert sink.capability_id in kb.capabilities
        if sink.api_signature_id:
            assert sink.api_signature_id in kb.api_signatures


def test_required_meta_present():
    kb = load_kb()
    for cap in kb.capabilities.values():
        assert cap.meta.owner
        assert cap.meta.test_fixture
        assert cap.meta.expected_tp_fp


def test_mvp_capability_coverage():
    kb = load_kb()
    required = {
        "command_execution",
        "code_execution",
        "sql_execution",
        "path_traversal",
        "ssrf",
        "unsafe_deserialization",
    }
    assert required <= set(kb.capabilities)


def test_sanitizer_is_candidate_not_autocut():
    """sanitizer 는 이름 기반 자동 FP 제거가 아님(candidate 표시용)."""
    kb = load_kb()
    name_heuristic = kb.sanitizers.get("validate_prefix")
    assert name_heuristic is not None
    assert name_heuristic.strength == "candidate"


def test_missing_seed_file_raises(tmp_path: Path):
    """codex Q9: 필수 seed 파일 누락은 침묵하지 않고 실패."""
    with pytest.raises(FileNotFoundError):
        load_kb(tmp_path)  # 빈 디렉터리


def test_codeql_mapping_allowlist():
    """codex Q9/A9: engine_mappings.codeql 는 허용 모델 계열만."""
    EngineMappings(codeql="sinkModel: command injection")  # ok
    EngineMappings(codeql="summaryModel: taint preserving")  # ok
    with pytest.raises(ValidationError):
        EngineMappings(codeql="randomModel: nope")


def test_kb_models_forbid_extra():
    """codex Q6: KB 모델도 잉여 필드 거부."""
    with pytest.raises(ValidationError):
        EngineMappings(codeql="sinkModel: x", bogus_field=1)


def test_kb_default_fixtures_all_exist():
    """codex Q4: 기본 seed 의 모든 test_fixture 가 실제 존재(없으면 load_kb 가 실패)."""
    load_kb()  # validate_fixtures=True 기본 — 미존재 fixture 면 FileNotFoundError


def test_kb_fixture_validation_fails_on_missing(tmp_path: Path):
    """codex Q4: test_fixture 미존재 시 검증이 조용히 통과하지 않고 실패한다."""
    from auditai.kb.loader import _validate_test_fixtures

    kb = load_kb()
    with pytest.raises(FileNotFoundError):
        _validate_test_fixtures(kb, tmp_path)  # 빈 root → 모든 fixture 미존재


def test_kb_public_load_validates_fixtures(monkeypatch, tmp_path: Path):
    """codex Q4r2: public load_kb() 경로가 fixture 검증을 실제로 실행(private helper 만이 아님)."""
    monkeypatch.setattr("auditai.kb.loader._repo_root", lambda: tmp_path)  # 빈 root
    with pytest.raises(FileNotFoundError):
        load_kb()  # validate_fixtures=True 기본 → fixture 가 빈 root 기준 미존재


def test_kb_empty_test_fixture_rejected():
    """codex Q4r2: 빈 test_fixture 는 KBMeta 단계에서 거부(min_length=1)."""
    from auditai.contracts import KBMeta

    with pytest.raises(ValidationError):
        KBMeta(owner="x", version="1", test_fixture="", expected_tp_fp="tp")


def test_kb_directory_test_fixture_rejected():
    """codex Q4r3: test_fixture 가 파일 아닌 디렉토리를 가리키면 거부(is_file)."""
    from auditai.kb.loader import _repo_root, _validate_test_fixtures

    kb = load_kb()
    item = next(iter(kb.capabilities.values()))
    object.__setattr__(item.meta, "test_fixture", "eval_targets")  # 디렉토리(파일 아님)
    with pytest.raises(FileNotFoundError):
        _validate_test_fixtures(kb, _repo_root())
