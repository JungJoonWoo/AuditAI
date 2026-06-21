"""Framework source validation 매트릭스 fixture 무결성 (B2)."""

from __future__ import annotations

import json
from pathlib import Path

from auditai.codeql import source_validation_path

_FX = Path(__file__).parent / "framework_sources"
_DIRS = [
    "fastapi_query_param", "fastapi_body_param",
    "starlette_query_params", "starlette_json_body",
    "strawberry_resolver_arg", "strawberry_input_object",
]


def test_six_fixtures_exist():
    for d in _DIRS:
        assert (_FX / d / "vuln.py").exists(), d
        assert (_FX / d / "expected.json").exists(), d


_REQUIRED_KEYS = {"framework", "source", "sink", "cwe", "expected_source_count",
                  "expected_sink_count", "expected_flow_exists"}
_OPTIONAL_KEYS = {"note"}  # codex Q4: note 를 optional 공식 필드로 명문화(스키마 일관)


def test_expected_json_schema():
    """codex Q4: 6종 expected.json 의 key set 이 일관(필수 7 + optional note 만 허용)."""
    for d in _DIRS:
        data = json.loads((_FX / d / "expected.json").read_text(encoding="utf-8"))
        keys = set(data)
        assert _REQUIRED_KEYS <= keys, f"{d}: missing {_REQUIRED_KEYS - keys}"
        assert keys <= _REQUIRED_KEYS | _OPTIONAL_KEYS, f"{d}: unexpected {keys - _REQUIRED_KEYS - _OPTIONAL_KEYS}"
        assert data["expected_flow_exists"] is True


def test_validation_status_recorded():
    """CodeQL 검증 실행됨 → status=run, FastAPI 탐지/Starlette·Strawberry 미탐지 기록(P0-3b).

    검증 매트릭스는 런타임 패키지 리소스(auditai/codeql/source_validation.json)로 이동(codex Q1 F5).
    """
    data = json.loads(source_validation_path().read_text(encoding="utf-8"))
    assert data["status"] == "run"
    r = data["results"]
    assert r["fastapi_query_param"]["detected"] is True
    assert r["strawberry_resolver_arg"]["detected"] is False  # custom model 필요
