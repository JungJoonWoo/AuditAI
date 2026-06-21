"""Security Knowledge Base — MVP seeded model registry (청사진 §6).

MVP 는 RAG/RDB 없이 Git-managed YAML seed 로 시작한다. 각 항목은 공통 메타
(owner/version/test_fixture/expected_tp_fp/engine_mappings)를 필수로 갖는다(codex A3/bp1-9).

**배선 상태(정직 고지)**: 이 KB seed 는 `load_kb()` 로 (1) schema(extra=forbid) (2) 교차참조
(3) **test_fixture 경로 존재**(codex Q4) 까지 검증된다. **전체 5단계 MVP 부터는 S1 candidate scanner
(`auditai/candidates.py`)가 `load_kb()` 로 KB 의 `SinkSpec`/`ApiSignature` 를 소비**해 AI 코드의 KB sink
호출을 AST 로 탐지한다(`run_pipeline` → `scan_candidates`). Track B 는 여전히 `security_controls.py`
휴리스틱. KB 를 더 쓰는 단계(Semgrep 룰 생성 / S3 LLM judge sanitizer 컨텍스트 / CodeQL custom model
export)는 이후 phase 다.
"""

from .loader import SecurityKB, load_kb, seed_dir

__all__ = ["SecurityKB", "load_kb", "seed_dir"]
