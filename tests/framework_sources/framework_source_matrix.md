# Framework Source Validation Matrix (B2)

CodeQL Python 이 FastAPI / Starlette / Strawberry 의 user-controlled source 를 실제로
잡는지 검증하는 매트릭스. **CodeQL CLI 미설치 상태에서는 검증이 실행되지 않으며, 그 경우
`FRAMEWORK_SOURCE_VALIDATION_NOT_RUN` (hard fail) 로 보고한다 — "no findings" 로 착각 금지.**

| # | dir | framework | source | sink | CWE |
|---|-----|-----------|--------|------|-----|
| 1 | fastapi_query_param | FastAPI | query param | subprocess(shell=True) | CWE-78 |
| 2 | fastapi_body_param | FastAPI | body field | eval | CWE-94 |
| 3 | starlette_query_params | Starlette | request.query_params | open | CWE-22 |
| 4 | starlette_json_body | Starlette | request.json | yaml.load | CWE-502 |
| 5 | strawberry_resolver_arg | Strawberry | resolver argument | cursor.execute | CWE-89 |
| 6 | strawberry_input_object | Strawberry | input object field | subprocess | CWE-78 |

각 dir: `vuln.py`(의도적 source→sink) + `expected.json`(expected source/sink count, flow_exists).

## 실측 결과 (P0-3b, CodeQL CLI v2.25.6 설치 후 — codex Q4: 실측과 일치)
- **FastAPI: ✅ DETECTED** (내장 라우팅 source model) — query/body 둘 다.
- **Starlette: ❌ NOT detected** — `Request.query_params`/`request.json` 미모델 → custom routing model 필요(V1.5).
- **Strawberry: ❌ NOT detected** — resolver arg / input object 미모델 → custom routing model 필요(V1.5).
- 미검출은 `missing_source_models.jsonl` 에 기록. 런타임 매트릭스: **`auditai/codeql/source_validation.json`**(Q1 에서 tests→패키지 이동).

## 실패 정책 (G2)
- 검증 매트릭스 없음/CodeQL 버전 불일치/탐지 미완료 → `FRAMEWORK_SOURCE_VALIDATION_NOT_RUN`
- detected 프레임워크가 매트릭스에서 미검증(Starlette/Strawberry) → `FRAMEWORK_SOURCE_MODEL_MISSING`

## 현재 상태
런타임 매트릭스 `auditai/codeql/source_validation.json` 는 `status=run`, FastAPI detected /
Starlette·Strawberry not detected. (구 파일명 `codeql_source_validation.json` → 패키지 리소스로 이동됨.)
