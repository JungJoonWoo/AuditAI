# Custom framework source models (DRAFT — 비동작)

`starlette.model.yml` 은 Starlette `Request.*` 를 remote source 로 등록하려는 **초안**이다.
**현재 동작하지 않는다**(CodeQL "Extension pack unused").

## 왜 동작 안 하나 (P0-3b 실측)
Starlette/Strawberry 의 request 객체·resolver 인자는 **어노테이션된 핸들러 파라미터**로 도착한다.
단순 `sourceModel(type, path, kind)` data-extension 은 그 파라미터를 해당 타입의 인스턴스로
연결하지 못한다 — CodeQL API graph 가 어노테이션만으로 인스턴스를 만들지 않기 때문.
FastAPI 가 동작하는 이유는 CodeQL 이 **FastAPI 라우팅을 모델링한 framework 모델**을 내장하기 때문.

## 필요한 것 (V1.5)
Starlette/Strawberry 의 **routing framework model**(handler/resolver 파라미터를 source 로 인식하는
typeModel + 라우팅 의미, .qll 또는 확장 data-ext). 이는 단순 데이터 행이 아니라 CodeQL 엔지니어링 과제.
근거/추적: `tests/framework_sources/missing_source_models.jsonl`.
