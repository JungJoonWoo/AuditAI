# AuditAI

GitHub PR/commit 에서 **AI(Claude)가 작성한 코드**를 우선 분석해 취약점을 찾는 SAST triage 도구
(MVP / Slice 1, Python 서버측). 설계 단일 진실원: [`docs/03-blueprint.md`](docs/03-blueprint.md),
P0 구현 계획: [`docs/05-p0-blockers.md`](docs/05-p0-blockers.md). 모든 결정은 codex 적대검증을 거친다.

## 핵심 원칙 — "빈 결과를 정상으로 착각하지 않는다"

AuditAI 는 "취약점 없음"을 다른 상태와 **반드시 구분**한다(하나로 뭉뚱그리면 SAST 로 신뢰 불가).
4-state 의 골자: ① 취약점 없음 / ② source model 없음 / ③ scope 잘못 / ④ MVP scope 밖. 실제 `RunStatus`
enum 은 그보다 세분화된다(아래는 대표 상태; 전체는 `auditai/contracts.py` RunStatus):

| 상태 (`RunStatus`) | 의미 |
|---|---|
| `NO_VULN_FOUND` | 실제로 (모델 범위 내) 취약점 없음 — G1 pass + G2 (pass/skipped) + S2 완료 + reliable 일 때만 |
| `FINDINGS_PRESENT` | Track A finding 또는 Track B inventory 존재 |
| `FRAMEWORK_SOURCE_MODEL_MISSING` | CodeQL 이 source 를 못 잡음 → "취약점 없음" 아니라 "source 모델 없음" |
| `FRAMEWORK_SOURCE_VALIDATION_NOT_RUN` | CodeQL 검증 미실행/매트릭스 없음/버전 불일치 → 결과 신뢰 불가 |
| `ANALYSIS_ERROR` | S2(taint) 미완료(미실행/실패) → clean 주장 불가 |
| `EVAL_TARGET_INSUFFICIENT` / `AUTHZ_SCOPE_UNDECLARED` | G3/G4 미충족 |
| `DIFF_SCOPE_MISSING` | PR diff scope 산출 실패 → 분석 scope 잘못됨 |
| `COMPLETED_DEGRADED` | smoke 에서 G2 미통과지만 계속(신뢰불가) |
| `OUT_OF_MVP_SCOPE` | cross-language/TS 등 MVP scope 밖 → 미분석 |

`source=0 / flow=0 / finding=0` 은 **절대 자동으로 정상 완료가 아니다.** 게이트(G1~G4)가 먼저 판정한다.

## Track A / Track B

- **Track A** — taint/data-flow 로 자동 검증하는 injection 계열(command/SQL/path/SSRF/deserialization/
  template/code). **현재 P0 구현 = CodeQL `python-security-extended` suite + AI-라인 필터**(source-bearing).
  청사진의 **split-config aiOnFlow QL·LLM 의미판정(S3)은 미구현/로드맵**(아래 "MVP 구현 범위" 참조).
- **Track B** — **자동 확정하지 않는** risk inventory. authz/IDOR/guard removal/boundary change.

### ⚠️ authz/IDOR 한정 고지 (G4 — 필수)

> **This is not automatically confirmed as an access-control vulnerability. However, the PR appears
> to remove or weaken a security boundary. Manual review is required.**

authz/IDOR/access-control 은 MVP 에서 **자동 confirmed finding 으로 다루지 않는다.** 대신
삭제/약화/우회(권한체크 제거, role 완화, tenant_id 검증 누락, default-allow 등)를
**Track B risk candidate** 로 수집하고 사람 검토(`requires_manual_review=true`)에 맡긴다.

## 핵심 차별점 — 삭제된 보안 통제 탐지

`git blame` 은 살아있는 라인만 보므로 **AI 가 지운** authz 가드/validator/sanitizer 를 못 본다.
AuditAI 의 S0 는 **`git diff <merge-base>..<head>` (PR-diff primary)** 를 쓰고, 삭제 라인에서
제거된 보안 통제를 `RemovedSecurityControlCandidate`(Track B) 로 수집한다. 삭제형은 source→sink
taint 가 없어도 후보가 된다(authz/IDOR 는 taint 취약점이 아니므로 "AI line 이 flow path 에" 필터 미적용).

## Gates

| Gate | 실패 시 |
|---|---|
| G1 Diff attribution | PR diff hunks 산출 실패 → `DIFF_SCOPE_MISSING` |
| G2 Framework source model | framework 사용인데 검증 매트릭스 없음/CodeQL 버전 불일치 → NOT_RUN; source model 미검증 → MODEL_MISSING; 탐지 미완료(grep 장애·선언만 있고 import 미탐지) → fail-closed NOT_RUN (smoke 는 degraded) |
| G3 Eval target | phoenix(smoke) 단독 eval 구성 → `EVAL_TARGET_INSUFFICIENT` |
| G4 Track B 한정 고지 | authz/IDOR 자동확정 안 함을 미고지 → `AUTHZ_SCOPE_UNDECLARED` |

## 현재 구현 상태 (P0)

- P0-1 contracts: ✅ (RunStatus 상태기계 / RunReport(resolver 위임) / Track B 모델 / 게이트 매트릭스)
- P0-2 S0: ✅ `auditai/scope.py`(PR-diff) + `auditai/security_controls.py`(삭제/약화 휴리스틱)
- P0-3a framework fixtures: ✅ `tests/framework_sources/` (6종) + `framework_source_matrix.md`
- P0-3b CodeQL 실행: ✅ **CodeQL CLI v2.25.6 설치(.tools/codeql) + python-queries@1.8.4**. Track A(`auditai/codeql.py`) 실동작 — `run_pipeline(run_codeql=True)`.
  - **framework source 매트릭스 실측**: FastAPI ✅ DETECTED(내장 모델) / **Starlette·Strawberry ❌ NOT detected** → custom framework routing model 필요(V1.5). 단순 sourceModel data-ext 으론 불충분(`auditai/codeql/models/README.md`).
- P0-4 eval targets: ✅ `eval_targets/`(synthetic_python[plumbing]/**owasp_sourced[efficacy]**/known_cve/ghsa/phoenix_smoke + `eval_config.json`)
- 오케스트레이션 + CLI: ✅ `auditai/run.py` → `runs/<run_id>/` artifacts, `python -m auditai scan`

### ⚠️ MVP 구현 범위 — 청사진(docs/03) vs 현재 P0 슬라이스 (codex Q2 R2-4/R2-5)
청사진 03 은 **전체 비전**(S1 Semgrep+KB 후보탐지 → S2 CodeQL taint → S3 LLM judge)이다. **현재 P0 슬라이스는 그 부분집합**이며, 효과/배선 주장은 아래 현실에 한정한다:
- **구현됨**: S0(diff/AI귀속) · **S2 Track A = CodeQL `python-security-extended` suite + AI-라인 필터**(source-bearing taint) · Track B(`security_controls.py` 휴리스틱, 삭제/약화) · 게이트 G1~G4 · artifact.
- **미구현(=청사진 로드맵, P0 밖)**: **S1 Semgrep/KB 후보탐지**(→ "source 무관 위험 sink 패턴 탐지"는 여기 영역) · **S3 LLM semantic judge** · `load_kb()` 파이프라인 소비(현재 KB 는 schema/cross-ref/fixture 검증된 forward registry, 미배선 — `auditai/kb/__init__.py`).
- **효과 주장 한정(★중요)**: MVP Track A 는 **framework source + 인식된 라이브러리 sink** 일 때 6개 OWASP 클래스를 탐지(`eval_targets/owasp_sourced`, 실측 6/6). **bare 함수 파라미터(source 없음)나 duck-typed sink 는 미탐지** — 그건 S1(post-MVP) 영역이며, `synthetic_python` 은 그 한계를 가진 **plumbing 타겟**(효과입증 아님). G3 는 efficacy 타겟(owasp_sourced/known_cve)이 있어야 PASS.

> **MVP 한계(정직 고지)**: ① Track A taint 는 CodeQL 기본 모델 범위(FastAPI 등)에서 동작. **Strawberry/Starlette 는 source 미검출 → `FRAMEWORK_SOURCE_MODEL_MISSING` 정직 보고**(custom routing model 은 V1.5). ② cross-language(TS↔Python) taint 는 MVP scope 밖. ③ 삭제 귀속은 squash/rebase 에서 강등. ④ Track B 휴리스틱은 FP/FN 있어 manual review 필수. ⑤ phoenix 는 효과 입증 타겟 아님(smoke). ⑥ **프레임워크 탐지**: 정적 import + 동적 import 리터럴(`importlib.import_module("fastapi")`/bare `import_module`/builtin `__import__`, 위치/키워드 인자, 함수명-`(` 공백 허용) + 의존성 매니페스트 선언을 본다. **변수인자 동적 import(`m="fastapi"; import_module(m)`)** 와 **importlib alias 호출(`from importlib import import_module as im; im("fastapi")`)** 이 매니페스트 선언도 없이 쓰인 경우는 정적 분석 한계로 미탐지(alias 추적은 V1.5) — 단 매니페스트가 있으면 dep-fallback 으로 fail-closed NOT_RUN, 변수인자 동적 import 는 불확실성 신호로 repo-wide/dep-fallback 보강을 켠다(보강이 해소할 때만 차단: dep 미탐지→NOT_RUN, repo-wide 미검증 framework→MODEL_MISSING). ⑦ G2 검증 매트릭스(`auditai/codeql/source_validation.json`)는 **CodeQL 2.25.6 기준**이며, 설치 버전이 다르면 매트릭스를 폐기하고 NOT_RUN(거짓 정직성 방지) — 버전 갱신 시 재검증 필요. ⑧ **G2 스코프(case A) — same-file helper-only 변경**(codex G2 over-flag r2): G2 case A 는 변경된 `.py` 파일의 **전체 head content** 에 있는 framework import 를 기준으로 검증 스코프를 확정한다(실 FastAPI repo 가 transitive Starlette/Strawberry 로 항상 over-flag 되는 것을 막기 위함). 따라서 AI 가 FastAPI 등 framework-bearing 파일 안의 **비-route helper 만** 변경했고 그 helper 가 **오직 미변경 Starlette/Strawberry route 로만** 흐르는 cross-framework taint 는 MVP 탐지 보장 밖이다 — 이 경우 `NO_VULN_FOUND` 는 해당 cross-framework 경로의 부재를 증명하지 않는다. route ownership/hunk-aware 탐지는 V1.5 범위다. (변경 파일에 framework import 가 전혀 없거나[case B], parse 실패·변수 동적 import[불확실성 신호]가 있으면 repo-wide + dep-fallback **보강을 켠다** — 보강이 해소할 때만 차단된다: dep-fallback[declared-but-not-imported]→fail-closed NOT_RUN, repo-wide 가 미검증 framework 탐지→G2 hard fail MODEL_MISSING. 어떤 framework 인지 정적으로도 매니페스트로도 확인 불가한 순수 변수 동적 import 는 ⑥ 한계로 미탐지된다. 즉 불확실성 신호 자체가 차단을 보장하지는 않는다.)

## 실행

```bash
uv run --no-sync pytest        # 테스트 (Windows: [project.scripts] uv 빌드 락 회피)

# CLI 표준 호출 (codex Q3-8: console script 대신 -m 권장 — uv 빌드 락 무관):
python -m auditai scan --repo . --base origin/main --head HEAD \
  --run-id r1 --target-type synthetic --eval-target owasp_sourced --runs-dir runs \
  --run-codeql                        # Track A taint 실행(없으면 Track-B-only)
# 또는: uv run --no-sync python -m auditai scan ...
# 파이프라인 API: auditai.run.run_pipeline(repo, base, head, run_id=..., target_type=..., eval_targets=[...], runs_dir=...)
```

종료코드: 0 NO_VULN / 1 FINDINGS / 2 hard-fail / 3 degraded / 4 OUT_OF_MVP (`auditai/cli.py`).

## 라이선스/주의

보안 분석 도구. Track A/B 모두 `vulnerability_confirmed=false` — 자동 확정은 없으며 사람 검토 후에만
유효하다. 외부 책임공개(disclosure)는 MVP 범위 밖(V3).
# AuditAI
