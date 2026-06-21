# AuditAI — P0 Blocker 구현 계획 v0.3 (B1~B4 + Gates)

> 상태: **codex 2차(82/100, "P0-1 착수 가능") 반영 완료.** 남은 5개 부분지적(누락 terminal RunStatus / smoke degraded / gate precedence / gate_results schema / noise FN편향)을 §0·§2.4·§2.8 에 lockdown → **P0-1 contracts 구현에서 코드로 잠근다.** 사용자 P0 지시(2026-06-19). 기반: [03-blueprint.md](03-blueprint.md), [04-hybrid-candidate-discovery.md](04-hybrid-candidate-discovery.md).
> 원칙: 신규 feature build 중단. **빈 결과를 정상으로 착각 금지.** v0.1→v0.2 변경: RunStatus 상태기계·게이트 순서 계약화, B2 미실행/source=0 분리, 삭제 귀속 source 명시, noise 경계, RunReport/risk_inventory 모델, Track enum 미확장, 재시퀀싱, acceptance 증거파일.

## 0. RunStatus 상태기계 + 게이트 평가 순서 (신뢰 근간 — codex P0-2)

### 0.1 RunStatus (모든 terminal path 에 정확히 하나 배정)
| RunStatus | 의미 | 분류 |
|---|---|---|
| `NO_VULN_FOUND` | **G1 pass && G2 (pass\|skipped) && S2 completed && finding_count=0 && reliable** 일 때만 | 정상 |
| `FINDINGS_PRESENT` | Track A finding 또는 Track B inventory 존재 | 정상 |
| `DIFF_SCOPE_MISSING` | S0 PR-diff scope 산출 실패 (G1) | hard fail |
| `FRAMEWORK_SOURCE_VALIDATION_NOT_RUN` | CodeQL 미설치/검증 미실행 (G2, **codex P0-1**) | hard fail (smoke 는 degraded 허용) |
| `FRAMEWORK_SOURCE_MODEL_MISSING` | CodeQL 실행했으나 source=0 (G2) | hard fail (smoke degraded) |
| `EVAL_TARGET_INSUFFICIENT` | phoenix 만으로 MVP eval 구성 (G3) | config hard fail |
| `AUTHZ_SCOPE_UNDECLARED` | Track B 한정 고지 누락 (G4) | report hard fail |
| `OUT_OF_MVP_SCOPE` | cross-language/authz 자동확정 등 미분석 표기 | 명시 표기 |
| `ANALYSIS_ERROR` | S2 taint/CodeQL DB build 등 분석 자체 실패 (codex r2-2) | hard fail |
| `COMPLETED_DEGRADED` | smoke 에서 G2 미통과지만 계속 — 결과 신뢰불가 표기 (codex r2-2/6/7) | degraded(정상 아님) |

- **`reliability ∈ {reliable, degraded, unreliable}`** 필드를 RunReport 에 둔다. G2 미통과 smoke = `COMPLETED_DEGRADED` + `reliability=unreliable`. **degraded 는 NO_VULN_FOUND 로 보고 금지.**
- **framework 미사용 target**: G2 `skipped`(실패 아님) → 정상 경로 진행(codex r2-2).
- **`GateFailureCode` 는 RunStatus 와 분리**: 게이트별 코드(G1_DIFF/G2_SOURCE_NOT_RUN/G2_SOURCE_ZERO/G3_EVAL/G4_AUTHZ)는 gate_results 에 기록.
- **gate severity precedence(codex r2-7)**: `G1 > G2(hard) > ANALYSIS_ERROR > G3 > G4 > G2(degraded) > FINDINGS_PRESENT > NO_VULN_FOUND`. 이 순서로 가장 심각한 것이 최종 RunStatus.

### 0.2 평가 순서 (runner 가 이 순서로 판정 — 구현 계약)
```
1. S0 PR-diff scope        → 실패 시 DIFF_SCOPE_MISSING (G1, 즉시 종료)
2. detect_frameworks(target)
     - FastAPI/Starlette/Strawberry 미사용 → G2 skipped (정상 진행)
3. load codeql_source_validation(target frameworks)   # framework 사용 시에만
     - 검증 산출물 없음/CodeQL 미설치 → G2: NOT_RUN  (PR/known_cve=hard fail, smoke=degraded)
     - 검증 있고 source_count=0     → G2: SOURCE_ZERO (PR/known_cve=hard fail, smoke=degraded)
4. S2 taint 실행
     - S2/CodeQL DB build 자체 실패  → ANALYSIS_ERROR (즉시 종료)
5. S2 result normalization + Track B inventory 합류
6. final RunStatus 판정 (severity precedence 적용)
     - NO_VULN_FOUND 는 [G1 pass && G2(pass|skipped) && S2 completed && finding=0 && reliability=reliable] 일 때만
     - smoke 에서 G2 미통과 && finding=0  → COMPLETED_DEGRADED (NO_VULN_FOUND 아님)
```
**source=0 / flow=0 / findings=0 을 절대 자동 NO_VULN_FOUND 로 보지 않는다.** 반드시 3단계 G2 가 선판정.

## 1. 실행 순서 (재시퀀싱 — codex P2)

- **P0-1**: contracts — RunStatus/GateFailureCode/RunReport/risk_inventory + 분리 candidate 모델. (코드 계약 먼저)
- **P0-2**: PR-diff primary S0 (scope.py) + deletion/weakening inventory (security_controls.py). (B1)
- **P0-3a**: framework source fixtures 6종 + `validation NOT_RUN` hard-fail 게이트(gates.py). (B2, CodeQL 없이 가능한 부분)
- **P0-3b**: **CodeQL CLI 설치 후** DB 빌드·쿼리·snapshot·`source=0` hard-fail. (B2 잔여)
- **P0-4**: phoenix eval config 격하 + Python known-CVE corpus **계획만**(실구축은 P0-3b 이후). (B3)
- **P0-5**: docs/report wording (G4 고지) + README/architecture. (B4 마감)
- 전 구간: artifact 를 `runs/<run_id>/` 에 저장.
- **STOP 유지**: 신규 finding logic / LLM judge 고도화 / report polish / S1C LLM miner 보류.

## 2. Decision B1 — PR-diff primary S0 (구현 가능, 최우선)

### 2.1 변경 핵심
S0 primary = **`git diff <merge-base>..<head> --find-renames`** (blame 아님). blame 은 **supplemental metadata 로 강등**. blame 은 살아있는 라인만 → 삭제된 guard/validator/authz 못 봄.

### 2.2 입력 / 산출물(runs/<run_id>/)
입력: repo, base ref, head ref, merge-base, diff, commit metadata, PR body/commit message/Co-authored-by 트레일러, AI signals.
산출물: `diff_scope.json`(added/modified/deleted hunks), `ai_attribution.json`(hunk/commit→상태+signals), `deleted_security_controls.jsonl`, `scope_selection_report.md`(+RunStatus).

### 2.3 추적 3종
1. **Added**: 신규 위험 코드 → 기존 S1 candidate(taint_path/static_pattern_risk).
2. **Modified(약화)**: allowlist→blocklist, parameterized→raw, safe→unsafe loader, `verify=True→False`, strict→loose → `WeakenedControlCandidate`(risk_track=track_b).
3. **Deleted(최우선)**: authz/permission/role/tenant·ownership/input validation/sanitizer/escaping/parameterization/path normalization/raise/security assertion/default-deny 삭제 → `RemovedSecurityControlCandidate`(risk_track=track_b).

### 2.4 삭제탐지 noise 경계 — 2-tier (codex P1 + r2-4: FN 편향 방지)
**공통 전제(모두)**: non-test/non-generated/non-vendored 경로의 changed **executable Python** + dedup key `(repo, base_sha, file, deleted_range, security_control_kind)`. (이건 noise 제거지 FN 유발 아님.)
- **high-priority candidate** (강한 신호): 구조 매칭(`if-guard|raise|assert|decorator|middleware|validator·sanitizer call|return-deny`) **AND** security keyword **AND** before/after delta evidence(통제가 실제 사라짐).
- **low-priority bucket** (약한 신호, **버리지 않음** — 삭제형 취약점 누락 방지): 구조 매칭 **OR** security keyword 중 하나만 충족, 또는 분류 불명확(`security_control_kind=unknown`).
- → high 는 manual review 큐 상단, low 는 inventory 하단. **둘 다 수집하되 우선순위만 분리**(recall 보존 + 폭발 억제).

### 2.5 RemovedSecurityControlCandidate (필드 + 귀속 source — codex P0-3)
```json
{
  "candidate_id": "RSC-001", "repo": "...", "base_sha": "...", "head_sha": "...",
  "file": "...", "deleted_line_start": 10, "deleted_line_end": 14, "deleted_code": "...",
  "enclosing_function_before": "...", "enclosing_function_after": "...",
  "security_control_kind": "authz_check|input_validation|sanitizer|exception_guard|path_normalization|parameterization|escaping|default_deny|unknown",
  "ai_attribution": "confirmed_ai|probable_ai|probable_ai_from_pr_metadata|unknown_due_to_history_loss",
  "deletion_attribution_source": "single_commit_pr|commit_walk_unique|pr_metadata_only|unknown_due_to_history_loss",
  "attribution_signals": [], "risk_reason": "...",
  "risk_track": "track_b", "inventory_kind": "removed_security_control",
  "requires_manual_review": true, "auto_confirmed": false, "priority": "high|low"
}
```
- **삭제 귀속(codex P0-3 + r2-3)**: `git diff merge-base..head` hunk 엔 "삭제 commit" 이 없다 → commit 특정 우선순위: ① PR 이 단일 commit → `single_commit_pr`; ② **PR commit 범위 내로 한정한** `git log -S<deleted_token> <merge-base>..<head> -- file` 결과가 **유일** → `commit_walk_unique`(비용 제한: PR 범위 밖 탐색 금지, 후보 다수면 포기); ③ 특정 불가(squash/rebase/amend) → `pr_metadata_only`(ai_attribution 최대 `probable_ai_from_pr_metadata`) 또는 `unknown_due_to_history_loss`. **squash/모호 면 confirmed 로 올리지 않는다.**

### 2.6 핵심 정책 (필터 예외)
**"AI line 이 flow path 에 존재해야 한다" 필터는 Track B(삭제/약화)에 적용 안 함.** authz/IDOR/guard removal 은 taint 아님 → source→sink flow 없어도 candidate. (Track A taint_path 에만 flow+AI-line 필터.)

### 2.7 contracts 정합 (codex P1 — Track enum 미확장)
- `RemovedSecurityControlCandidate`/`WeakenedControlCandidate` 는 **FindingCandidate 와 분리 모델**. **Track enum 은 A/A_prime/B 그대로 유지**(새 값 추가 금지). 분리 모델은 `risk_track="track_b"` + `inventory_kind` 필드로 표기.
- 이들은 S2 taint/S2.5 게이트/S3 judge 를 거치지 않고 **risk_inventory 로 직행**.
- **04 의 `unknown_risk_surface`/`evidence_kind=llm_mined` 는 이번 P0 구현 제외 — enum 확장하지 않는다(codex P1).**

### 2.8 S4 계약 (codex P1 + r2-6 — risk_inventory + gate_results 구조)
```
RunReport {
  run_id, target_type(smoke|synthetic|known_cve),       # codex r2-6: target_type 보존
  run_status(RunStatus), reliability(reliable|degraded|unreliable),
  gate_results: GateResult[],
  findings: FindingReport[], risk_inventory: RiskInventoryItem[]
}
GateResult { gate(G1|G2|G3|G4), status(pass|fail|skipped|degraded), code(GateFailureCode|null), message }
RiskInventoryItem { item_id, risk_track, inventory_kind, priority(high|low),
  file, line_or_deleted_line, evidence, why_it_matters, requires_manual_review, auto_confirmed=false }
```
기존 `FindingReport`(Track A taint)는 그대로, RunReport 가 findings + risk_inventory + status + reliability + gate_results 를 묶는다.

## 3. Decision B2 — CodeQL framework source validation (P0 전제)

### 3.1 제약 + 분할(codex P0-1)
**CodeQL CLI 미설치.** B2 acceptance 를 둘로 분리:
- **#5a**: CodeQL 미설치/검증 산출물 없음 → `FRAMEWORK_SOURCE_VALIDATION_NOT_RUN` **hard fail**. (지금 구현 가능: 게이트 로직 + fixture)
- **#5b**: CodeQL 실행 후 source_count=0 → `FRAMEWORK_SOURCE_MODEL_MISSING` **hard fail**. (CodeQL 설치 후)
**CodeQL 설치 전 B2 완료 선언 금지.**

### 3.2 매트릭스 fixture
```
tests/framework_sources/{fastapi_query_param, fastapi_body_param, starlette_query_params,
  starlette_json_body, strawberry_resolver_arg, strawberry_input_object}/
```
각: intentionally vulnerable source→sink + expected source/sink count + expected flow_exists + (설치 후) CodeQL query snapshot.

### 3.3 Acceptance / 실패 메시지
FastAPI pass / Starlette pass / Strawberry **pass or custom model required**. source=0 시 "no findings" 금지, 메시지: "CodeQL did not identify any remote/user-controlled source for this framework. Results are not reliable. Add or fix framework source model before using this target."
산출물: `framework_source_matrix.md`, `codeql_source_validation.json`, `missing_source_models.jsonl`, custom source model 초안.

## 4. Decision B3 — phoenix = integration/smoke (효과입증 아님)

phoenix 용도: integration smoke / pipeline scale / framework source modeling / AI attribution·scope. **효과 입증 타겟 아님.**
```
eval_targets/{synthetic_python, python_known_cves, python_ghsa_patch_diffs, phoenix_smoke}/
```
eval config 에 `target_type`(smoke|synthetic|known_cve) 분리. **phoenix 만으로 MVP eval → G3 실패.**
**codex P2**: `synthetic_python` 은 P0 구축, **`python_known_cves` 5~10개 실선별·구축은 P0-3b 이후**(P0 에선 계획·기준만).

## 5. Decision B4 — authz/IDOR: 자동확정 밖, Track B inventory 필수

Track A=taint injection 자동검증, Track B=authz/IDOR/guard removal/boundary change risk inventory(자동확정 아님). Track B 수집 항목·필드는 §2.5/§2.8 의 risk_inventory 로 통일. 보고서 고정 문구: "This is not automatically confirmed as an access-control vulnerability. However, the PR appears to remove or weaken a security boundary. Manual review is required." 미명시 시 G4 `AUTHZ_SCOPE_UNDECLARED`.

## 6. Gates (RunStatus vs GateFailureCode 분리 — codex P1)

> **구현 시 진화(Q1 codex 8라운드)**: G2 의 "source=0" 은 *per-run source 카운팅* 발상이었으나,
> 실제 구현은 **프레임워크 source-model 검증 매트릭스**(`auditai/codeql/source_validation.json`,
> CodeQL 버전 결합) 기반 **per-framework** 판정으로 진화했다. GateFailureCode 는 그대로 재사용:
> - `G2_SOURCE_NOT_RUN`(→`FRAMEWORK_SOURCE_VALIDATION_NOT_RUN`) = 매트릭스 없음 / CodeQL 버전 불일치 /
>   프레임워크 탐지 미완료(grep 장애·dep 선언인데 import 미탐지 → fail-closed).
> - `G2_SOURCE_ZERO`(→`FRAMEWORK_SOURCE_MODEL_MISSING`) = 탐지된 프레임워크의 source model 이 매트릭스에서
>   미검증(예: Starlette/Strawberry). 상세 8라운드: `docs/CODEX_HISTORY.md` Q1.

| Gate | 조건 | target_type 별 처리 | GateFailureCode |
|---|---|---|---|
| G1 Diff | PR diff hunks 산출 실패 | **전부 hard fail** | G1_DIFF |
| G2 Source | framework 사용인데 검증 미실행/매트릭스 없음/버전 불일치/탐지 미완료 / source model 미검증 | **PR·known_cve hard fail / smoke degraded(계속, 단 결과 unreliable 표기)** | G2_SOURCE_NOT_RUN / G2_SOURCE_ZERO |
| G3 Eval | phoenix 단독 eval 구성 | **eval-config hard fail** | G3_EVAL |
| G4 Authz | Track B 한정 미고지 | **report hard fail** | G4_AUTHZ |

## 7. Acceptance Criteria + 증거파일 (codex P2)

| # | 조건 | 증거 |
|---|---|---|
| 1 | blame 이 primary 아님 | `scope.py`(diff primary), `scope_selection_report.md` |
| 2 | added/modified/deleted hunks artifact | `runs/<id>/diff_scope.json` |
| 3 | 삭제 통제 → RemovedSecurityControlCandidate | `runs/<id>/deleted_security_controls.jsonl` + 테스트 |
| 4 | framework matrix 존재 | `tests/framework_sources/*`, `framework_source_matrix.md` |
| 5a | 검증 미실행 시 explicit fail | `runs/<id>/gate_results.json`(G2_SOURCE_NOT_RUN) |
| 5b | source=0 시 explicit fail | `codeql_source_validation.json`(설치 후) |
| 6 | phoenix integration/smoke 분리 | `eval_targets/phoenix_smoke/`, eval config `target_type` |
| 7 | known CVE corpus 계획 | `eval_targets/python_known_cves/README`(선별 기준) |
| 8 | authz=Track B 문서화 | RunReport risk_inventory + docs |
| 9 | artifact → runs/<id>/ | runs 디렉터리 구조 |
| 10 | README/architecture 반영 | `README.md` 게이트·제한 섹션 + `docs/03` 갱신 |

## 8. 구현 영향 (코드/문서)
- `auditai/contracts.py`: RunStatus/GateFailureCode/RunReport/RiskInventoryItem enum·모델 + RemovedSecurityControlCandidate/WeakenedControlCandidate(분리, Track 미확장).
- `auditai/scope.py`(신규, PR-diff primary) / `auditai/security_controls.py`(신규, 삭제·약화 휴리스틱+noise 경계) / `auditai/gates.py`(신규, G1~G4+RunStatus 판정) / `auditai/run.py`(신규, runs/<id> writer + 평가순서).
- `auditai/attribution.py`: blame 은 supplemental 유틸로 유지(primary 아님).
- `tests/framework_sources/*` fixture 6종 + `eval_targets/*` 구조.
- 문서: 03/04 정합 갱신 + README(G4 고지) + architecture.

## 9. codex 재검증 요청 포인트
1. RunStatus 상태기계·평가순서(§0.2)가 모든 terminal path 를 빠짐없이 덮는가, NO_VULN_FOUND 가로채기 순서가 빈틈없는가.
2. 삭제 귀속 source 4분류 + squash 강등이 정합적인가.
3. noise 경계(§2.4)가 inventory 폭발을 실제로 막는가, 과소탐지(FN)로 가지 않는가.
4. Track 미확장 + 분리모델(risk_track/inventory_kind) + RunReport 가 03/04 와 충돌 없는가.
5. B2 #5a/#5b 분리 + smoke degraded 예외가 "빈 결과 오독 금지" 원칙을 끝까지 지키는가.
6. P0 재시퀀싱이 STOP 원칙(신규 feature 금지)과 정합한가.
