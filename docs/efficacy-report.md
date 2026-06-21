# AuditAI 효과 리포트 (Track A/B, 통제 실험 실측)

> 목적: "AuditAI 가 AI 작성 코드의 취약점을 실제로 탐지하는가"를 통제 실험으로 실증.
> 측정 환경: CodeQL CLI v2.25.6 + python-queries@1.8.4, 실제 `python -m auditai scan` end-to-end.
> 상태: self-review 실측(codex 적대적 재검증 대기 — `CODEX_VERIFICATION_QUEUE.md` Q2). **P0 차단 여부는 codex 판정 대상.**

## 요약

| | recall (진짜 취약점 탐지) | precision (안전 코드 무오탐) |
|---|---|---|
| **Track A** (CodeQL taint) | source+인식sink 시 **6/6 OWASP 클래스** | 안전 파라미터화 SQL → 무탐지(정확) |
| **Track B** (통제 제거/약화) | authz/guard/SQL약화 **HIGH 포착** | 가드 추가·비약화 변경 → 무탐지(정확) |

**결론**: framework-routed 현실 코드에서 AuditAI 는 핵심 취약점 클래스를 탐지하고(recall), 안전 코드를 clean 으로
정직 보고하며(precision), 불확실/미실행 상태를 4-state 로 정직 구분한다("빈 결과 오독 금지"). MVP 핵심 목적 달성을 양방향 실증.

## Track A (taint) — recall 통제 실험

AI 가 6개 OWASP 클래스를 추가한 PR 을 `--run-codeql` 로 스캔, 조건별 탐지율:

| 조건 | 탐지 | 비고 |
|---|---|---|
| bare 함수 파라미터 (source 없음) | **0/6** | CodeQL taint 는 source 필요 — bare param 은 RemoteFlowSource 아님 |
| FastAPI source + 타입미상 sink (`def f(cur, name)`) | 5/6 | SQL(89) 누락 = cursor provenance 미인식 |
| FastAPI source + 인식 sink (`sqlite3.connect().cursor()`) | **6/6** | CWE-78/89/22/502/918/94 전부 |

- 회귀 잠금: `tests/test_run.py::test_track_a_efficacy_owasp_classes` (fixture `owasp_efficacy_repo`).
- **갭(정직 고지)**: ① 비-framework 코드(source 없음) → 미탐지 → "위험 sink 존재" 패턴 탐지는 청사진 S1 Semgrep/KB
  = post-MVP. ② duck-typed sink(타입 미상 라이브러리 객체) → provenance 미인식(타입 어노/인식 생성자로 완화).

## Track A — precision

| 입력 | 결과 | 판정 |
|---|---|---|
| 안전 파라미터화 SQL (`execute('...?', (name,))`) + FastAPI + --run-codeql | findings=0, **NO_VULN_FOUND(reliable)** | 무오탐 + 진짜 clean 정확 보고 |

→ "항상 hard-fail 도, 오탐도 아닌" 균형 확인: 진짜 안전한 검증완료 코드에만 NO_VULN_FOUND(reliable) 도달.

## Track B (통제 제거/약화) — recall

AI 가 authz/exception guard/sanitizer/path_norm/input_valid/default_deny 제거 + SQL 파라미터화→f-string 약화한 PR:

- **9건 risk_inventory 포착**. authz(`is_admin`)·exception guard(`raise PermissionError`)·SQL 약화 = **HIGH**(정확);
  나머지 = low(noise 제어 설계).
- SQL 파라미터화→f-string = `weakened_control/HIGH` 로 포착(실제 SQL injection 유입 신호).

## Track B — precision

| 입력 | 결과 | 판정 |
|---|---|---|
| AI 가 가드 **추가**(`raise PermissionError`) | risk_inventory=0 | 가드 추가를 제거로 오탐 안 함 |
| safe_load 유지(`.strip()` 추가, 비약화) | risk_inventory=0 | 비약화 변경 오탐 안 함 |

## 미해결 설계 질문 (codex 판정 대상)

1. **효과 갭**: 비-framework 위험 sink 미탐지가 P0 차단인가 / S1 MVP 편입 / post-MVP 한계계약?
2. **Track B 전용 실행 status**: `--run-codeql` 없이 Track B 가 통제제거를 찾아도 s2 미완료 → ANALYSIS_ERROR(exit 2).
   taint 항상 강제(현 설계) vs Track B inventory 만으로 FINDINGS_PRESENT(exit 1) 허용?
3. **효과 corpus**: synthetic(bare param)은 Track A 미탐지 — source-bearing 효과 corpus 를 정식 추가?
