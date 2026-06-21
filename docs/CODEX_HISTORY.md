# CODEX 검증 이력 (요약)

> 원본 `.codex-prompt-*.md` / `.codex-out-*.txt` 는 정리 시 삭제. 점수·결론만 여기 보존.
> 규칙: 검증 step 이 끝나면 해당 working 파일은 삭제(이 표에 결과만 남김).

| 대상 | 라운드 | 점수 추이 | 결론 |
|---|---|---|---|
| 01 방향성/기술계약 | 5 | 42→68→78→86→**96** | sign-off (split-config QL·blame 귀속·평가게이트 확정) |
| 02 아키텍처(MVP/로드맵) | 2 | 58→**88** | MVP/로드맵 분리, chain/RAG/disclosure 로드맵화 |
| 03 청사진(canonical) | 3 | 82→90→**96** | sign-off ("MVP 구현 착수 가능: 예") |
| 04 hybrid candidate discovery | 1 | **61**(조건부) | S1C LLM miner 기본 off, 별도 모델 분리 등 — 로드맵으로 |
| foundation CODE QA(contracts+S0+KB) | 3 | 68→78→**90** | 머지 가능 |
| P0-1 RunStatus contracts CODE QA | 5 | 62→84→78→82→**93** | "OUT_OF_MVP s2 강제 1건만"→반영, cleared |
| P0 구현계획(05) | 2 | 68→**82** | "P0-1 착수 가능 — 남은 5건 contracts 에서 잠금" |
| scope.py + security_controls.py | 3 | 68→(cut)→**78** | High2+Med4 수정(파서 in_hunk, log-S 검증, squash 강등 등) |
| run.py + gates.py | 1 | **82**(조건부) | 5건 수정(S2 guard, run_id 경로안전, G2 메시지, G1 artifact) |
| **Q1 run.py+gates.py+G2 재설계 (CODE QA)** | **8** | 68→86→78→82→90→86→96→**94** | **머지 가능(예, r7부터)** — 아래 상세 |
| **Q2 P0 통합/acceptance (INTEGRATION QA)** | **4** | 74→86→92→**92** | **머지 가능(예, r3)** — 아래 상세 |
| **Q3 CLI (auditai/cli.py)** | **2** | 78→**92** | **머지 가능(예, r2)** — exit 전수분류(_HARD_FAIL+RuntimeError), 예외 catch 확대(OSError/GitError), CLI 테스트 8종(검증분기/status≠run/gate-fail stderr/exit3/parser), `python -m auditai` 표준. |
| **Q4 KB/fixtures/eval/README** | **3** | 82→88→**94** | **머지 가능(예, r3)** — KB test_fixture 미존재 3종 신설 + **load_kb fixture 존재검증**(public path, is_file, 빈값 거부, KBMeta min_length), expected.json note optional 명문화, framework_source_matrix.md 실측 일치, eval README 두 축 분리, "schema/cross-ref/fixture 검증 registry" 정직 문구. |
| **Q5 Track A CodeQL (auditai/codeql.py)** | **4** | 72→86→82→**96** | **머지 가능(예, r4)** — r1~r3 16건 반영, r4 "결함 없음". 아래 상세. |
| **G2 over-flag 수정 (gates.py/run.py, 실 FastAPI 발견)** | **설계1+코드8** | 78→82→78→84→88→94→82→**95** | **sign-off(예, r8)** — 실 tiangolo/fastapi over-flag 제거 + planted CWE-78 reliable. 아래 상세. |

### Q5 (Track A CodeQL 통합) — 3라운드+ 상세
- r1(72): SARIF severity fallback(result→rule default→problem.severity), AI-라인 필터 basename **unique-only**(cross-dir false match 차단), `_norm` proper "./" strip, finding_id 전역유일, **codeql_status.json**(stage/returncode/stderr/version 진단·재현성), build_python_db rmtree 제거(--overwrite 위임), FlowEvidence split-config "V1.5 미산출" 명시. (8건)
- r2(86): basename 폴백을 finding 경로가 `../`/absolute 면 금지(보존 의도 유지), CodeQL 미설치 케이스도 codeql_status 기록. (2건)
- r3(82): `_plain_rel` 을 Windows drive(`C:/`,`C:\`)·URI(`file://`) absolute 까지 차단, codeql_status 주석 정확화. (2건)
- r4(96): **머지 가능, "결함 없음"** — Windows/URI absolute 차단·주석 정확화 확인. **Q5 종결.**

### G2 over-flag 수정 (실 FastAPI repo 첫 실행에서 발견) — 설계판정 1 + 코드 QA 8라운드 상세
**발견**: 실 tiangolo/fastapi(1129 .py)에 planted CWE-78 PR 실행 → 탐지는 됐으나 repo-wide 탐지가 transitive
starlette(44)/strawberry(1)를 잡아 `FRAMEWORK_SOURCE_MODEL_MISSING` over-flag → 주 용도(실 FastAPI)에서
항상 "신뢰불가". codex 적대 루프가 내 수정이 도입한 fail-open/over-flag 회귀까지 반복 적출.
- **설계판정**: over-flag 결함 확정 + 내 초안("변경 파일에 framework 있으면 repo-wide 무시")의 구멍(혼합 PR)
  지적 → **확정 설계 "changed-file primary + frameworkless-changed-file fallback"**(트리거=변경 framework
  공집합이 아니라 **framework 없는 변경 .py 존재**). 대안 ①(subsumes)②(route 탐지)③(per-finding status)는
  MVP 부적합/위험 기각.
- r1(78): ① same-file helper-only(case A 가림) ② case A 에서 dep-fallback 비활성 회귀.
- r2(82): ② 확정=(a) README 문서화. ① uncertain 이 모든 positional arg 검사 → over-flag 회귀.
- r3(78): callee qualifier 무시(`obj.import_module` 오인), uncertain "fail-closed" 계약 불일치((B) 채택).
- r4(84, 조건부): dyn regex/grep 함수명 경계, importlib alias 계약 누락, fail-closed 문구.
- r5(88, 조건부): dyn regex/grep 함수명-`(` 공백, alias 미탐지 (b)문서화+계약테스트, fail-closed 잔재.
- r6(94, **예**): 비차단 2건(fail-closed 용어, repo-wide 정적 grep multiline string 오탐).
- r7(82): **내 r6 "정적 grep→AST 통일"이 도입한 회귀** — 후보 grep line-anchored 라 line-continuation
  import 누락(under-detection) + 후보 show/parse 실패 조용히 skip(fail-open).
- r8(95, **예 — sign-off**): 토큰 후보 grep+AST 확정, show 실패 GitError 전파·parse 실패 incomplete→NOT_RUN,
  fail-closed/MODEL_MISSING 용어 분리. 3건 전부 "닫힘, 수정안 없음". **실 fastapi over-flag 제거 + planted
  CWE-78 = G2 PASS/findings_present/reliable** 실증. 235 tests pass.
- 핵심 산출: `FrameworkScope(changed/repo_wide/has_frameworkless_changed_py/uncertain_changed_py/
  repo_wide_incomplete)` + `_dynamic_import_spec`(callee/대상 인자 정밀) + `_repo_wide_frameworks`(토큰 후보→
  AST 확정, fail-closed). README ⑥/⑧ 한계 명문화.

### Q2 (P0 통합/acceptance) — 4라운드 상세
codex 가 self-review 발견(효과 갭·Track B status·KB 미배선)을 P0 차단/계약불일치로 확정 + 추가 발굴. 핵심: "docs/효과 주장 ↔ 실제 구현" 정합화로 좁힘.
- r1(74): R2-1 G1실패 7종 artifact / R2-2 Track-B status 충돌(track_a_required 도입) / R2-3 G3 efficacy 재정의(synthetic=plumbing) / R2-4 효과 갭→owasp_sourced corpus 신설+MVP범위 명시 / R2-5 KB 미배선 고지 / R2-6 G4 실제 고지문 검증.
- r2(86): Track-B-only 분기가 G3 우회 → G3>G4 검사 추가. README LLM judge 과장 정정. "4-state" 문구→대표 9상태+exit bucket.
- r3(92): **머지 가능=예**. MINOR 3(G1실패 track_a_required 메타/resolver docstring/03 로드맵행).
- r4(92, low): MINOR 3 수정 확인, 회귀 없음. 테스트 194개 통과.
| **CLI / KB정합 / CodeQL통합(P0-3b)** | — | **미검증** | Q3/Q4/Q5 (Q1 변경 반영 후 검증 예정) |

### Q1 (run.py + gates.py + G2 framework source 검증) — 8라운드 상세
codex 적대적 루프가 핵심 불변식("빈 결과 오독 금지")을 깰 **fail-open 경로 다수**를 실측으로 잡아 닫음:
- r1(68): G2 가 per-run `source_count` int 로는 프레임워크별 검증 불가 → **매트릭스 기반 재설계**(`gate_g2(frameworks, unvalidated, target_type)`), `CodeqlValidation` 제거→s2_completed 파생, `--run-codeql` 만으론 프레임워크 코드 hard-fail 이던 통합공백 확인.
- r2(86): CodeQL **버전 결합** 누락(매트릭스=2.25.6 검증본인데 다른 버전서 G2 PASS=거짓정직성) → `validation_codeql_version` 가드. wheel 패키징 확인. run_track_a→None 실패경로 테스트.
- r3(78): r2 수정이 fail-OPEN 도입 → **fail-CLOSED 전환**(버전없는 매트릭스 불신, detect_frameworks grep 장애 전파→G2 NOT_RUN, grep 예외 정규화, grep 경계).
- r4(82): `frameworks=set()` 명시입력 우회 + `import os, fastapi` 다중import 과소탐지 → union(ADD만)+패턴확장.
- r5(90): 동적 import(`import_module("fastapi")`) 미탐지 → 리터럴 양성탐지 + **의존성 매니페스트 fallback**(선언-미탐지→fail-closed).
- r6(86): dep-fallback 을 `--framework` 로 우회가능 → `declared - detected`. part-1 **AST 전환**(주석/문자열 오탐 제거, keyword-arg 포착). 변수인자 동적 import 는 out-of-scope 문서화.
- r7(96): **머지 가능=예**. 잔여 MINOR 2건(상대import 오탐, 진단문구).
- r8(94): MINOR 수정 확인, 머지 가능 유지. 테스트 179개 통과.

리밋 해제 후 남은 검증: [CODEX_VERIFICATION_QUEUE.md](CODEX_VERIFICATION_QUEUE.md) Q2~Q5.
