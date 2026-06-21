# CODEX 검증 큐 / 현황

> codex 적대적 검증(codex-review) 진행 현황. 라운드별 점수·지적·수정 상세는
> [CODEX_HISTORY.md](CODEX_HISTORY.md). transient working 파일(`.codex-prompt-*`/`.codex-out-*`)은
> step 종료 시 삭제(.gitignore).

## 현황 요약
모든 codex 검증 항목 종결. **Q1~Q5 + G2 over-flag 전부 머지 승인**, **235 tests pass**. 실 tiangolo/fastapi
end-to-end 검증(planted CWE-78 → G2 PASS / findings_present / reliable)으로 over-flag 제거 실증 완료.
남은 것은 청사진(docs/03) 로드맵(post-MVP, 별도 phase): S1 Semgrep/KB 후보탐지, S3 LLM judge, load_kb
배선, Starlette/Strawberry custom routing source model, cross-language.


## 검증 완료 (codex 머지 승인)

| 항목 | 라운드 | 점수 | 결과 |
|---|---|---|---|
| **Q1** run.py+gates.py+G2 재설계 | 8 | 68→…→94 | ✅ 머지 가능 |
| **Q2** P0 통합/acceptance | 4 | 74→…→92 | ✅ 머지 가능 |
| **Q3** CLI | 2 | 78→92 | ✅ 머지 가능 |
| **Q4** KB/fixtures/eval/README | 3 | 82→88→94 | ✅ 머지 가능 |
| **Q5** Track A CodeQL | 4 | 72→86→82→96 | ✅ 머지 가능 |
| **G2 over-flag** 수정(실 FastAPI 발견) | 설계1+코드8 | 78→…→94→82→95 | ✅ sign-off |

전 항목 상세: [CODEX_HISTORY.md](CODEX_HISTORY.md). 현재 **235 tests pass**. **Q1~Q5 + G2 over-flag 전부 codex 머지 승인 완료.**

## G2 over-flag (실 FastAPI repo 첫 실행에서 발견) — ✅ 종결
- 실 `tiangolo/fastapi`(1129 .py) full 루프 → planted CWE-78 탐지했으나 repo-wide 탐지가 transitive
  starlette/strawberry 를 잡아 MODEL_MISSING over-flag(주 용도에서 항상 신뢰불가).
- **확정 설계**: "changed-file primary + frameworkless-changed-file fallback"(트리거=framework 없는 변경 .py
  존재). 불확실성 신호(parse 실패/변수 동적 import)도 보강 트리거. repo-wide 는 토큰 후보 grep→AST 확정
  (문자열/주석·메서드·공백 속성 무오탐, line-continuation 포착, show/parse 실패 fail-closed).
- **실증**: 실 fastapi over-flag 제거 → planted CWE-78 = G2 PASS / findings_present / **reliable**. 상세
  [CODEX_HISTORY.md](CODEX_HISTORY.md) G2 섹션(설계판정 1 + 코드 QA 8라운드).

## 핵심 성과 (codex 적대 루프가 잡은 것 — self-review 만으론 못 잡았을 것)
- **fail-open 다수 차단**(Q1): G2 매트릭스+버전결합, detect_frameworks AST+repo-wide+dep-fallback,
  동적 import, 명시 frameworks 우회 — 전부 "빈 결과 오독 금지" 위반 경로.
- **효과 갭 확정+정합화**(Q2): bare-param taint 미탐지 → MVP=source-bearing taint 로 좁히고
  `eval_targets/owasp_sourced`(6/6 실측) 신설, S1/KB/LLM=로드맵 명시. Track-B-only status(track_a_required).
- **KB '쓰는 척' 차단**(Q4): test_fixture 존재검증 추가(미배선 forward registry 정직 고지).
- **CodeQL 통합 견고화**(Q5): SARIF severity fallback, AI-라인 필터 false-match 차단, 진단 artifact.

## codex 리셋(19:18) 후 일괄 검증 결과 (2026-06-21 19:24~)
3건 모두 발사·판정 완료. 출력: `docs/.codex-out-{s1e2,s2func,s2integ}.txt`.

### 1. S1 r5 (recall-first 판정) — 방향 OK, 단 **실 FN/배선 갭** 지적(미반영, 후속)
codex: "방향은 맞지만 현재 코드가 주장한 S2 evidence 필터를 실행하지 않으며, S1 recall 에도 실 FN 이 남음."
- [상] `.execute(query)` 선행변수 SQLi FN(진짜 fail-open): `q=f"..{x}"; cur.execute(q)` 는 인자가 `Name` 이라 후보 안 됨(`candidates.py:146` `_is_dynamic_string` 가 직접 f-string/`+`/`%`/`.format` 만 동적으로 봄). → **수정안**: route 안 `execute(Name)` 후보 유지 + 최소 intra-function assignment 추적. **[판정: 타당, 후속 — S1 recall 보강 단계]**
- [상] yaml module-attribute rebinding FN 부분 잔존(`yaml.SafeLoader=yaml.Loader` 후 사용). [판정: 타당, 후속]
- [중] candidate_inventory 가 항상 FINDINGS_PRESENT 오염(아래 §3 verdict-C 와 동일 이슈). [판정: 타당, verdict-C 에서 해소]
- [중] 범위 과장: "S1" 이 아니라 "known-KB AST seed scanner" 로 부르라. [판정: 타당, 문서 표기 교정]

### 2. S2 함수 CODE QA — **35%/머지불가 → 수정 완료, 재검토 중**
codex 가 fail-closed 핵심(exact correlation)이 깨졌다고 7건 지적. **전부 코드 대조해 타당 판정 → 수정**(자세히 아래 "S2 함수 fail-open 수정" 섹션). 306 tests pass. 재검토 프롬프트 `docs/.codex-prompt-s2func2.md` 발사(`bhr44dtok`).

### 3. ★S2 run.py 통합 설계결정 — **권고안 C / codex 확신도 88%**
- **B(병존)는 "실패 은폐"**: evidence/llm_gate 를 만들면서 status 는 direct findings 로 FINDINGS_PRESENT 유지 = S3 미판정을 알면서 exit 1 성공 finding 으로 포장(`cli.py:35-43` 이 SEMANTIC_JUDGE_NOT_RUN 을 hard-fail 로 분류하는데 그걸 우회). [CRITICAL]
- **즉시 A(폐지)도 증명 부족**: S3/S4 부재라 파이프라인 완성 증거가 없음.
- **권고 C(채택)**: **S3 FakeEngine + 최소 S4 를 먼저** 만들고 → **그 다음 한 번에 full switch**. direct CodeQL findings 는 `RunReport.findings` 에서 빼고 필요시 `legacy_codeql_findings.jsonl` 비권위 진단 artifact 로만 남긴다.
- **내 판정: 수용**(타당). 이게 사용자 "5단계가 완벽히 돌아가도록" 와도 정합 — S3/S4 까지 만들고 통합하면 owasp_sourced·실 fastapi 가 judged FindingReport 로 정직하게 산출.

## S2 함수 fail-open 수정 상세 (codex S2func r1 35% → 반영, `auditai/codeql.py`)
- **prim_hit 제거**(CRITICAL): `correlate_candidate_evidence` 가 sink span 만 본다(primary 만 겹쳐도 통과하던 fail-open 제거). codeFlow 없을 때만 parse 에서 sink=primary fallback.
- **_spans_overlap 정밀화**(CRITICAL): 단순 범위교차 → `a.start_line<=rsl<=a.end_line`(result sink 가 후보 call span '포함') + 같은 라인 col 교차 강제(disjoint reject) + `rsl<=0`(누락 region) reject. **col exact 동일은 의도적 비요구**(AST call span vs CodeQL sub-node 앵커링 차이로 exact 면 전면 FN — 재검토에서 타당성 재확인 요청).
- **_region 누락→0 sentinel**(MAJOR): `or 1` 제거(line 1 위조 차단).
- **threadFlow 별 result 분리**(MAJOR): `parse_codeql_taint_results` 가 threadFlow 마다 `CodeQLTaintResult` 1개 → 다중 sink 모호성을 `len(matches)!=1 reject` 가 포착.
- **CWE 정확 일치**(MAJOR): `_cwe_compatible` 정규식 `CWE-0*(\d+)` 번호 일치(선행 0 무시), 부분문자열(CWE-7⊂CWE-78)·CWE-unknown·capability_id-없음 무조건통과 제거 → fail-closed.
- **evidence_backend_version 'unknown' 위조 금지**(MINOR): `codeql_ver` 없으면 evidence 미산출.
- **경계 테스트 7종 추가**: primary-only / col disjoint / missing region / multi-threadflow / CWE mismatch·prefix·unknown / no-version. (306 tests pass.)

## 다음 구현 순서 (verdict-C 확정)
1. **S2 함수 재검토(`bhr44dtok`)** 결과 반영 → S2 함수 sign-off.
2. **S3 PLAN(docs/06 §4 CLI 멀티엔진) codex 검증** → **S3 구현**(`judge.py`: JudgeEngine + Claude/Codex/Gemini CLI + FakeEngine + graceful degrade) + FakeEngine 결정적 테스트.
3. **S4 최소 구현**(`report.py`: judged 후보 → FindingReport draft, vulnerability_confirmed=False).
4. **S2 run.py 배선 + full switch**: `run_track_a_sarif`→`parse_codeql_taint_results`→`correlate_candidate_evidence(scan.taint_candidates,...)`→`compute_llm_eligible`→S3→S4. direct findings 폐지(legacy artifact 강등). evidence 없는 TAINT 후보는 RELIABLE FINDINGS_PRESENT 금지(별도 처리 — S1 r5 §3 이슈 동시 해소).
5. **S1 recall 보강**: `execute(Name)` route 후보 유지(intra-function assignment 추적) + yaml rebinding(별도 PLAN 검증 후).

## ⏳ 병렬 빌드 후 CODE QA (2026-06-21, 432 tests pass)
- **engine-v2 보안 QA(`bj94zik1d`) = 68%/머지불가** — 9건 수정 필요(다음 집중):
  1. [High] behavioral probe 가 실제 도구차단 증명 못 함("UNABLE" 출력도 통과). → stdout+**stderr**+transcript 까지 토큰 scan, 도구 실행 trace/deny/audit 검증, 증명 불가면 passed=False. write-side-effect(canary 수정 시도→불변 확인)가 read-token 보다 강함.
  2. [High] behavioral probe stderr/transcript 누출 미검사 → CompletedProcess 전체 + 엔진별 transcript/config dir probe-temp 강제 + cleanup 전후 scan.
  3. [High] `usable` 우회 가능 → `CapabilityProbeResult.usable = stdin and flags and behavioral_probe_run and behavioral_probe_passed` 고정.
  4. [High] behavioral cache 가 프로세스 전역 → run context 바인딩, key=config/env fp+help argv+safety argv+CLI ver+sandbox, run 시작마다 clear.
  5. [High] binary repo-internal 차단이 factory 미적용 → `build_judge_engine(repo_root=)` + env override·PATH-resolved 모두 `resolve().relative_to(repo_root)` reject.
  6. [High] Claude transcript 격리 미배선 → start_session/engine 생성 시 전용 temp `CLAUDE_CONFIG_DIR` env 주입, cleanup 실패→EngineError→FAILED, 아니면 claude unusable.
  7. [Med] `_fixed_comspec` SystemRoot env 신뢰 → GetSystemDirectoryW 또는 canonical 검증.
  8. [Med] close 실패가 parse 실패에 가림 → close 실패 우선 기록/병합.
  9. [Low] UUID 검증 느슨 → `uuid.UUID()` round-trip.
- **KB QA(`b819cwlvl`)**: 진행 중(다음 tick 확인). S4/S1 QA: 미발사(다음 배치).
- **분리 가능**: 오케스트레이터는 FakeEngine 으로 end-to-end 가능 → engine-v2 실CLI 보안 하드닝과 병행/후행 가능.

## ⏳ rework 후 잔여 (오케스트레이터 직후 "최종 정확도 패스"에서 처리)
- **S1/KB 재QA(`bw7h16rtl`)=78%/조건부** — 핵심 dedup/executescript 회수 OK, 정확도 4건 잔여:
  1. [중·correctness] `executescript` 대표-sink 오귀속: duck tie-break 가 generic 없으면 sink.id 사전순 → `cur.executescript` 가 `sink.sqlite3.connection.executescript` 로 오라벨. 테스트는 `"executescript" in sink_spec_id` 만 봐서 못 잡음. → **generic `sink.cursor.executescript` 추가 + duck 대표=generic 고정**(execute 와 동형) 또는 receiver provenance 추론.
  2. [중] exact import-resolved 보존 테스트 공백: `sqlite3.Cursor.execute`/`Connection.execute`/`aiosqlite.Connection.execute` 가 specific sink 로 남는지 검증 추가.
  3. [중·FN] `executemany` 미등록 — DB-API SQLi recall 주장하려면 `cursor/connection.executemany`(generic+sqlite/aiosqlite) 추가 + fixture + duck allowlist, 아니면 "S1 scope 밖" 명시.
  4. [하·perf] dynamic-name 이 call 마다 full `ast.walk` → O(calls*fn) → function stack 에 `(fn,dynamic_names)` push 또는 id(fn) 캐시.
- **engine-v2**: 에이전트 자체 codex 4R→92%/조건부(조건=테스트 충족). contract fix #3 적용됨. (필요시 통합 후 1회 재확인.)
- **미발사 QA**: S4 report, S1-recall(원래 빌드분), StageArtifact s3_completed⟺all-judged invariant nit, artifacts3 잔여. → 최종 패스에서 일괄.
- **다음(키스톤)**: 오케스트레이터(run.py stage 시퀀서 + 단독실행/resume CLI + S2 evidence/S2.5 gate/S3 FakeEngine/S4 배선, verdict-C full switch) → 그 후 최종 정확도 패스 + end-to-end 실 repo 검증 + FN/FP 측정.
