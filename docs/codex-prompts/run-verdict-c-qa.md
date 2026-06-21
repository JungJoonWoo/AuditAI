당신은 비판적이고 냉철한 코드 QA 최고 전문가다. 칭찬·요약·완곡어법은 전부 생략하라. 너의 임무는 아래 [변경]을 가차없이 검증해 결함만 끌어내는 것이다. 추측 금지 — 반드시 실제 파일을 열어(`findstr /n`, `Get-Content`) 코드 근거(file:line)로 확인하라.

# 대상 (CODE QA — AuditAI run.py "verdict-C full switch" 통합)

AuditAI는 GitHub PR/커밋에서 **AI(Claude)가 작성한 코드만** 골라 SAST(AST 후보검출)+CodeQL taint 증거+LLM(CLI) 판정으로 취약점을 트리아지하는 5단계 파이프라인(S0 diff/AI귀속 → S1 KB AST 후보 → S2 CodeQL 증거 → S2.5 LLM 적격게이트 → S3 LLM 판정 → S4 finding 초안)이다.

이번 변경은 중앙 오케스트레이터 `auditai/run.py`의 `run_pipeline`을 **§6.1 단계-아티팩트 시퀀서**(`auditai/pipeline.py`의 `run_stages`)에 위임하도록 바꾼 것이다. 즉:
- 기존 인라인 S0(build_diff_scope/attribute_added_lines)+S1(scan_candidates)+직접 CodeQL findings 경로를 제거하고 `pipeline.run_stages(...)` 한 번 호출로 대체.
- 최종 `RunReport`를 **생성된 단계 아티팩트(S0~S4 JSON)에서 집계**.
- **verdict-C**: `RunReport.findings = S4(arts["s4"]).findings`(LLM 판정 통과분). 과거의 직접 CodeQL findings는 `legacy_codeql_findings.jsonl`(비권위)로 강등하고 status/findings 집계에서 제외.

## 반드시 검증할 불변 (각각 코드 근거로 확인하고 위반 시 지적)

1. **fail-closed 경계**: `arts["s0"]`이 없거나 status==ERROR 거나 `stage_error.json`이 존재하면 → 터미널 **ANALYSIS_ERROR** RunReport로 종료해야 한다(빈 결과를 정상/clean으로 오독 금지). 부분 산출(partial)이 OK로 "세탁"되지 않는지 확인.
2. **resolve_run_status 매핑 정확성**: 인자들이 올바른 아티팩트 필드에서 왔는지 — s2_completed=arts["s2"].s2_completed, s3_completed/llm_eligible_count/judged_count/judgement_skipped_count=arts["s3"], s0_attribution_completed=arts["s0"].completed, unknown_sink_candidate_count=arts["s1"].unknown_sink_count, candidate_inventory_count=len(arts["s1"].candidate_inventory), finding_count=len(arts["s4"].findings). 하나라도 엉뚱한 소스/기본값(특히 누락 시 True/0으로 안전측 위장)이면 지적.
3. **verdict-C 진짜 적용**: RunReport.findings가 S4에서 오는가? 과거 직접 CodeQL/`s2_findings` 주입이 여전히 findings/status에 새는 경로가 있는가? legacy 강등이 실제로 비권위(상태 계산 제외)인가?
4. **게이트/Track B 보존(직교)**: G1~G4, 프레임워크 탐지/G2(case-A/B + declared-dep fallback), Track B(detect_removed/weakened_controls)가 위임 후에도 동일 로직·동일 입력(scope=arts["s0"].scope)으로 보존되는가? 위임 과정에서 게이트가 우회/약화되지 않았는가?
5. **엔진 None 처리**: `build_judge_engine`가 (None, probe) 반환 시(=사용 가능한 CLI 없음) S3는 전원 skipped → SEMANTIC_JUDGE_NOT_RUN 으로 가야 하며, 절대 NO_VULN/clean 이 아니어야 한다.
6. **테스트 정직성(가장 중요)**: `tests/test_run.py`에서 verdict-C 때문에 바뀐 기대값이 **실제 의미 변화** 때문인지, 아니면 회귀를 숨기려 약화시킨 것인지 항목별로 의심하라. 토큰-착시(실제 동작 미검증) 테스트, 항상 통과하는 무의미 단언, FakeEngine/None 으로 우회한 가짜 통과가 있는가? end-to-end(git fixture) 및 resume(저장된 s1/s2 JSON으로 S2.5~S4 단독 재개) 테스트가 진짜 동작을 검증하는가?
7. **resume CLI**: 단계 단독 재개(`auditai stage <s> --in ...`)가 다중 입력(S2.5=s1+s2, S4=s3+s1+s2)을 올바르게 로드하고, load_stage_artifact의 fail-closed(error/partial/require_ok)를 준수하는가?
8. **회귀/예외/인코딩**: 위임으로 죽은(dead) 코드, 미사용 import, 잘못된 예외 경로(GitError 등), Windows 경로/UTF-8 처리 문제.

## 보고 형식
각 지적:
```
[심각도: CRITICAL|MAJOR|MINOR] [유형: BUG|REGRESSION|FAIL-OPEN|MISSING|TEST-ILLUSION|...]
- 주장/위치: <file:line 인용>
- 판정: <무엇이 왜 문제인가>
- 근거: <코드 인용>
- 수정안: <구체안>
```
마지막 줄에 전체 평가(0~100%, 100%=운영 투입 가능)와 진행 가능 여부(예/조건부/아니오) + 한 문장 사유.

대상 파일: auditai/run.py, auditai/pipeline.py, auditai/artifacts.py, auditai/contracts.py(resolve_run_status/RunReport/JudgeRun), auditai/gates.py, auditai/judge_engines.py(build_judge_engine), auditai/cli.py, tests/test_run.py, tests/test_pipeline.py. workdir에서 직접 열어 대조하라.
