# AuditAI — 방향성 검증 및 교정 기획안 (v0.6)

> 상태: **codex 5차 sign-off 완료 — 96/100, "기술 설계는 착수 가능 수준으로 닫힘, 남은 것은 §7 사용자 제품결정뿐".** (점수 추이 42→68→78→86→96)
> 개발 착수 = §7 사용자 제품결정 확정 후. 누적 반영: codex 1차 15 + 2차 8 + 3차 4 + 4차 5 + 5차 QL preamble/형식 보정 = 전부 수용. 변경 로그 §9.

## 1. 프로젝트 목표 / 정직한 포지셔닝

- **궁극 목표**: GitHub 레포에서 AI(Claude)가 작성한 코드의 취약점을 효율적으로 찾는다.
- **정직한 포지셔닝 (codex F8/F10)**: 새로운 탐지기가 아니다. 탐지는 기존 SAST(CodeQL)가 하고, AuditAI의 기여는 ① **AI 귀속 인지형 트리아지/우선순위화**, ② **LLM 기반 익스플로잇 검증(FP 저감)**이다. 정확한 한 줄: **"AI-attribution-aware security triage + LLM exploitability verification layer over existing SAST."** "repo-wide AI 코드 취약점 탐지"는 과장 — 사용 금지.
- **MVP 가치 지표 (codex R2-5/R2-6; 이것만으로 가치 정의)**: ① AI 관련 alert 선별 precision, ② 리뷰량 절감(review volume reduction), ③ LLM FP 저감률, ④ 놓친 AI 관련 CodeQL alert 비율(miss rate). **"LLM이 CodeQL보다 더 잡는다"는 추가-recall 주장은 §6의 외부 corpus로 숫자 증명 전까지 금지.**

## 2. 핵심 판정 (사용자 두 질문에 대한 답)

### 2.1 Gemini 4단계 기획 → **전제 ACCEPT / 현 설계 REJECT-AND-REVISE**

방향(AI 코드 우선 + static 도달성/LLM 의미판정 분업)은 합리적이다. 단, **"LLM+static이 CodeQL 단독보다 더 잡는다"(IRIS ICLR2025 등)는 향후 탐지확장 연구 근거로만** 둔다(MVP 가치 주장 아님 — codex R2-5). Gemini 4단계 실행 메커니즘은 깨져 있어 §4로 교정.

### 2.2 noperator/slice 벤치마킹 → **패턴만 차용, 포크 안 함 (codex F15)**

- **근본 불일치**: slice 시작점은 CodeQL 쿼리 결과가 유일·배타적(C/C++ UAF 강결합) — 우리의 "AI 코드 시작점"과 무관.
- **차용(패턴만)**: 결과 JSON-schema, 프롬프트 템플릿, LLM worker pool(동시성), ranking. 코어 슬라이싱/분석은 CodeQL 쿼리팩+자체 구현. **포크 안 함.**
- **2패스 LLM은 AuditAI 자체 설계 (codex R2-8)** — slice에서 차용하는 것은 schema/prompt/worker/ranking뿐. slice의 "2단계 LLM"은 블로그 서술(README는 단일 `filter`)이라 레퍼런스 인용 금지.

## 3. phoenix 실측 (전제 검증 — codex F6/F7)

- 전체 14,076 커밋. **탐지된 Claude-신호 866개 중** 직접 author=Claude 43, `Co-authored-by` 트레일러 823(main 179). → "트레일러 ≈95%"는 ‘탐지된 커밋 내 비율’일 뿐, ‘전체 AI 코드의 95%’가 아님.
- 안정적 키: 트레일러 `noreply@anthropic.com`. `claude[bot]`은 NAME으로 구분(id 41898282는 github-actions 공유). "ci: Add Claude Code Workflow" 류 ~123건은 코드 아님 → 제외.
- 언어: **TS/TSX ~2,939 > Python ~1,267** + GraphQL(Strawberry)/OTLP/REST 경계 → 폴리글랏.
- **provenance 손실 = 침묵 FN (codex F6/F7)**: squash/rebase/amend/cherry-pick/리포맷/conflict/생성파일/vendoring/파일이동에서 귀속 소실. **commit 트레일러 ≠ line-level authorship** → 라인 귀속은 §5 Step1에서 별도 산출.
- **입력 계약**: 워크스페이스에 `.git` 없음(`repomix-output.md`만) → Step1 재현 불가. §5 전제계약 참조.

## 4. 핵심 교정 (codex 1차 15 + 2차 8 반영)

| # | 등급 | 교정 |
|---|------|------|
| C1 | CRITICAL | **메커니즘(F1/F2 + R2-1)**: `reachableByFlows` 임의노드 양방향 chop은 폐기. → **표준 taint(untrusted source 카탈로그 → dangerous sink 카탈로그) path-problem 쿼리**. AI 라인 교차 판정은 **(MVP) SARIF `codeFlows[].threadFlowLocations` 후처리 ∩ AI 라인 구간**, **(엄밀) split-flow 쿼리 `source→AI노드` ∧ `AI노드→sink`로 AI 노드가 실존 경로에 있음을 보장**. 주의: 단일 witness path는 대체 경로를 놓칠 수 있으므로(FN) 엄밀판정은 split-flow로. AI 라인은 경로 어디든(source/sink/transform/sanitizer) 가능 — 역할은 보고 메타로만. |
| C2 | CRITICAL | **v1 source 모델링(F3) + 검증 매트릭스(R2-4)**: v1부터 Python 경계 source 정의 — FastAPI/Starlette request(body/headers/query/path), Strawberry/GraphQL resolver args, 파일 업로드, env/config, 사용자통제 DB 필드. **"CodeQL 기본 제공"을 가정하지 말 것**: 각 source에 대해 [CodeQL 기본 탐지 O/X, custom model 필요 여부]를 테스트로 잠그는 **기본제공 검증 매트릭스**를 산출물로. phoenix는 Strawberry/Starlette라 미검증 시 source FN 직격. cross-language(TS↔Python) 전파만 v2. |
| C3 | CRITICAL | **엔진(F4)**: **CodeQL-only Python 베이스라인=MVP**. Joern은 동일 평가셋에서 recall/FN 우위 입증 시에만 추가하는 실험 백로그. |
| C4 | MAJOR | **CodeQL 사용법(F5 + R2-3)**: `codeql database create .codeql-db/python --language=python --source-root=.`. Python은 빌드 불필요 → **build-mode 생략 또는 `--build-mode=none` 사용 가능**("컴파일 전용 옵션"이라는 v0.2 서술은 사실오류였음, 정정). |
| C5 | MAJOR | **귀속 정직화(F6/F7)**: "확정 AI"(트레일러/직접 author) vs "추정 AI"(점수화: author+committer+trailer+PR body+bot comment+workflow artifact+Claude config+변경파일 패턴) 분리. provenance 손실 = FN 리스크 명시. 고정 SHA + raw `git log --format` + 귀속 벤치마크 스크립트를 산출물로. |
| C6 | MAJOR | **스코프/포지셔닝(F8/F10)**: MVP="phoenix **Python 서버측** taint triage 프로토타입". "repo-wide" 삭제. |
| C7 | MAJOR | **sink 카탈로그 + 한계(F9 + R2-7)**: **taint-shaped(탐지대상)**: OS cmd(CWE-78), code exec/eval(94/95), SQLi(89), path traversal(22), SSRF(918), unsafe deserialize(502), template injection, open redirect, file write. **non-taint-shaped**: authz bypass/IDOR/tenant isolation/business-logic은 **"범위 밖"이 아니라 "탐지불가 RISK"로 리포트에 명시**하고, **Track B(LLM+policy/spec 기반 검증)**를 백로그로 분리(§7 사용자 결정). "sink 미정의=탐지 불가"를 리포트에 명기, catalog miss를 negative-control로 측정. |
| C8 | MAJOR | **barrier(F11)**: MVP는 hard-cut 아닌 **annotate**(슬라이스에 검증/이스케이프/바인딩 유무 메타). hard barrier는 recall 손실 0 증명 시에만. 도달성은 static, LLM은 sanitizer 충분성 판단. |
| C9 | MAJOR | **Tree-Sitter(F12)**: 함수 **본문 경계 추출**(LLM 프롬프트 조립)만. 의미 컨텍스트(경로/imports/callsite/프레임워크 모델)는 CodeQL에서. |
| C10 | MAJOR | **비용(F8/F10)**: static(DB+쿼리)=풀스캔(절감 없음). 절감은 LLM 단계만. 증분/캐시 DB로 완화. |
| C11 | MAJOR | **평가(F13 + R2-6)**: §6 참조 — 목적별 분리 + 합격 수치. |
| C12 | MINOR | **slice 포크 안 함(F15)**: 패턴만. |

## 5. 교정된 권장 아키텍처 (MVP = phoenix Python 서버측, CodeQL-only)

**전제 계약**: 입력 = `.git` 포함 full 클론. 인덱싱 스냅샷 **commit SHA 고정**. 귀속/슬라이스/평가 동일 SHA.

- **Step 0 — 평가 게이트(단계 분리, codex R3-4)**: **T1/T2 = 개발 착수 전 게이트**(엔진 sanity·귀속 정확도), **T3/T4 = MVP 구현 후 게이트**(회귀·트리아지 정밀), **T5 = real-world 효과 주장 전 게이트**(외부 corpus). T5 미확보가 개발 착수를 막지 않도록 분리. §6 참조.
- **Step 1 — AI 라인 산출(line-level, codex R2-2 + R3-3)**: 고정 SHA에서 **`git blame --line-porcelain`**로 line→commit 매핑 → commit→AI(확정/추정 점수, C5). **산출물 스키마**: `{file, line_range, commit, attribution_state, ai_confidence, label_source, loss_modes[], manual_label}`. `attribution_state ∈ {confirmed_ai, probable_ai, human, unknown_due_to_history_loss}`. **loss_modes 명시 플래그**: `squash, rebase, amend, cherry_pick, conflict_resolution, reformat, generated, vendored, file_move`. blame 노이즈(사람 리포맷→FN, Claude 리포맷→FP)와 위 손실모드를 precision/recall 리스크로 노출(숨기지 않음). generated/vendor 경로 제외. **평가용 수동 라벨 샘플** 확보.
- **Step 2 — CodeQL DB + 표준 taint**: C4 명령. security-extended + Python 경계 source 모델(C2, 검증 매트릭스) + sink 카탈로그(C7). DB는 SHA별 캐시.
- **Step 3 — 경로 + AI 라인 교차(C1, codex R3-1/R3-2 + R4)**: AI 라인 구간 ↔ CodeQL 노드 매핑이 핵심. CodeQL `Flow::flow(a,b)`는 a=config의 isSource·b=isSink일 때만 성립하므로, 임의 중간 노드를 끼우려면 **두 config로 분리**해야 한다(codex R4-1/R4-2). **QL 계약**:
  ```ql
  import python
  import semmle.python.dataflow.new.DataFlow
  import semmle.python.dataflow.new.TaintTracking
  // aiLine: Step1 산출물에서 '단일 방식'으로 주입 (codex R4-3). top-level non-member predicate.
  //   택1: data-extension YAML 주입, 또는 Step1이 aiLine fact .qll 생성. 병기 금지.
  //   file 정규화(codex R4-4): getRelativePath()와 동일한 forward-slash repo-relative 경로.
  extensible predicate aiLine(string file, int s, int e);
  // OriginalConfig = Step2의 실제 source/sink 카탈로그(auditAiSource/auditAiSink). 별도 .qll이면 alias (codex R5).
  module OriginalConfig implements DataFlow::ConfigSig {
    predicate isSource(DataFlow::Node n) { auditAiSource(n) }
    predicate isSink(DataFlow::Node n)   { auditAiSink(n) }
  }
  predicate aiOverlap(DataFlow::Node n) {
    exists(Location loc, string f, int s, int e |
      aiLine(f, s, e) and loc = n.getLocation() and
      loc.getFile().getRelativePath() = f and
      loc.getStartLine() <= e and loc.getEndLine() >= s)
  }
  module SourceToAiConfig implements DataFlow::ConfigSig {
    predicate isSource(DataFlow::Node n) { OriginalConfig::isSource(n) }
    predicate isSink(DataFlow::Node n) { aiOverlap(n) }
  }
  module AiToSinkConfig implements DataFlow::ConfigSig {
    predicate isSource(DataFlow::Node n) { aiOverlap(n) }
    predicate isSink(DataFlow::Node n) { OriginalConfig::isSink(n) }
  }
  module SourceToAi = TaintTracking::Global<SourceToAiConfig>;
  module AiToSink   = TaintTracking::Global<AiToSinkConfig>;
  // AI가 경로 '위 어디든'(중간/소스 자체/싱크 자체) 있는 실존 흐름만 채택. ai==source/ai==sink 포섭.
  predicate aiOnFlow(DataFlow::Node source, DataFlow::Node ai, DataFlow::Node sink) {
    OriginalConfig::isSource(source) and OriginalConfig::isSink(sink) and aiOverlap(ai) and
    (ai = source or SourceToAi::flow(source, ai)) and
    (ai = sink   or AiToSink::flow(ai, sink))
  }
  ```
  - **path 증거(codex R4-5/R5)**: 위 `aiOnFlow`는 triage row 선택용(데이터플로우). 경로 시각화는 `SourceToAi::PathGraph`·`AiToSink::PathGraph`를 각각 import한 **두 개의 `@kind path-problem` 쿼리**로 산출. 형식(첫 컬럼=PathNode 위치): `from SourceToAi::PathNode source, SourceToAi::PathNode ai where SourceToAi::flowPath(source, ai) select ai.getNode(), source, ai, "..."` (AiToSink도 동일 패턴).
  - **(MVP 휴리스틱)** SARIF `threadFlowLocations` ∩ AI 라인 구간: verdict-state = **`heuristic_positive_only`** — 양성 신호 전용. **"경로에 AI 없음"을 음성 판정에 쓰지 말 것**(witness ≠ 전체 경로 열거 → miss). 엄밀 판정은 위 split-config로.
  - 함수=분석단위/라인=귀속단위(혼합 함수는 경로가 AI 라인을 실제 통과할 때만). sanitizer annotate(C8).
- **Step 4 — LLM 검증(2패스, 자체 설계)**: Tree-Sitter 본문 조립(C9) + CodeQL 경로 메타 → 저가 triage(FP 컷) → flagship(Claude) 익스플로잇 심층. 도달성=static 확정, LLM=분류·설명·sanitizer 충분성. rank.
- **백로그**: Joern 비교(C3), cross-language v2(C2), TS 트랙, authz/IDOR Track B(C7).

## 6. 평가 설계 (1급 산출물 — codex F13 + R2-6, 목적별 분리)

| 트랙 | 측정 목적 | 방법 | 합격 기준(초안) |
|---|---|---|---|
| T1 엔진 sanity | known-CWE 탐지력 | 공개 Python 보안 벤치마크(SecurityEval/PyT 등) | recall/precision 기준선 충족 |
| T2 귀속 정확도 | 확정/추정 AI 식별 | 수동 라벨 샘플 | precision·recall + 손실률 보고 |
| T3 회귀/민감도 | **(효과 입증 아님)** | phoenix AI 라인에 controlled mutation 주입 | 주입 변이 탐지율(회귀 테스트) |
| T4 트리아지 정밀 | AI 관련 alert 선별 | phoenix 전체 CodeQL alerts와 shadow 비교 | 선별 precision + LLM FP 저감률 |
| T5 실제 효과 | **real-world recall** | 외부 labeled vuln corpus 또는 historical vuln-fix commit revert | 실제 취약점 탐지율 |
- **게이트 분리(codex R3-4)**: **T1/T2 = 개발 착수 전 게이트**, **T3/T4 = MVP 구현 후 게이트**, **T5 = real-world 효과 주장 전 게이트**. T5 외부 corpus 미확보가 개발 착수를 막지 않도록 분리.
- **순환논증 주의(R2-6)**: T3(우리가 만든 변이를 우리 카탈로그로 탐지)·T4(CodeQL alert 위 정밀)는 효과 입증이 아님. **real-world 효과는 T5(외부 corpus)로만.** phoenix는 알려진 CVE가 없어 T5는 외부 corpus 의존 — phoenix 단독으로는 real-world recall 입증 불가임을 명시(§7-4 선택과 연결).

## 7. 사용자 제품 결정 (엔지니어링 기본값은 §4에서 잠금 — codex F14)

1. **포지셔닝 수용**: "AI 코드 취약점 탐지기" → "AI 귀속 인지형 SAST 트리아지+LLM 검증 레이어"(§1) 재정의를 받아들이는가.
2. **MVP 스코프**: Python 서버측 우선(권장) vs 처음부터 TS 포함.
3. **authz/IDOR 처리(codex R2-7)**: MVP는 injection류 taint만(authz/IDOR는 "탐지불가 RISK" 명시) vs Track B(LLM+policy) 우선순위 상향.
4. **타겟/평가**: phoenix + 외부 labeled corpus(T5) vs phoenix 단독(real-world 효과 입증 포기).

## 8. 주요 리스크

침묵 FN(귀속 게이트/sink 미정/source 미모델링/단일 witness path), CodeQL Python taint의 동적기능·프레임워크 미모델링 한계, blame 노이즈, LLM 익스플로잇 환각, 비용(LLM만 절감), real-world ground-truth 부재(phoenix CVE 없음 → 외부 corpus 의존), 포지셔닝 과장 시 "기존 SAST 대비 가치" 미입증.

## 9. 변경 로그

- **v0.1→v0.2 (codex 1차 15건)**: 메커니즘 'seed chop'→'taint 경로+AI라인 필터'(F1/F2), v1 source 모델링(F3), 엔진 CodeQL-only(F4), build-mode(F5), 귀속 확정/추정(F6/F7), 포지셔닝(F8/F10), sink CWE 확장(F9), barrier annotate(F11), Tree-Sitter 한정(F12), 평가 3트랙(F13), 결정 잠금(F14), slice 포크 안함(F15).
- **v0.2→v0.3 (codex 2차 8건)**: C1 구현 정밀화(SARIF threadFlowLocations+split-flow, R2-1), Step1 line-level 산출물 확정(blame --line-porcelain, R2-2), build-mode 사실정정+DB경로(R2-3), source 기본제공 검증 매트릭스(R2-4), IRIS를 향후연구로 강등(R2-5), 평가 목적분리+T5 외부corpus(R2-6), authz/IDOR 탐지불가 RISK+Track B(R2-7), 2패스 자체설계 명시(R2-8).
- **v0.3→v0.4 (codex 3차 4건)**: Step3에 AI라인↔CodeQL노드 매핑 QL 스케치(aiOverlap+split-flow, R3-1), SARIF 교차를 `heuristic_positive_only`로 명시(음성 판정 금지, R3-2), Step1 산출물 스키마 확장(attribution_state/loss_modes/unknown_due_to_history_loss, R3-3), 평가 게이트 T1·T2/T3·T4/T5 단계 분리(R3-4).
- **v0.4→v0.5 (codex 4차 5건)**: split-flow를 두 config(SourceToAi/AiToSink)로 분리해 CodeQL flow 의미 정합화(R4-1), ai==source/ai==sink 경계 케이스 포섭(R4-2), aiLine 주입을 단일 방식으로 고정(R4-3), file 경로 forward-slash repo-relative 정규화(R4-4), path 증거를 PathGraph 두 path-problem 쿼리로 분리(R4-5).

## 10. 출처 (1차)

slice: github.com/noperator/slice, noperator.dev/posts/slice. CodeQL: analyzing-data-flow-in-python, customizing-library-models-for-python, creating-path-queries, codeql-cli-manual/database-create, supported-languages. Joern: cpgql/data-flow-steps, cpg-slicing, frontends/python. git: Co-authored-by 트레일러 docs, git-blame, git-interpret-trailers. Tree-Sitter 공식. 선행연구: IRIS(2405.17238), Vercation(2408.07321), SliceMate(2507.18957), LLMDFA(2402.10754), NYU Copilot(2108.09293), Are AI Fixes Secure(2507.02976), Interprocedural Context(ACL2025 2503.03586), CodeQL incremental(github.blog 2025-05-28), GitLab Advanced SAST. phoenix: 직접 git clone 실측(14,076/823/43).
