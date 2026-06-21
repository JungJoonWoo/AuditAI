# AuditAI — 제품 비전 + MVP/로드맵 아키텍처 (v0.2)

> 상태: **codex 1차(arch) 검증 반영 완료(58→재검증 대기).** 기반: [01-direction-review.md](01-direction-review.md)(codex 96/100 기술 코어).
> v0.1→v0.2 핵심: 사용자 비전은 **로드맵으로 보존**, MVP는 **단일 루프로 잔인하게 축소**(codex arch 11건 전부 수용). 비전 자체는 유지된다 — 순서를 나눴을 뿐.

## 1. 비전 / 북극성 (사용자, 2026-06-19 — 보존)

장기 목표는 그대로다: AI-authored code 중심 **high-recall 후보탐지 → CPG/taint evidence → LLM semantic judge → multi-stage chain reasoning → 책임있는 제보**, 그리고 source/sink/sanitizer/propagator/state-boundary/chain-rule을 축적하는 **Security Knowledge Base**로 오픈소스 **CVE급 취약점·exploit chain 발굴 플랫폼**. 멀티엔진(CodeQL/Joern/Semgrep)은 후보·evidence 생성기, LLM은 판정자.

**그러나 이 전체를 MVP로 만들지 않는다.** MVP는 **핵심 루프 하나**를 분해가능하게 증명하고, 나머지는 §3 로드맵에서 **단계별 게이트**로 추가한다(codex A8: 5단계를 한꺼번에 하면 실패 원인을 source model/Semgrep noise/LLM judge/chain/disclosure 중 뭐인지 분해 못 함).

### 정직성 가드레일 (codex 1~5차 + arch)
- **G1 — firehose는 LLM 앞에서 막는다(codex A1)**: 정밀도 통제를 LLM **이전** `pre-LLM 예산 게이트`로(§2-4). "등급 표시"는 사후 분류일 뿐 큐 폭주를 못 막음.
- **G2 — 효과는 입증, 주장 아님**: CVE 발굴·추가 recall은 §5 labeled corpus의 수치로 증명 전까지 마케팅 금지.
- **G3 — 도달성은 static, 의미는 LLM**: LLM 단독 도달성/exploit 단정 금지(환각 차단).
- **G4 — 등급 분리 + 정직한 명명(codex A7)**: `static-confirmed-taint`(=high-confidence, **확정 아님**) / `candidate` / `heuristic_positive_only`를 섞지 않음. 외부 제보 전엔 항상 별도 `human-reviewed` 필요.
- **G5 — 제보 안전(codex A4)**: MVP는 외부 제보 기능 없음(§3-P6).

## 2. MVP = Slice 1 (CodeQL-only Python taint triage + LLM FP 컷)

**범위(codex A8이 지정한 최소 루프)**: 단일 엔진(CodeQL), 단일 언어(Python 서버측), taint-shaped만, 외부 제보 없음.

1. **Step 0 — AI 라인 산출**: 01 Step1 그대로(`git blame --line-porcelain`, 확정/추정, loss_modes, SHA 고정).
2. **Step 1 — CodeQL DB + 표준 taint**: 01 Step2/C4(`codeql database create ... --language=python`). security-extended + Python 경계 source 모델(01 C2 검증 매트릭스) + sink 카탈로그(01 C7, injection류만).
3. **Step 2 — split-flow aiOnFlow**: 01 Step3 QL 계약(SourceToAi/AiToSink config, `ai=source/ai=sink` 포섭, aiOverlap). 후보 타입은 **`taint_candidate` 단일**(codex A6: 다른 후보 타입은 MVP에 없음).
4. **Pre-LLM 예산 게이트 (codex A1, 신규)**: LLM 호출 **전** 적용 —
   - `CodeQL static path 없음 ⇒ LLM 금지`(휴리스틱 교차만 있으면 `heuristic_positive_only`로 두고 LLM 안 보냄).
   - `rule allowlist`(어떤 CWE/쿼리를 후보로 받을지 명시), `CWE별 후보 상한`, `repo당 LLM 호출 예산`, `(source,sink,path) dedup`.
5. **Step 3 — 최소 LLM FP triage(1패스로 시작)**: evidence pack(flow path + source/sink/sanitizer 메타 + Tree-Sitter 본문, 01 C9) → Claude가 **FP 컷 + exploitability 의견 + sanitizer 충분성**. 도달성은 static 확정(G3). (2패스/저가 triage는 비용 측정 후 P-later.)
6. **Step 4 — internal evidence memo(codex A4)**: 외부 제보 아님. finding + evidence + 등급(G4) + 한계. 사람 검토용 내부 산출물.

**MVP 등급(G4)**: `static-confirmed-taint`(static path + LLM exploitable, **확정 아님**) / `heuristic_positive_only`(SARIF 교차만, 음성 판정 금지) / `human-reviewed`(사람 검토 부착 시).

## 3. 로드맵 (비전을 단계별 게이트로 — 각 단계 '왜 미뤘나 + 재진입 조건')

| 단계 | 추가 능력 | 재진입 게이트(이게 충족돼야 시작) |
|---|---|---|
| **P2 — Semgrep shadow 후보(codex A5/A6)** | Semgrep을 추가 high-recall **shadow candidate source**로 | MVP의 LLM 예산/정밀도 안정화 후. Semgrep 단독 후보는 `candidate`등급, **CodeQL evidence로 재검증된 것만 LLM**. `semgrep_pattern` 별도 evidence 스키마. |
| **P3 — authz/IDOR Track B(결정 3)** | AI 커밋의 권한체크 제거/role 완화/middleware 우회/tenant_id 누락/broad-except/default-allow를 `authz_pattern` 후보로 수집 | taint MVP 정밀도 입증 후. policy/spec 기반 LLM 판정 설계 + `authz_pattern` 별도 evidence/등급. **자동확정 아님**. |
| **P4 — KB 확장(codex A3)** | seeded registry(§4) → propagator/state-boundary/chain-rule 축적 | 각 신규 KB 항목이 acceptance test 통과 시에만 등록. |
| **P5 — chain hypothesis(codex A2)** | multi-stage exploit chain 가설 | `typed chain schema` + hop별 `state-boundary evidence` + `manual exploitability review` + `dynamic/reproducer evidence` + `no-CVE-claim-before-human-signoff`. taint path만으로 chain 생성 **금지**. |
| **P6 — disclosure(codex A4)** | 외부 책임공개 | `human approval checklist` + `scope authorization` + `reproduction safety` + `redaction policy` + `maintainer contact workflow` + `legal disclaimer` + `no active exploitation`. 그 전까지 internal memo만. |
| **P7 — Joern 비교 / TS adapter** | 멀티엔진·폴리글랏 | 01 C3(Joern은 동일 평가셋 우위 입증 시) / language adapter로 TS. |

## 4. Security Knowledge Base — MVP = seeded model registry (codex A3)

MVP KB는 "장기 자산"이 아니라 **seeded model registry**: 01의 source/sink/sanitizer 카탈로그만. chain-rule/state-boundary/propagator는 P4 백로그.
- **항목 스키마(필수)**: `{id, kind(source|sink|sanitizer), pattern, engine_mapping, test_fixture, expected_tp_fp, owner, version}`.
- **`codeql_model_export` 하위 스키마(codex A9)**: CodeQL data-extension(Python은 **beta**)으로는 `sourceModel/sinkModel/typeModel/summaryModel/barrierModel/barrierGuardModel` 계열만 export. chain-rule/state-boundary 전체를 data-extension에 먹일 수 있다고 가정하지 않음.

## 5. 평가 (측정가능하게 — codex A11, 01 §6 게이트 분리 유지)

- **T1~T4 (phoenix)**: 01 §6(엔진 sanity, 귀속 정확도, 회귀/민감도, 트리아지 정밀). T1/T2=개발 전, T3/T4=구현 후 게이트.
- **T5 (외부 labeled corpus, real-world 주장 전 게이트)**: **labeled 계약** — `{vulnerable/fixed pair, expected CWE, expected source/sink, accepted evidence criteria, false-positive traps}`. 출처: CVE patch diff, GHSA/NVD/Snyk, LLM 인프라 취약사례(LangChain/LangGraph류 역직렬화/SSRF).
- **측정가능 지표(codex A11)**: high-recall은 **labeled ground truth 대비**로만 측정. 리포트는 "생성률"이 아니라 **`human-accepted report rate` + `maintainer-confirmed valid rate`**. "alert 수"는 지표 아님.

## 6. 아키텍처 원칙 (MVP는 단일, 인터페이스는 확장 대비)

- 인터페이스만 미리 둠(`CandidateGenerator`/`EvidenceGenerator`/`SemanticJudge`/`LanguageAdapter`)되, **MVP 구현체는 CodeQL+Python 단일**. 멀티엔진·멀티언어는 인터페이스 뒤 로드맵.
- 재현성: 01 전제계약(full .git 클론, SHA 고정).

## 7. 변경 로그 / codex 반영

- **v0.1→v0.2 (codex arch 11건)**: pre-LLM 예산 게이트 신설(A1), chain을 P5로(A2), KB를 seeded registry로 축소(A3), disclosure를 P6로·MVP는 internal memo(A4), MVP CodeQL-only·Semgrep을 P2 shadow로(A5), 후보 타입별 evidence 분리(A6), `auto-confirmed`→`static-confirmed-taint`+human-reviewed(A7), MVP를 5단계 단일 루프로 축소(A8), codeql_model_export 하위스키마(A9), chain 예시 제거(A10), 평가지표 측정가능화(A11).

## 8. (P5 재도입 시) chain 예시 — hop별 전제·evidence (codex A10)

로드맵 P5 참고용 정밀 예시(MVP 아님): `attacker input → SQL write primitive → persisted malicious serialized blob → unsafe deserialization sink → code execution`. 각 hop은 별도 evidence type(taint path / 저장소 상태 / deserialize sink 도달성)과 precondition이 필요. "deser→SQLi→RCE" 같은 느슨한 표기는 폐기.
