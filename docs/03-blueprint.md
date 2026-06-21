# AuditAI — 개발 전 기획 청사진 (Blueprint v1.2)

> **상태: codex bp3 sign-off 완료 — 96/100, "MVP 구현 착수 가능: 예, 남은 것은 §12 사용자판단뿐, 설계결함 0."** 이 문서가 **canonical 청사진**이다. [01-direction-review.md](01-direction-review.md)(codex 5차 96/100 기술계약)·[02-architecture.md](02-architecture.md)(arch 2차 88/100 MVP/로드맵)를 사용자 가이드(2026-06-19) 형식으로 통합하고, codex arch2 잔여 패치까지 반영했다.
> 통합 원칙: 가이드는 **참고**로 삼되, 01에서 codex로 굳힌 기술계약(blame 라인귀속, CodeQL split-config, pre-LLM 게이트, 정직한 등급, 평가 게이트)은 **보존**한다. 가이드와 충돌 시 §의 "결정 노트"로 명시 해소.

---

## 1. Executive Summary

AuditAI는 **GitHub commit/PR에서 LLM이 작성(추정 포함)한 Python 서버측 코드**를 우선 분석해, taint/data-flow로 검증 가능한 **injection류 취약점·위험 sink**를 찾는 도구다. 핵심은 **단계적 신뢰 상승 파이프라인**이다: **high-recall을 목표로 한** 후보탐지(Semgrep+CodeQL) → CodeQL taint **evidence 복원** → LLM **semantic judge**(sanitizer/guard 의미판정) → 사람 검토용 **finding draft**.

- **LLM은 탐지기의 본체가 아니다.** 탐지·도달성은 정적 엔진이 보장(G3), LLM은 의미판정·설명만.
- **MVP 성공 기준은 zero-day 자동발굴이 아니라 end-to-end 파이프라인 검증.** CVE급 발굴·chain·제보는 장기(로드맵 V2/V3).
- 점수 추이(codex 적대검증): 기술계약 42→96, 아키텍처 58→88, 청사진 82→90. 본 청사진은 그 위에 가이드를 통합한 canonical 문서(현재 v1.2).

## 2. What AuditAI Is / Is Not

| AuditAI는 ~이다 | AuditAI는 ~아니다 |
|---|---|
| AI 작성 코드 우선 **security triage + evidence 생성** 레이어 | 처음부터 모든 취약점을 찾는 만능 탐지기 |
| 기존 엔진(Semgrep/CodeQL)을 **후보·evidence 생성기로 활용** | CodeQL/Semgrep 대체품 |
| LLM을 **sanitizer/guard 의미판정자**로 사용 | LLM이 evidence 없이 취약점을 상상·확정하는 도구 |
| **사람 검토용 evidence pack** 산출(MVP) | 자동 외부 제보·exploit 생성기(MVP 아님 → V3) |

**왜 LLM-authored code부터?** LLM 생성 코드는 양이 급증하며 보안 검증이 누락되기 쉽고(NYU Copilot 40% 결함, "AI 패치 9배 취약" 등 선행연구), 변경 영역이 명확해 분석 스코프를 좁혀 **LLM 토큰·시간을 절감**할 수 있다. 단 이 "효율" 주장은 §9에서 수치로 입증 전까지 마케팅하지 않는다(G2).

## 3. MVP Scope

> **⚠️ 구현 현실 vs 청사진 (codex Q2 R2-4/R2-5)**: 이 문서는 **전체 비전**(S1 Semgrep+KB → S2 CodeQL
> taint → S3 LLM judge)이다. **현재 P0 슬라이스 구현 = S0 + S2(CodeQL `python-security-extended`
> suite + AI-라인 필터) + Track B 휴리스틱 + 게이트**뿐이다. **S1 Semgrep/KB 후보탐지·S3 LLM judge·
> `load_kb()` 파이프라인 소비는 아직 미구현(로드맵)** — 따라서 MVP Track A 효과는 *framework source +
> 인식 sink* 한정(`eval_targets/owasp_sourced` 6/6), "source 무관 위험 sink 패턴 탐지"는 S1=post-MVP.
> 상세·정직 고지: 루트 `README.md` "MVP 구현 범위" 섹션.

### 3.1 대상 코드
GitHub PR/commit 기반, **LLM 작성(확정/추정) Python 서버측** 변경. FastAPI/Flask/Django/일반 backend 우선. TS/JS·Java·Go·polyglot·cross-language taint는 **V2 이후**.

### 3.2 취약점 범위 — 후보 3타입 분리 (codex bp1-1/2)
MVP 후보를 3타입으로 나누고 **LLM deep judge(S3)는 `taint_path`만** 받는다(나머지는 inventory만).
- **`taint_path` (Track A, LLM 대상)**: source→sink taint로 검증 가능 — Command Injection(CWE-78), SQLi(89), Path Traversal(22), SSRF(918), Unsafe Deserialization(502), Template Injection(94/1336). **S2 CodeQL evidence 통과 시에만 S3.**
- **`static_pattern_risk` (Track A', inventory-only)**: source→sink가 아닌 패턴 위험 — `verify=False`/`debug=True`/unsafe YAML loader/`shell=True`(상수)/security-sensitive broad-except/hardcoded secret/"security TODO later"/LLM smell(raw SQL 조립·unsafe subprocess/path wrapper). **LLM 미전송(`llm_sent=false`), `vulnerability_confirmed=false`**, S4 risk_inventory로만.
- **`authz_candidate` (Track B, inventory-only)**: authz/IDOR/access control/business logic/multi-tenant ownership. **무시하지 않음** — AI 커밋이 permission check 제거/role 완화/middleware 우회/`tenant_id` 검증 제거/default-allow fallback/auth 실패 broad-except를 건드리면 수집. **MVP는 risk_inventory 표시까지**(policy 기반 LLM 판정은 V2).

### 3.3 LLM eligibility 계약 (firehose 차단, codex bp1-1/3)
`llm_eligible = (candidate_type == "taint_path") AND flow_evidence.source_to_sink_flow_exists AND static_path_confirmed`. 그 외(static_pattern_risk/authz_candidate, 또는 CodeQL path 없음)는 **S3 미전송** → `heuristic_positive_only` 또는 risk_inventory. **Semgrep 단독 taint 후보**는 `evidence_kind=requires_codeql_validation`이며 CodeQL 검증 실패 시 LLM 금지(`llm_block_reason` 기록).

### 3.4 MVP 제외 (로드맵)
full exploit generation, cross-language taint, full framework policy inference, multi-stage chain 자동확정, 외부 자동제보, RAG.

### 3.5 착수 게이트 (codex 01 §6 / arch2 상속)
**Slice 1 구현 착수 전 T1(엔진 sanity)·T2(귀속 정확도) 결과 파일이 산출돼 임계 충족해야 함**(§9). 미달 시 착수 보류.

## 4. Architecture Overview

```
            ┌────────────── Security KB (YAML/JSON seed spec) ──────────────┐
            │ Capability / ApiSignature / Source / Sink / Sanitizer / Propagator │
            └──────┬─────────────┬──────────────┬─────────────┬─────────────┘
                   │ (rules)     │ (models)     │ (specs)      │ (prompt ctx)
                   ▼             ▼              ▼             ▼
 [S0 Scope] → [S1 Candidate] → [S2 Flow Validation] → [S3 LLM Judge] → [S4 Finding Draft]
 blame/diff    Semgrep+CodeQL   CodeQL split-config     Claude 1-pass    internal evidence
 LLM-authored  +AST scanner     taint (+Joern v1.5)     semantic judge   memo (사람검토)
 line ranges   = candidates     = FlowEvidence          = Judgement      = report draft
                   │                                   ▲
                   └────── pre-LLM 예산 게이트(§5 S2.5) ─┘  (no static path ⇒ no LLM)
```

- **컴포넌트 인터페이스(확장 대비, MVP는 단일 구현)**: `CandidateGenerator`(Semgrep+CodeQL), `EvidenceGenerator`(CodeQL; Joern은 v1.5 plug), `SemanticJudge`(LLM), `LanguageAdapter`(Python; TS v2), `SecurityKB`(YAML).
- **실패 시 fallback**: S2에서 CodeQL DB 빌드 실패 → 후보를 `candidate(unvalidated)`로 보존하고 LLM 미전송. CodeQL path 없음 → `heuristic_positive_only`. 예산 초과 → `defer_no_llm`.
- **재현성**: full `.git` 클론 + 인덱싱 **SHA 고정**(01 전제계약).

## 5. Pipeline Stage Details

### Stage 0 — Scope Selection
- **입력**: repo_url, base_sha, head_sha, changed_files/hunks, **llm_authored_signal**(commit author/committer, message, PR label, generated-marker, co-author 트레일러 `noreply@anthropic.com`, user flag).
- **AI 라인 산출(01 Step1 보존, 가이드보다 엄격)**: 고정 SHA에서 `git blame --line-porcelain` → line→commit → `attribution_state ∈ {confirmed_ai, probable_ai, human, unknown_due_to_history_loss}` + `loss_modes[]`(squash/rebase/amend/cherry_pick/conflict/reformat/generated/vendored/file_move). generated/vendor 제외. provenance 손실은 FN 리스크로 노출(숨기지 않음).
- **출력 `AnalysisScope`**: changed hunks + enclosing func/class + same-file helper + (가능시) direct caller/callee + diff가 건드린 import. flow 검증 시 caller/callee로 repo 일부 확장 허용.

### Stage 1 — High-Recall Candidate Discovery
- **도구**: Semgrep custom rules + CodeQL default/custom query + lightweight AST/call scanner. KB(YAML) 소비.
- **원칙(가이드 §11-3)**: **1차에서 FP 제거 금지.** sanitizer 있어도 후보 유지. Stage 1 = 탐지가 아니라 **candidate discovery**.
- **출력 `FindingCandidate[]`** (candidate_type ∈ {`taint_path`, `static_pattern_risk`, `authz_candidate`} — §3.2). 각 후보에 `candidate_source`(semgrep|codeql|ast), `rule_id/query_id`, `evidence_kind`, `source_loc`, `sink_loc`, `evidence_required`, `llm_eligible`, `llm_block_reason` 기록(§7).
- **결정 노트(Semgrep, codex A5 의식적 편차)**: 사용자 결정으로 Semgrep을 MVP Stage1에 포함한다. 단 **Semgrep 결과는 finding이 아니라 candidate**이며, taint류 확정은 S2 CodeQL evidence를 통과해야만 LLM에 도달한다(firehose 차단은 S2.5 게이트). 이 편차의 리스크(엔진 중복/노이즈)는 §11에 등록.

### Stage 2 — Flow Validation (evidence)
- **도구**: CodeQL Python taint(주력). Joern/CPG는 **v1.5 optional**(아래 결정). KB의 source/sink/propagator/sanitizer spec.
- **메커니즘(01 §5 Step3 QL 계약을 normative로 상속 — codex bp1-6)**: `taint_path` 후보에 한해 CodeQL split-config로 `aiOnFlow(source, ai, sink)` 복원 — `SourceToAiConfig`(sink=aiOverlap) ∧ `AiToSinkConfig`(source=aiOverlap), `ai=source/ai=sink` 경계 포섭, `aiOverlap`은 `node.getLocation()`의 forward-slash repo-relative 경로 overlap. path 증거는 `PathGraph` 두 path-problem 쿼리. sanitizer/barrier는 **hard-cut 아닌 annotate**(01 C8). **01의 구현 제한을 그대로 상속**: `aiLine` 주입은 단일 방식(data-extension YAML 또는 생성 .qll, 병기 금지), **SARIF threadFlowLocations 교차는 `heuristic_positive_only`(양성 전용, 음성 판정 금지)**.
- **출력 `FlowEvidence`**: source/sink/flow_path/entrypoint/call_chain/control_guards/sanitizer_candidates/barrier_candidates/unresolved_edges/confidence.
- **결정 노트(Joern, 가이드 §7 — Option B 추천)**: **MVP에서 Joern 제외, v1.5로 미룸.** 근거: CodeQL이 Python taint 검증을 충분히 커버하고, Joern pysrc2cpg 정확도·운영 리스크가 MVP 일정을 위협(01 C3 정합). 단 `FlowEvidence` 스키마는 **엔진 무관**으로 설계해 v1.5에서 Joern을 보강 evidence backend로 attach. (Option A=MVP optional backend는 일정 리스크로 비추천.)

### Stage 2.5 — pre-LLM 예산 게이트 (codex A1, fail-closed 계약)
LLM 호출 **전** 강제:
- `CodeQL static path 없음 ⇒ LLM 금지`(휴리스틱 교차만이면 `heuristic_positive_only`로 두고 미전송).
- `llm_budget.max_calls_per_repo`(예: 200), `max_candidates_per_cwe`(예: 50), `rule_allowlist`(허용 CWE/쿼리 명시).
- `dedup_key = (repo, sha, cwe, source_loc, sink_loc, path_hash)`로 중복 제거.
- `budget_exceeded ⇒ defer_no_llm`(버리지 않고 다음 실행으로 이월, 상위 rank 우선).
- `gate_metrics` 기록(통과/차단/이월 수) — 게이트가 실제 작동하는지 측정.
- **`static_path_confirmed` 산출(codex bp2)**: 이 게이트가 `static_path_confirmed = FlowEvidence.source_to_sink_flow_exists AND (split-config aiOnFlow 성립)`을 **여기서 확정**해 `llm_eligible` 산식에 공급. S3 출력이 아니라 **S2/S2.5 산출 필드**(순환의존 제거).

### Stage 3 — LLM Semantic Judge (MVP = 1-pass)
- **입력**: FindingCandidate + FlowEvidence + 최소 코드 스니펫(Tree-Sitter 본문 추출, 01 C9) + KB context + sanitizer/barrier 후보 + framework context.
- **판정**: sanitizer가 실제 충분한가(`validate_xxx`가 이름뿐인지 실제 allowlist/escaping/parameterization인지), guard가 보안검증인지 단순 null/length인지, parameterized vs raw query, `shell=True`+command 조립의 실제 위험, framework 기본 escaping 적용 여부, verdict 등급, manual review 필요 여부. (**S3는 `taint_path`만 받으므로 Track B 판정 안 함 — codex bp2; Track B/static_pattern_risk는 S4 risk_inventory 표시 대상.**)
- **금지(G3)**: evidence에 없는 호출경로/코드 상상, 근거 없는 확정, exploit payload 생성.
- **전제(codex bp1-1/7)**: S3는 `llm_eligible == true`(§3.3)인 `taint_path` 후보만 받는다. static_pattern_risk/authz_candidate는 S3 미전송.
- **출력 `SemanticJudgement`**: verdict∈{`static_path_triaged_positive`, `likely_risk`, `suspicious`, `false_positive`, `needs_manual_review`} (**`confirmed_finding` 금지 — 사람검토 전 확정 없음, codex bp1-7**) + reason + sanitizer_sufficient + authz_relevant + exploitability_hint + missing_evidence + confidence + recommended_next_action. **항상 `vulnerability_confirmed=false`, `human_review_state=not_reviewed`**. 1-pass 출력은 `needs_manual_review` 중심 운영, FP reduction은 보장이 아니라 §9 실측 지표(codex bp1-4).
- **결정 노트(1-pass, arch2 정합)**: MVP는 **1-pass**. 01의 "2-pass(저가 triage→flagship)"는 **post-MVP 비용 최적화로 재분류**(여기서 명시 해소).

### Stage 4 — Finding Report Draft (internal, codex A4)
- **출력 `FindingReport`**(taint_path 판정분) + **`risk_inventory`**(static_pattern_risk/authz_candidate 모음, LLM 미판정): title/severity/CWE/file·line/source→sink path/evidence snippets/why-sanitizer-insufficient/impact/**safe reproduction idea**/remediation/confidence/responsible-disclosure-note + **`vulnerability_confirmed=false`/`human_review_state=not_reviewed` 필수**(codex bp1-7/8).
- **제약**: 외부 자동제보 아님(internal evidence memo). destructive exploit validation 금지 — **non-destructive regression test 또는 mocked sink proof** 수준. 외부 제보는 V3(human approval 체크리스트 통과 후).

## 6. Security KB Minimal Design

MVP는 RAG·RDB·graph DB 없이 **Git-managed YAML/JSON seed spec**(Python 전용). scanner가 읽어 Semgrep rule / CodeQL model·query / LLM prompt context로 사용. Postgres/pgvector/RAG는 V2.

- **MVP 엔티티**: Capability, ApiSignature, SourceSpec, SinkSpec, SanitizerSpec, PropagatorSpec(§7).
- **KB 항목 공통 메타(codex A3/bp1-9 — 순환방지 + 소비자 매핑)**: 각 항목 `{owner, version, test_fixture, expected_tp_fp, provenance, engine_mappings:{semgrep, codeql, prompt_context}}` 필수. `engine_mappings`는 도메인 모델을 세 소비자(Semgrep 패턴 / CodeQL data-extension row / LLM prompt context)로 내보내는 구체 매핑. 빈 KB가 아니라 **검증된 seed**로 시작.
- **`codeql_model_export` 하위스키마(codex A9)**: CodeQL Python data-extension(**beta**)으로는 `sourceModel/sinkModel/typeModel/summaryModel/barrierModel/barrierGuardModel` 계열만 export. chain-rule/state-boundary 전체를 data-extension에 먹일 수 있다고 가정 안 함.
- **sanitizer 원칙(중요)**: 이름만 보고 FP 제거 금지 — `validate_*`/`sanitize_*`는 **sanitizer candidate로만 표시**, 실제 충분성은 S3 LLM이 판정.

## 7. Data Contracts (pseudo-schema; MVP=필수 / V2=확장 표시)

> 각 엔티티: 왜 필요 / 어디서 생성 / 어디서 사용. 필드 옆 `[V2]`는 v2 확장.

- **AnalysisScope** (S0 생성, S1 사용): `{repo, base_sha, head_sha, changed_hunks, enclosing_units, helper_funcs, callers_callees, touched_imports}`. 왜: 전체 repo 대신 AI 변경 주변 우선.
- **AILineAttribution** (S0 생성, 전 단계 사용): `{file, line_range, commit, attribution_state, ai_confidence, label_source, loss_modes[], manual_label}`. 왜: 모든 단계의 "AI 코드 통과" 판정 기준(01 핵심).
- **Capability** (KB): `{id, name, cwe, description, severity_hint, examples, terminal_impact}`. 왜: 엔진 결과를 공통 위험분류로 정규화. 예: command_execution, sql_execution, unsafe_deserialization, file_access, network_request, template_render, dangerous_config.
- **ApiSignature** (KB): `{id, language, package, module, qualified_name, receiver_type, method_name, capability_id, argument_roles, dangerous_conditions, confidence, provenance}`. 왜: 언어/라이브러리 API를 capability에 연결, 위험 인자 식별.
- **SourceSpec** (KB): `{id, language, framework, qualified_name_or_pattern, source_kind, arg_or_return_role, confidence, provenance}`. 예: request.args.get, FastAPI param, env var, file upload, **LLM output / agent tool result**(LLM-authored agent 코드에서 LLM 출력을 tainted source로).
- **SinkSpec** (KB): `{id, api_signature_id, sink_kind, dangerous_argument, required_conditions, capability_id, cwe, confidence}`. 예: subprocess.run arg0+shell=True, cursor.execute dynamic, pickle.loads arg0, yaml.load w/o SafeLoader.
- **SanitizerSpec** (KB): `{id, language, qualified_name_or_pattern, sanitizer_kind, applies_to_capability, strength, limitations, confidence}`. **candidate 표시용**(충분성은 LLM 판정).
- **PropagatorSpec** (KB): `{id, language, qualified_name_or_pattern, from, to, propagation_kind, confidence}`. 왜: wrapper/helper에서 taint 끊김 방지. CodeQL summaryModel로 확장 가능.
- **FindingCandidate** (S1 생성, S2 입력): `{candidate_id, candidate_type(taint_path|static_pattern_risk|authz_candidate), track(A|A'|B), repo, commit_sha, file, source_loc, sink_loc, ai_attribution_refs[](→AILineAttribution, codex bp1-8: changed_by_llm bool 폐기), code_snippet, capability_id, sink_spec_id, source_nearby, sanitizer_candidates, candidate_source(semgrep|codeql|ast), rule_id, query_id, evidence_kind, evidence_required, llm_eligible, llm_block_reason, risk_score, recall_reason, next_stage}`. **후보지 finding 아님.**
- **FlowEvidence** (S2/S2.5 생성, S3 입력): `{candidate_id, source_to_sink_flow_exists, static_path_confirmed(codex bp2: 여기서 산출, S3 출력 아님), source, sink, flow_path, path_nodes[]:{engine, node_id, file, start_line, end_line, role, code, kind, path_leg(source_to_ai|ai_to_sink), sequence, path_id}, entrypoint, call_chain, control_guards, sanitizer_candidates, barrier_candidates, unresolved_edges, engine(codeql|joern[V1.5]), engine_artifacts[], query_id, evidence_backend_version, confidence}`. **엔진 무관 path-node 스키마 + split-config 두 leg(source→ai, ai→sink) 병합 규칙**(codex bp1-5/bp2: `path_leg`+`sequence`+`path_id`로 보존, Joern 후속 attach 가능).
- **SemanticJudgement** (S3 생성, S4 입력): §5 Stage3 출력(verdict enum에 `confirmed_finding` 없음). + `static_path_confirmed`(**read-only echo from FlowEvidence — S3가 생성하지 않음, codex bp2**), `vulnerability_confirmed=false`(항상), `human_review_state=not_reviewed`, `track(A)`.
- **FindingReport** (S4 생성): §5 Stage4 출력. internal memo. **`vulnerability_confirmed=false`, `human_review_state=not_reviewed` 필수**(codex bp1-7). `risk_inventory`는 별도(static_pattern_risk/authz_candidate, LLM 미판정).
- **ChainRule** `[V3 schema-only]`: `{chain_id, name, stages, required_capabilities, state_boundary, produces, consumes, final_impact, confidence, maturity(draft|experimental|validated)}`. **MVP 자동확정 금지** — draft seed(sqli_to_deserialization_rce 등)는 LLM chain hypothesis 참고용으로만, V3에서 source→state→sink로 확장.

## 8. Tooling Strategy

- **Semgrep** (S1 후보생성기): 빠른 diff scan, 위험 API/flag/LLM smell/insecure config 후보. rule 예: `subprocess.run(...,shell=True)`, `os.system`, `eval`/`exec`, `pickle.loads`, `yaml.load` w/o SafeLoader, `cursor.execute(f"...")`/`+ user_input`, `requests.get(user_url)`, `open(user_path)`, `render_template_string`, `verify=False`, `debug=True`, `except Exception: pass`, hardcoded token. **결과=candidate, finding 아님.**
- **CodeQL** (S2 주력 검증): Python source→sink taint, built-in security query, custom high-recall query, custom model extension(source/sink/summary/barrier), Semgrep candidate의 data-flow 검증. 결과도 evidence/candidate로 정규화.
- **Joern/CPG** (**v1.5 optional**, §5 결정): MVP 제외. FlowEvidence 스키마로 후속 attach. sink 주변 call graph/slice/evidence 복원에 보강.
- **LLM(Claude)** (S3 판정자): unknown API capability 분류, sanitizer 실제 충분성, guard/authz/barrier 의미판정, finding 설명·report 초안. **evidence 없는 추측·exploit 생성 금지.**
- **Security KB** (정형 지식): YAML/JSON seed가 Semgrep/CodeQL/LLM에 공유.

## 9. Evaluation Strategy (측정가능 — codex A11, 게이트 분리)

- **MVP 평가 데이터**(과대 금지): 내부 synthetic vulnerable snippets, 소형 Python benchmark, known vulnerable commit/patch diff 일부, **GHSA/CVE 있는 Python 취약점 5~10개**. LangGraph류(checkpoint/memory/deser/SQLi)는 **장기 benchmark 후보로만**.
- **T5 외부 corpus 계약(labeled)**: `{vulnerable/fixed pair, expected CWE, expected source/sink, accepted evidence criteria, false-positive traps}`.
- **지표(측정가능)**: ① Candidate recall(위험 sink를 1차에서 안 놓침, **labeled ground truth 대비**), ② Flow validation success rate(source→sink evidence 복원율), ③ FP reduction(LLM 판정 후 오탐 감소), ④ Evidence quality(**human-accepted report rate / maintainer-confirmed valid rate** — "생성률" 아님), ⑤ Time-to-triage(PR당 분석시간 실용성).
- **게이트(01 상속, §3.5 연결)**: **T1/T2 = 착수 전**, T3/T4 = 구현 후, T5(real-world 효과 주장) = 외부 corpus 확보 후. **MVP 성공기준은 zero-day 발굴 아님 = end-to-end pipeline 검증.**
- **착수 전 임계값 초안(codex bp1-10 — "없음" 금지, 수치는 §12-6에서 튜닝)**: **T1** = seed CWE fixture **전부**에서 source→sink path evidence 복원(100%). **T2** = 수동 라벨 샘플에서 confirmed_ai 식별 precision ≥ 0.9 / recall ≥ 0.8, 그리고 provenance loss rate를 수치로 **보고**(보고 자체가 합격 조건). 결과 파일(`eval/t1.json`, `eval/t2.json`) 산출이 착수 전 필수.

## 10. Roadmap

| 단계 | 내용 |
|---|---|
| **MVP(설계 목표)** | Python only, LLM-authored diff scope, Semgrep candidate + CodeQL flow validation, YAML Security KB(seed), pre-LLM 게이트, **1-pass** LLM judge, internal finding report. Joern 제외. |
| **MVP(P0 실제 구현 — 부분집합)** | S0 diff/AI귀속 + **S2 CodeQL `python-security-extended` suite + AI-라인 필터**(source-bearing taint) + Track B 휴리스틱 + 게이트 G1~G4 + artifact. **미구현(로드맵): S1 Semgrep/KB 후보탐지, S3 LLM judge, load_kb 파이프라인 소비, split-config aiOnFlow QL.** (codex Q2 — README "MVP 구현 범위" 참조) |
| **V1.5** | Joern optional evidence backend, better call graph/slicing, Python 프레임워크 추가, 소규모 외부 CVE corpus, (옵션)2-pass LLM. |
| **V2** | TS/JS support(language adapter), RAG evidence corpus, Security KB Postgres/pgvector, custom model 자동생성, state-boundary 모델링. authz/IDOR Track B 정식화. |
| **V3** | multi-stage chain detection(source→state→sink), framework/library-wide 분석, **responsible disclosure workflow**(human approval), real-world CVE hunting. |

## 11. Risk Register

| 리스크 | mitigation |
|---|---|
| MVP scope too large | §3 Track A/B 분리, Joern·chain·RAG·disclosure를 로드맵으로. 단일 루프 5스텝. |
| Semgrep/CodeQL 중복·firehose (codex A5 편차) | Semgrep=candidate만, taint 확정은 CodeQL 검증 후. **S2.5 pre-LLM 게이트(no static path⇒no LLM, repo 예산, dedup)**. |
| LLM hallucination | G3(도달성 static 확정), evidence 없는 경로 상상 금지, exploit 생성 금지. |
| Security KB 유지부담 | MVP는 seed YAML 최소, 항목당 test_fixture/expected_tp_fp 강제. RAG는 V2. |
| sink DB precision/recall | rule_allowlist + CWE 상한 + labeled corpus로 catalog miss 측정. "sink 미정의=탐지불가" 명시. |
| sanitizer misclassification | 이름 기반 FP 제거 금지 → candidate 표시 + LLM 충분성 판정. barrier annotate(hard-cut 아님). |
| authz/IDOR complexity | 자동확정 안 함 → Track B candidate. policy 판정은 V2. |
| chain detection overclaim | MVP 제외(V3). hop별 evidence/precondition 요구, human signoff 전 CVE 주장 금지. |
| evaluation corpus 부족 | 내부 synthetic + 5~10 known CVE + 외부 labeled corpus(T5). phoenix 단독 real-world 입증 불가 명시. |
| FP UX | 등급 분리(§ 등급), candidate/finding 절대 혼합 금지. |
| exploit validation 안전 | destructive 금지, mocked sink proof/non-destructive regression만. 외부 제보 V3. |
| 등급 오독(codex A7/arch2) | enum=`static_path_triaged_positive`, UI/JSON에 `vulnerability_confirmed=false` 강제. `confirmed_vulnerability` 필드 금지. |
| 귀속 침묵 FN | blame loss_modes/attribution_state 노출, confirmed/probable 분리, 머지-base diff 보조. |

## 12. Open Questions (사용자/구현 판단)

1. **Semgrep MVP 포함 확정?** 가이드는 포함, codex(A5)는 CodeQL-only 권장. 본 청사진은 **포함 + 게이트 완화**로 채택 — 동의하는지, 아니면 V1.5로 미룰지.
2. **LLM 1-pass 확정?** MVP 1-pass / 2-pass는 V1.5. 비용·정밀 측정 후 재검토.
3. **pre-LLM 예산 수치**(max_calls_per_repo, max_candidates_per_cwe 등) 초기값 — §5 S2.5 예시값으로 시작할지.
4. **타겟**: phoenix(T1~T4) + 외부 labeled corpus 5~10 CVE 즉시 확보 vs 내부 synthetic 우선.
5. **AI 귀속 신뢰선**: confirmed_ai만 자동분석 vs probable_ai까지 포함(저신뢰 버킷).
6. **T1/T2 착수 임계값 튜닝**(codex bp1-10): §9 초안(T1 100% fixture 복원, T2 precision≥0.9/recall≥0.8)을 그대로 쓸지, 데이터에 맞게 조정할지.

---

### 부록 A — codex 검증 이력
- 01(기술계약): 5라운드 42→68→78→86→96. split-config QL, blame 귀속, 평가 게이트 확정.
- 02(아키텍처): 2라운드 58→88. MVP/로드맵 분리, chain/RAG/disclosure 로드맵화.
- 본 03(청사진): 가이드 통합 + arch2 잔여패치 반영(v1.0) → **codex bp1차(82/100) 11건 전부 반영(v1.1)**: 후보 3타입 분리·llm_eligible 계약(bp1-1/2/3), 01 QL 계약 normative 상속(bp1-6), verdict enum 통일·`confirmed_finding` 제거(bp1-7), §7 필드 보강·`changed_by_llm`→`ai_attribution_refs`(bp1-8), KB engine_mappings(bp1-9), FlowEvidence path_nodes 표준(bp1-5), T1/T2 임계 초안(bp1-10), high-recall=목표 표현(bp1-11). → **codex bp2차(90/100) 4건 반영(v1.2)**: static_path_confirmed를 S2/S2.5 산출로 이동(순환의존 제거), path_nodes에 path_leg/sequence/path_id 추가(split-config 두 leg 병합), S3에서 Track B 판정 제거, 버전 표기 정리. → **codex bp3차 sign-off: 96/100, "MVP 구현 착수 가능: 예, 설계결함 0, 남은 것은 §12 사용자판단뿐."**
