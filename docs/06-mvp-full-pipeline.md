# AuditAI — Full 5-Stage MVP (S0→S1→S2→S3→S4) 구현 설계 (draft, codex 검증 대기)

> 상태: **codex PLAN 검증 대기.** 기반: [03-blueprint.md](03-blueprint.md)(canonical), [04-hybrid-candidate-discovery.md](04-hybrid-candidate-discovery.md)(S1), contracts.py(스키마 전부 codex-검증 완료).
> 동기(사용자 2026-06-21): **MVP 범위 재정의** — "실제로 돌아가고 취약점이 대략적으로라도 찾아지는 5단계 end-to-end"까지를 MVP로. 코드 최적화/디테일(split-config aiOnFlow QL, Semgrep, LLM miner, Starlette/Strawberry source model, cross-lang)은 그 이후 phase.

## 0. 현재 상태 vs 목표
- **계약(스키마)**: 전부 존재·codex-검증 — `FindingCandidate`(S1), `FlowEvidence`+`compute_llm_eligible`/`LlmGateDecision`(S2/S2.5), `SemanticJudgement`(S3), `FindingReport`(S4), KB specs(SourceSpec/SinkSpec/SanitizerSpec/Capability). **재설계 아님 — 구현/배선만.**
- **구현 현황**: S0 ✅(scope.py), S2 CodeQL ✅(codeql.py, 단 직접 탐지 경로), Track B ✅, gates ✅. **S1·S2.5배선·S3·S4 미구현.**
- **목표**: S0→S1→S2→S2.5→S3→S4 가 한 루프로 실행되어 owasp_sourced fixture·실 fastapi planted CWE-78 에서 **judged FindingReport 를 산출**(vulnerability_confirmed=False 유지). "빈 결과 오독 금지"·gates·status 머신 보존.

## 1. S1 — Candidate Discovery (신규 `auditai/candidates.py`) — **known-KB AST seed scanner**
**정직한 명명(codex r1 M3)**: 이건 high-recall candidate discovery 가 아니라 **KB 등록 sink 한정 AST seed 스캐너**다. Semgrep/LLM miner/unknown-surface 부재로 인한 FN(KB 미등록 sink, bare-param, duck-typed)은 artifact 에 카운트(`s1_fn_note`). 수용기준도 "KB 등록 sink + planted CWE-78"로 한정. MVP 는 **AST 기반 결정적 스캐너**(Semgrep/LLM miner 는 이후 phase). 외부 의존 0, 항상 실행.
- 입력: S0 의 `DiffScope` + **AI 귀속 라인(`AILineAttribution[]`)** + 로드된 KB(`load_kb()` — **드디어 파이프라인 배선**).
- **★S0 확장(codex r1 C2 선결)**: 현재 `DiffScope` 는 added/deleted line 만 가짐 → `FindingCandidate.ai_attribution_refs`(=`AILineAttribution[]`)를 만들 입력이 없다. S0 에 added line 을 head blame → `classify_commit` 으로 분류해 `AILineAttribution`(file, line_range, commit, attribution_state, ai_confidence, label_source="blame") 산출 추가. S1 은 sink 가 **is_ai 인 added line** 일 때만 후보화. (blame 불가/실패 라인은 UNKNOWN 으로 정직 표기.)
- part-1(S1A, known sink): 변경 .py 를 `ast.parse` → `ast.Call` 노드를 KB `SinkSpec`(qualified_name/pattern)과 매칭. 매칭 sink 가 AI-귀속 라인이면 후보 생성.
- part-2(S1B, source-nearby 판정): 같은 함수 스코프에 source 신호(FastAPI route 파라미터 / `request.*` / 함수 파라미터가 sink 인자로 흐름)가 있으면 `source_nearby=True`.
- 후보 타입 결정:
  - sink + source_nearby → `candidate_type=TAINT_PATH`(Track.A) → S2/S3 대상.
  - sink-only(source 미확인) → `STATIC_PATTERN_RISK`(Track.A_PRIME) → S3 미전송, inventory/heuristic.
  - authz/약화 → 기존 Track B(`security_controls.py`)가 이미 산출(`AUTHZ_CANDIDATE` 변환).
- 출력 `FindingCandidate[]`: candidate_id(`S1-...`), candidate_source=AST, evidence_kind=`REQUIRES_CODEQL_VALIDATION`(taint)/`STATIC_PATTERN`(pattern), sink_spec_id/capability_id(KB), code_snippet, ai_attribution_refs, risk_score, recall_reason. **finding 아님(1차 FP 제거 금지).**
- artifact: `candidates.jsonl`.

## 2. S2 — Flow Validation (기존 codeql.py 재사용 + 신규 상관) — **exact-overlap, 오귀속 차단**
현재 codeql.py 는 `python-security-extended` suite 를 돌려 SARIF→`FindingReport` 축약+AI-라인 필터. **codex r1 M1: `FindingReport` 는 rule/result identity·위치구조·codeFlow 를 잃어 candidate-level evidence 로 부적합.** → 신규 내부모델 **`CodeQLTaintResult`**(rule_id, cwe, sink_file, sink_start/end_line(+col 가능 시), codeFlow sink node, full path nodes, raw region)를 SARIF 에서 직접 파싱 보존.
- 상관(per-candidate): 후보 sink ↔ `CodeQLTaintResult` 매칭 = **normalized full path 일치 AND AST call span exact overlap(±N 근접 금지) AND CWE/rule allowlist AND codeFlow sink node 교차**. 한 후보에 2개 이상 결과가 모호하게 매칭되면 **reject(ambiguous)** — 잘못된 evidence 귀속 금지.
- 매칭 시 → `FlowEvidence(candidate_id, source_to_sink_flow_exists=True, sink=…, flow_path=[codeFlow], path_nodes=[…], engine=codeql, evidence_backend_version=codeql_version, confidence<1)`. candidate_id 일치는 `compute_llm_eligible` 이 이미 강제.
- 매칭 없음/모호 → evidence=None → 후보는 llm 미전송(`heuristic_positive_only`).
- **★`static_path_confirmed` MVP 의미(codex r1 C3 확정 = 근사+정직표기)**: 계약은 split-config aiOnFlow 의미라 P0 미산출이라 못박음. 그러나 `compute_llm_eligible` 이 이 필드 True 를 S3 진입요건으로 강제 → 그대로면 S3 가 안 돈다.
  - **확정**: MVP 에서 `static_path_confirmed` = "generic-suite CodeQL taint codeFlow 가 후보의 AI-귀속 sink 와 exact 교차"로 **근사**. **compute_llm_eligible 요건은 유지(제거 금지)**, split-config 실구현은 MVP 과대(둘 다 codex 기각).
  - 정직 표기: FlowEvidence 에 **`approximation_kind="generic_codeql_ai_sink_intersection"`** 필드 추가 + `confidence<1` + `evidence_backend_version` 기록 + contracts docstring 갱신(근사임을 명시). split-config aiOnFlow QL 은 V1.5.
- artifact: `flow_evidence.jsonl`(기존 codeql_status.json 유지).

## 3. S2.5 — LLM Gate (기존 compute_llm_eligible, 배선만)
`compute_llm_eligible(candidate, evidence)` → `LlmGateDecision`. taint_path + flow_exists + static_path_confirmed → llm_eligible. 그 외 전부 미전송(heuristic_positive_only / inventory). artifact: `llm_gate.jsonl`.

## 4. S3 — LLM Judge (신규 `auditai/judge.py`, **CLI 기반 멀티엔진** — API 키 미사용)
**사용자 결정(2026-06-21): SDK/API 키 대신 설치된 LLM CLI 를 subprocess 로 호출(`exec`/`-p`).** 이 프로젝트가 이미 codex 를 그렇게 부른다(키 관리 0, 각 CLI 의 자체 인증 사용).
- **엔진 추상화**(교체·수정 용이): `class JudgeEngine(Protocol): def run(prompt: str, *, timeout) -> str`. 구체구현 3종 + 테스트 fake. **모든 엔진은 프롬프트를 argv 가 아니라 stdin 으로 받는다**(codex S3plan: argv 인젝션/길이 회피, 일관성):
  - `ClaudeCliEngine` → `claude -p`(프롬프트 stdin) + `--output-format json`→envelope `result` 추출 + `--model` + **도구 비활성 플래그**. 모델 기본=검증용 capable(아래 티어).
  - `CodexCliEngine` → `codex exec --skip-git-repo-check -s read-only`(프롬프트 stdin) + `-c model_reasoning_effort=<tier>` + ANSI strip + `tokens used` 절단. **S3=검증이므로 effort 기본 medium/high**(low 는 검출용).
  - `GeminiCliEngine` → `gemini`(프롬프트 stdin) + `-m` 모델 + **MCP/extensions 차단 플래그**.
  - `FakeEngine`(테스트): 주어진 JSON 을 그대로 반환(네트워크/CLI 0).
  - 각 엔진은 **독립 클래스**라 명령/플래그/파서를 엔진별로 따로 수정 가능. 공통 헬퍼 `_run_cli(argv, stdin, timeout, cwd, env)`.
- **★capability probe(codex S3plan 필수)**: 엔진을 "사용 가능"으로 등록하기 전에 `<engine> --help`/dry-run 으로 **요구 안전 플래그의 실재**를 확인한다(claude no-tools, gemini MCP/extensions 차단, codex approval-never/non-interactive). 확인 불가 → 등록 안 함 → graceful degrade(검증 안 된 subprocess 도박 금지). 엔진별 golden test 로 cwd=temp·최소 env·안전 플래그 포함을 고정.
- **★모델 티어([[auditai-llm-model-tiers]], 사용자 2026-06-21)**: **검출 단계(S1C, 이후 phase)=가장 가벼운 모델**(`claude-haiku-4-5` / `codex effort=low`) — "단순 취약점 찾기"는 모델 성능 무관. **검증 단계(이 S3)=강한 모델 기본** — sanitizer 충분성/verdict 가 결과 품질을 좌우. 엔진별 모델/effort 는 `AUDITAI_JUDGE_MODEL`/플래그로 오버라이드. 비용은 예산 게이트 + "싼 검출→비싼 검증으로 넘어가는 양 축소"로 통제.
- **엔진 선택**: CLI 플래그 `--judge-engine {claude,codex,gemini}` + env `AUDITAI_JUDGE_ENGINE`(기본 claude), 모델 오버라이드 `AUDITAI_JUDGE_MODEL`. 미설치/미인증/probe 실패 CLI 는 자동 graceful degrade(아래).
- **subprocess 보안(codex r1 M4 + S3plan 강화)**: `shell=False`(argv 리스트), **프롬프트 stdin 전달**, **cwd=임시 디렉토리(repo 아님)**, **env scrub(최소 환경)**, 엔진별 도구비활성/read-only/approval-never 강제(probe 로 실재 확인). read-only 도 파일 유출은 못 막으므로 LLM 에 **후보 snippet + evidence JSON 만** 제공(repo 전체 접근 안 줌). list-argv·timeout·status 기록은 기존 codeql subprocess 패턴 재사용하되 cwd/env/stdin 격리를 추가.
- **구조화 출력(CLI 엔 messages.parse 없음)**: 프롬프트가 "**아래 JSON 스키마에 정확히 맞는 JSON 객체만 출력**(코드펜스·산문 금지)"를 지시 → stdout 에서 JSON 추출(코드펜스/ANSI/envelope strip → 첫 `{`..마지막 `}` 블록) → `JudgeOutput`(pydantic) 검증. 파싱 실패 시 1회 repair 재요청, 그래도 실패면 그 후보 **`judgement_skipped`(미판정)** — **절대 `false_positive`/NO_VULN 로 떨어뜨리지 않음**(codex r1 M4, fail-closed).
- `JudgeOutput`(LLM 산출 부분집합): **verdict(=계약 `Verdict` enum: static_path_triaged_positive|likely_risk|suspicious|false_positive|needs_manual_review — codex r1 M5, 설계서 옛 likely_vulnerable/needs_review 폐기)**, reason, sanitizer_sufficient, exploitability_hint, missing_evidence, confidence, recommended_next_action. 파이프라인이 `SemanticJudgement` 로 조립(static_path_confirmed=evidence echo, vulnerability_confirmed=False 강제, track=A).
- 프롬프트: candidate code_snippet + FlowEvidence(flow_path/sanitizer_candidates) + KB capability/sanitizer 컨텍스트. **지시: exploit 생성 금지, evidence 없는 추측 금지, sanitizer 충분성만 의미판정, 항상 vulnerability_confirmed=False.**
- **CLI 없음/실패(graceful degrade)**: 선택 엔진 CLI 가 PATH 에 없거나 인증 안 됨/타임아웃/비정상 종료 → S3 skip(또는 해당 후보 미판정), eligible 후보는 "S3 미실행" 표식 → status 가 NO_VULN_FOUND 로 오독 금지(s2_completed 와 동형의 s3_completed 처리).
- **★카운트 accounting(codex S3plan 필수)**: `judge_eligible(candidates, evidence) -> list[JudgeTask]` 와 `judge(tasks) -> JudgeRun(judgements, judged_count, judgement_skipped_count, llm_eligible_count, s3_completed)` 형태로, **eligible 모든 후보가 judged|skipped 중 하나로 회계**되도록 API 를 설계(다음 run.py 배선에서 카운트 누락 불가능). invariant: `judged_count + judgement_skipped_count == llm_eligible_count`(부분실행이면 s3_completed=False). 이 카운트가 `resolve_run_status` 의 SEMANTIC_JUDGE_NOT_RUN 분기로 직결.
- **예산 게이트**: `judge_budget.max_calls_per_repo`(기본 50), dedup_key=(repo,sha,candidate sink). 초과 → `defer_no_llm`.
- artifact: `judgements.jsonl`(+ 엔진/모델/raw stdout 진단 보존).

### 4.1 S3 구현 조건 (codex s3plan2 82%/조건부 — 착수 전 못 박음)
1. **capability probe = 행동 검증**: `CapabilityProbeResult(engine, version, argv, supports_stdin, safety_flags_present, behavioral_probe_passed)`. `--help` 플래그 실재만이 아니라, **temp cwd 에서 "repo 파일 읽기/도구 사용 유도" 프롬프트가 실제로 차단되는지** behavioral probe 까지 통과해야 등록. 실패 → 등록 금지(graceful degrade). codex argv 에 approval-never/non-interactive 명시 + golden test 고정.
2. **예산 회계(누락 불가)**: 예산은 `judge_eligible()` **이후** 적용. budget 초과 후보도 `llm_eligible_count` 에 **남기고** `JudgeRunState.SKIPPED(reason="budget_exceeded")` + `judgement_skipped_count++`(eligible 에서 드롭 금지 — 숨김 방지).
3. **예산 단위 = 토큰/시간/비용**(후보 수 아님): `max_prompt_bytes`, `max_flow_nodes`, `max_output_bytes`, `max_total_tokens_estimate`, `max_wall_time`, `max_parallelism=1`, dedup cache 선적용, `risk_score` 상위 K 제한. **강한 모델 기본 유지하되**(검증 단계) 토큰/시간/비용으로 상한.
4. **`assemble_semantic_judgement(task, output)` 단일 함수**: `candidate_id` / `gate.llm_eligible` / `evidence.static_path_confirmed==True` / `SemanticJudgement.static_path_confirmed == evidence echo` / `vulnerability_confirmed=False` 를 assert+테스트. **LLM output 에서 `static_path_confirmed`·`vulnerability_confirmed` 는 받지 않는다**(evidence echo / 강제이지 LLM 산출 아님).
5. **per-candidate `JudgeOutcome` 모델**: `JudgeTask` + `JudgeOutcome(candidate_id, state, judgement?, skip_reason?, engine, model, probe_id)` 를 실제 모델로. aggregate count 는 **이 리스트에서만 derive**(손으로 judged_count 맞추기 금지 — 감사성).
6. **실 CLI 1회 검증(skipif)**: verdict-C 순서(FakeEngine+최소 S4 먼저)는 맞으나, full switch 전 **실 CLI 1개로 probe+stdin+temp cwd+env scrub+JSON parse smoke** 통합 테스트(skipif)를 남긴다. "FakeEngine 만으로 S3 CLI 완료" 주장 금지(자기기만).
7. **S4 제외 규칙 수정**: "`state != judged` **또는** `verdict == false_positive` → finding draft 제외".
8. **docstring 정합**: resolve_run_status 의 실제 precedence 와 §6 status 설명 문구 일치(불일치 시 다음 구현자가 resolver 를 오"정리").

### 4.2 Judge 대화 세션 정책 (★아키텍처 고정 — 사용자 2026-06-21)
**원칙(결정론적, 단일 결정점 = judge.py — "어떨땐 이렇게 어떨땐 저렇게" 금지)**:
- **세션 단위 = 1 후보 판정 1 세션.** 후보가 바뀌거나(완전 새 내용) 파이프라인 단계가 바뀌면(stage transition) → **새 세션**(resume 금지 → context bleed 0, 판정 독립성 보장).
- **같은 후보 내 continuation**(parse repair·후속 질의) → **그 세션 resume**(모델이 자기 직전 출력을 이어서 교정 — 전체 프롬프트 재전송 대신).
- 세션은 후보 종료 시 **close**(세션/temp cwd 정리). new-vs-resume 결정은 judge.py 가 일괄(엔진 무관).

**균일 추상화 `JudgeSession`**:
- `engine.start_session() -> JudgeSession`: claude/gemini = 생성 UUID `--session-id`, codex = exec 출력서 `session id:` 파싱. **세션 전용 temp cwd**(claude/gemini 세션이 cwd-키잉이므로 세션 수명 동안 동일 cwd 유지 — 보안 cwd≠repo 와 양립).
- `session.send(prompt,*,timeout) -> str`: 첫 send=새 세션 생성, 이후=resume(claude `--resume <uuid>`, codex `exec resume <uuid>`, gemini `--resume <uuid>`).
- `session.close()`: temp cwd 삭제 + best-effort 세션 삭제(gemini `--delete-session`/codex `delete`; claude orphan→cleanup TODO).
- 3종 모두 명시적 session-id + resume 지원 확인됨(`--help` 실측). 모든 send argv 는 §4.3 보안 통과.

### 4.3 S3 엔진 보안 하드닝 (codex s3eng 58%/머지불가 반영)
1. **Windows cmd 인젝션 차단**: COMSPEC 를 `%SystemRoot%\System32\cmd.exe` 로 **고정**(부모 env 무시). model명/session uuid/path 등 모든 env·user-derived argv 에 **엄격 allowlist regex**(모델 `[A-Za-z0-9._:@/-]+`, uuid 정형, 메타문자 `& | < > ^ % !` 거부). 가능 시 `.cmd` 대신 실 `.exe`/node entrypoint 직접 호출.
2. **nonzero-exit fail-closed**: `_run_cli` → `CompletedProcess` 반환. probe 는 `returncode==0` 필수. judge 는 nonzero exit → `engine_error`→FAILED(명시적 known-benign code 만 예외). stdout 에 JSON 조각 있어도 exit≠0 면 JUDGED 금지.
3. **probe 과신 제거 + behavioral**: `--help` 검사는 `help_probe`(설치+플래그) — "검증된 격리 아님". **behavioral probe**(temp cwd canary: 랜덤토큰 파일 두고 "읽어라" 프롬프트 → 도구 비활성이면 토큰 미유출/파일불변 확인)를 **run 당 엔진별 1회(캐시)** 실행, usable = `help_probe AND behavioral_probe_passed`. (Ultracode: LLM 1회 호출 비용 수용.)
4. **env scrub 정정**: `GEMINI_API_KEY_FILE` 제거. config dir(USERPROFILE/CODEX_HOME 등) 전달은 인증에 필요하나 behavioral probe 가 profile/config 외부 파일 접근 차단을 확인.
5. **binary 해석 강화**: `AUDITAI_JUDGE_<ENGINE>_PATH` 절대경로 지원, repo-내부/상대/메타문자 경로 거부, resolved path 를 `probe.detail` 기록+테스트.
6. **출력 추출 견고화**: codex usage footer = 줄-앵커 정확 패턴만 절단(JSON 내부 오절단 방지), ANSI = CSI/OSC 포괄 제거.
7. **★run.py 배선(codex s3eng 최우선 지적)**: build_judge_engine→judge_tasks 가 테스트에서만 호출됨 → 실 scan 경로 미배선. eligible `JudgeTask` 생성→`build_judge_engine`→`judge_tasks`→`to_report_counts()`→`RunReport` + cli `--judge-engine` 추가(verdict-C full switch 와 함께).

**§4.3 보강(codex s3sess PLAN 68%/조건부 — 구현 전 확정)**:
- **순서**: S3 회계 **run.py 배선을 먼저**(테스트 전용 장식 방지) → 그 다음 세션/보안 하드닝.
- **nonzero-exit**: `_run_cli`→`CompletedProcess[str]` 반환. `run()`은 `returncode!=0`→`EngineError`(stdout JSON 무시). help/probe 도 returncode 0 필수.
- **COMSPEC**: `SystemRoot` 검증 후 `Path(SystemRoot)/System32/cmd.exe` 고정, 없으면 fail. parent COMSPEC 사용 금지.
- **argv 검증자(必)**: `validate_model_arg`/`validate_uuid_arg`/`validate_effort_arg`/`validate_binary_path` 를 `_argv()` 전에 강제+테스트. codex session id 는 `^[0-9a-fA-F-]{36}$` allowlist(복수/없음/초과/메타문자→session start FAILED).
- **behavioral probe 필수화**: `behavioral_probe_run=False`면 `usable=False`(둘 다 유지 금지 — 우회 유발). canary 를 temp cwd + repo 밖 경로 둘 다 두고 stdout/stderr/세션 transcript 토큰 미출현 + 파일 mtime/hash 불변 확인. 실패/불확실=unusable. help probe=run 캐시, behavioral=엔진 config·argv mode·cwd policy 키로 캐시(세션 생성 경로 smoke).
- **세션 lifecycle fail-closed**: start/send/resume **실패→FAILED**. close 의 **세션 transcript 삭제 실패는 보안상 FAILED** 급(cleanup warning 과 분리). 삭제 불가 엔진(claude)은 run-scoped ephemeral `CLAUDE_CONFIG_DIR`(run temp)로 격리.
- **세션 결정론**: `judge.py` 가 `with engine.start_session() as s:` 로 new/resume 를 일괄 결정, `_judge_one` 은 `s.send()` 만(엔진이 결정하면 비결정론). 세션 temp cwd 엔 canary 외 후보 파일 금지.
- **s3 상태 의미분리**: `s3_reached`(단계 도달) vs `s3_completed=all judged` 분리(현 모호성 제거).

## 5. S4 — Finding Draft (신규 `auditai/report.py`)
- judged 후보(verdict ∈ 계약 `Verdict`: `static_path_triaged_positive`/`likely_risk`/`suspicious`/`needs_manual_review`; `false_positive`/`judgement_skipped` 는 finding draft 제외) → `FindingReport`(finding_id, title, severity, cwe, file, line, source_to_sink_path, evidence_snippets, why_sanitizer_insufficient, impact, remediation, confidence, responsible_disclosure_note). **vulnerability_confirmed=False 불변.**
- **title 접두 강제(codex r1 M5): "Potential"/"Needs manual review"** — 확정 finding 처럼 보이지 않게.
- artifact: `findings.jsonl` + `findings_report.md`(사람 검토용 draft). 기존 scope_selection_report.md 와 별개.

## 6. 파이프라인 배선 (run.py)
순서: G1 → S0(diff/AI) → **S1 candidates** → 프레임워크 탐지/G2 → (run_codeql 시) **S2 CodeQL evidence + 상관** → **S2.5 gate** → **S3 judge(eligible)** → **S4 reports** → Track B inventory → gates G3/G4 → `resolve_run_status`.
- status: FINDINGS_PRESENT 가 이제 judged FindingReport(또는 heuristic_positive_only 후보/Track B inventory)로 뒷받침. judged finding 0 + 신뢰가능 + S2/S3 완료 → NO_VULN_FOUND. S3 미실행(키없음/예산) → 미완료로 처리(NO_VULN 금지).
- 기존 artifacts(7종) 유지 + 신규(candidates/flow_evidence/llm_gate/judgements/findings/findings_report).

### 6.1 단계 분리 + 타입 고정 아티팩트 핸드오프 (★아키텍처 고정 — 사용자 2026-06-21)
**현황(정직)**: 계약(pydantic StrictModel)으로 각 단계 데이터 형태는 고정돼 있고 아티팩트도 쓰지만, 현재 `run.py` 는 **단일 함수 in-memory 핸드오프**(scope→added_attr→scan 객체를 인자로 직접 전달)이고 아티팩트는 진단용 side-output 일 뿐 **다음 단계가 읽지 않는다**. → 사용자 요구 미충족. 아래로 고정.

**원칙**: 5단계는 하나의 워크플로우지만 각 단계는 **독립 pure transform**. 단계 Sn 은 **자신이 선언한 입력 아티팩트(들)만**(`input_refs`, 타입 로드+스키마 검증) 입력으로 받아, 자기 아티팩트를 **정해진 템플릿**(canonical JSON; 사람 단계는 +MD)으로 산출한다. **"직전 1개"가 아니라 그 단계가 실제 필요로 하는 아티팩트들**이다(codex pipeline-qa): S2.5=`s1+s2`, S4=`s3+s1+s2`. 단계는 서로의 내부(in-memory 상태)를 참조하지 않는다 — **선언된 입력 아티팩트가 곧 계약**. 그 아티팩트들만 있으면 **독립 실행·독립 테스트·중단지점 resume** 가능(resume CLI 는 다중 입력: 예 `--in s3_judgements.json --in s1_candidates.json`).

**단계 경계 아티팩트(고정·버전드, 각각 `schema_version`+`stage`+입력참조 스탬프)**:
- S0 → `s0_attribution.json`: {scope(DiffScope), attributions(AILineAttribution[]), ai_lines, completed}
- S1 → `s1_candidates.json`: {candidates(FindingCandidate[]), candidate_inventory, unknown_sink_count, fn_note} (s0 입력)
- S2 → `s2_evidence.json`: {taint_results(CodeQLTaintResult[]), evidence(FlowEvidence[] by candidate_id), s2_completed, codeql_version} (s1 입력)
- S2.5 → `s2_5_gate.json`: {gate_decisions(LlmGateDecision[]), tasks(JudgeTask[]), eligible_count} (s1+s2 입력)
- S3 → `s3_judgements.json`: {JudgeRun(outcomes+counts)} (s2.5 입력)
- S4 → `s4_findings.json` + `findings_report.md`: {findings(FindingReport[])} + 사람용 MD (s3+s1/s2 입력)
- final → `run_report.json`: RunReport(집계)

**규약**:
- 각 단계: `load_input(path)→typed`(schema_version 검증, 불일치=fail-closed/ANALYSIS_ERROR) → `run_stage(input)→output` → `write_output(output,path)`(canonical JSON; 해당 시 MD 렌더).
- JSON = 모든 경계의 기계 핸드오프(단일 진실 템플릿). MD = 사람 단계(S4 findings_report, scope_selection_report) 렌더.
- 오케스트레이터(`run.py`→stage 시퀀서)는 단계를 순서 실행하며 각 아티팩트를 영속화하고 **다음 단계엔 아티팩트(경로/로드모델)를** 넘긴다. 어느 단계든 앞 아티팩트로 재실행 가능(decoupled, 재현가능, 디버그가능).
- StageArtifact 래퍼 모델(StrictModel)로 경계마다 검증. 골든 아티팩트 fixture 로 경계별 독립 테스트.
- **★단독 실행 + resume(사용자 2026-06-21 핵심)**: 각 단계는 **앞 아티팩트 파일만으로 단독 실행되는 독립 모듈**. 중간에 끊겨도 처음부터 안 돌리고 **해당 아티팩트로 그 다음 단계를 바로 이어서** 실행. 실현:
  - 단계별 진입점: `auditai stage <s1|s2|s2.5|s3|s4> --in <prior_artifact.json> --out <artifact.json>`(+ repo 필요 단계는 `--repo`). 예: candidates 후 중단 → `auditai stage s2 --in s1_candidates.json --repo <path> --out s2_evidence.json` 로 S2 부터 재개.
  - 통합 resume: `auditai run --resume-from <stage> --artifacts-dir <dir>`(해당 dir 의 앞 아티팩트 로드 후 그 단계부터).
  - **아티팩트 자기기술(self-describing)**: 각 아티팩트가 `repo`/`commit_sha`/입력 소스 파일참조/도구버전을 스탬프 → repo 필요 단계(S2 CodeQL, S4 snippet)도 아티팩트로 필요한 것을 rehydrate. 입출력 포맷 고정이 곧 resumability 의 전제.
- **구현 시점**: verdict-C full switch(run.py 배선) 단계에서 stage 함수 추출 + 경계 아티팩트 모델 + 시퀀서 + 단계 진입점/resume CLI 로 일괄 적용.

**§6.1 보강(codex pipeline PLAN 82%/조건부 — 아키텍처 "맞다" 검증, 구현 전 확정)**:
1. **valid-empty ≠ failed-empty**: 각 아티팩트에 `status: ok|partial|error`. `load_input` 이 `error` 면 다음 단계 실행 금지 → 오케스트레이터가 `stage_error.json`+`run_report.json`(ANALYSIS_ERROR)로 종료. 부분 S2 = `status:partial`+`errors[]`+부분 evidence. "정상 빈 결과"와 "실패 빈 결과"를 같은 JSON 으로 표현 절대 금지.
2. **StageArtifact[T] = 메타 래퍼**(schema_version/stage/status/repo/sha/input_refs/tool_versions/errors), payload = 그 단계의 **로드 가능한 모델만**(전 내부모델 raw dump 금지).
3. **JudgeRun round-trip 금지**: `s3_judgements.json` payload = `{outcomes, eligible_candidate_ids, s3_completed}` 만(검증 입력), counts 는 load 시 **재계산**(저장된 report_counts 와 불일치 → fail-closed). `RunReport` 는 **최종 집계물(단계 아티팩트 아님)**. `resolve_run_status` 는 s0~s4+gates+inventory 집계로 **마지막에 1회** 계산.
4. **G1~G4 = 직교 메타게이트**(S0~S4 "안"에 억지로 넣지 말 것).
5. **순서(확정)**: artifact-boundary + **FakeEngine S3 배선 먼저** → 그 다음 `JudgeSession`(세션+보안) 교체(같은 PR 혼합 금지, 회귀위험).
6. **load_input = JSON 만**. MD 는 s4_findings.json/run_report.json 에서 렌더하는 파생물(다음 단계 입력 금지).

## 7. 하위호환·테스트
- 기존 235 tests 보존(흐름 변경 지점만 갱신). S3 는 `FakeEngine`(고정 JSON 반환)으로 결정적 테스트 — 네트워크/CLI 0. 실 CLI 엔진 테스트(`claude -p`/`codex exec`/`gemini -p`)는 해당 CLI 가 PATH 에 있을 때만(skipif).
- 엔진 어댑터 단위 테스트: JSON 추출 파서(코드펜스/ANSI/envelope strip, repair 재시도), CLI 미설치 시 graceful degrade.
- 새 테스트: S1 후보생성(owasp_sourced 6종 sink 탐지), S2 상관(planted CWE-78 → flow_exists), S2.5 게이트, S3 FakeEngine 판정 조립+불변식, S4 리포트 생성, end-to-end(owasp repo → judged findings).

## 8. "대략적으로라도 찾기" 수용 기준
- owasp_sourced fixture: S1 이 6개 OWASP sink 후보 생성 → (CodeQL 있으면) S2 가 그중 source-bearing 건 flow_exists → S2.5 eligible → S3(Fake/실LLM) judged → S4 FindingReport.
- 실 fastapi planted CWE-78: end-to-end 로 judged FindingReport 1건(vulnerability_confirmed=False, reliable).

## 9. 명시적 비범위(이후 phase)
split-config aiOnFlow QL(정확 static_path_confirmed) · Semgrep S1A · LLM candidate miner S1C · Starlette/Strawberry custom source model · cross-language · RAG/KB 학습루프 · 외부 제보.

## 11. codex PLAN r1 반영 — 선결 계약 확장 + 구현 순서 (확정)
codex r1(62%, 조건부)이 지목한 "돌아가는 척하며 clean 오독" 4선결 + MAJOR 를 계약부터 닫는다.

### 11.1 계약(contracts.py + cli.py) 확장 — **구현 1단계(0순위)**, r2 반영 확정
codex r2 가 두 fail-open(`judgement_skipped`, S0 UNKNOWN sink)을 "계약에 먼저 박아라" 함. 1단계 범위 확장:
- **RunStatus 신규 `SEMANTIC_JUDGE_NOT_RUN`**(r1 C1): NOT_RUN 계열, unreliable.
- **신규 enum `JudgeRunState = judged | skipped | failed`**(r2 M4): parse 실패/미판정을 `Verdict.false_positive` 와 **다른 축**으로 분리. judged 일 때만 `SemanticJudgement`(verdict) 채움.
- **RunReport 확장**(옵셔널 디폴트, 하위호환): `s3_completed: bool=True`, `llm_eligible_count:int=0`, `judged_count:int=0`, **`judgement_skipped_count:int=0`**(r2 C1), `candidate_inventory: list[CandidateInventoryItem]=[]`(r1 M2), **`s0_attribution_completed:bool=True`**, **`unknown_sink_candidate_count:int=0`**(r2 C2).
- **resolve_run_status 분기**(precedence, r2 C1/C2): 위치 = 기존 `ANALYSIS_ERROR(s2 미완)` **직후, G3/G4 이전**.
  - `s0_attribution_completed=False` 또는 `unknown_sink_candidate_count>0` → fail-closed(ANALYSIS_ERROR/전용) — UNKNOWN+KB sink 있으면 NO_VULN 금지.
  - `llm_eligible_count>0` AND (`not s3_completed` OR `judged_count < llm_eligible_count` OR `judgement_skipped_count>0`) → **SEMANTIC_JUDGE_NOT_RUN**.
  - `candidate_inventory>0`(judged finding 0 이어도) → FINDINGS_PRESENT/ANALYSIS_ERROR 판정 반영(clean 오독 차단).
- **cli.py exit 분류**(r2 M5): `SEMANTIC_JUDGE_NOT_RUN` 을 `_HARD_FAIL`(exit 2)에 즉시 등록 + exhaustive 분류 테스트 갱신(미분류면 RuntimeError).
- **FlowEvidence.approximation_kind**(r1 C3/r2 M3): `Literal["generic_codeql_ai_sink_intersection"] | None`. `approximation_kind is not None` 이면 static_path_confirmed 는 근사 + confidence<1 + evidence_backend_version, **report 문구에서 "confirmed" 단어 금지**. docstring 을 "MVP approximation"으로 갱신. **compute_llm_eligible 불변(요건 유지)**.
- **CodeQLTaintResult**(r1 M1/r2 M2): SARIF→evidence 중간모델 — primary location region, threadFlow 전체 node region, **마지막 sink node**, raw result id, rule_id, cwe 보존. `FindingReport` 를 evidence 로 재사용 금지. **primary sink ≠ 마지막 threadFlow sink → ambiguous reject.**
- **CandidateInventoryItem**: Track A′/heuristic/UNKNOWN+KB sink 후보 인벤토리(candidate_id, file, line, capability, reason, ai_attribution_state).
- **JudgeOutput.verdict = 계약 `Verdict` enum**(r1 M5): static_path_triaged_positive|likely_risk|suspicious|false_positive|needs_manual_review.

### 11.2 S0 구현 경로(r2 M1)
`attribution.attribute_scope()` 결과를 diff added line range 와 교차해 `AILineAttribution[]` 생성. **`scope.attribute_addition()`(DeletionAttribution 반환) 재사용 금지.** blame 실패/멀티커밋 라인 → UNKNOWN(is_ai=False) 로 정직 표기하고 그 sink 는 `candidate_inventory`(unknown_sink_candidate_count++).

### 11.3 S3 CLI 보안(r2 M6)
엔진별 golden test 로 검증: `cwd=temp`, **최소 env allowlist**(CLI 인증 필수 항목만 유지, `GIT_CONFIG_*`·작업 secret 제거), stdin-only prompt, stdout/stderr size cap, timeout, no-tools/read-only flags. (주의: HOME/인증 프로필 완전 제거 시 CLI 인증이 깨질 수 있으므로 엔진별로 인증 경로만 남기고 나머지 scrub.)

### 11.4 구현 순서(codex r2 확정)
1. **계약+CLI 확장**(11.1 전부) + resolve_run_status + cli exit + 테스트 → **codex CODE QA**(여기서 두 fail-open 닫힘 확인).
2. **S0** AILineAttribution(11.2, attribute_scope 교차) → codex QA.
3. **S1** known-KB AST seed scanner + KB 배선 + FN/UNKNOWN 카운트 → codex QA.
4. **S2** CodeQLTaintResult 파서(codeFlow sink 보존) + exact-overlap 상관 + approximation 표기 → codex QA.
5. **S2.5** 배선 + **S3** CLI 멀티엔진(11.3, FakeEngine 우선, 실 CLI skipif) + JudgeRunState → codex QA.
6. **S4** report(title "Potential" 접두) + run.py 전체 배선 + status + end-to-end → codex QA.
각 단계 [[codex-review-mandatory-auditai]] 준수(구현 후 보고 전 codex).

## 10. codex 판정 요청 포인트
1. **§2 static_path_confirmed 근사 정의**가 "빈 결과 오독 금지"와 양립하나? 근사를 정직하게 표기하면 충분한가, 아니면 compute_llm_eligible 을 건드려야 하나(어느 쪽이 덜 위험)?
2. **S1 AST-only**(Semgrep/LLM miner 없이)가 "대략적으로라도 찾기" MVP 로 충분한가? high-recall 원칙 위반 없나? KB 미탑재 sink 누락은 어떻게 정직 표기?
3. **S2 상관 휴리스틱**(파일+라인근접+CWE)이 잘못된 evidence 부여(다른 finding 을 후보에 귀속) 위험은? candidate_id 일치 외에 어떤 안전장치?
4. **S3 graceful degrade**(CLI 미설치/미인증/예산초과)가 false NO_VULN 를 만들지 않게 status 와 어떻게 엮나? FakeEngine 주입이 테스트 무결성 해치나?
   - **★CLI 멀티엔진 설계(사용자 결정)**: SDK/API 키 대신 `claude -p`/`codex exec`/`gemini -p` subprocess 호출. (a) JSON 강제출력→robust 파싱(코드펜스/ANSI/envelope strip + repair)이 신뢰가능한가, 구조화출력 부재의 위험은? (b) subprocess 보안(prompt injection 으로 CLI 가 도구 실행/파일접근? claude -p 도구 비활성·codex read-only sandbox 로 충분한가)? (c) 엔진 추상화가 codex/gemini/claude 를 각각 독립 수정 가능하게 깔끔한가? (d) 비결정성(같은 후보 다른 판정)·타임아웃·부분출력 처리?
5. **S4 / 불변식**: vulnerability_confirmed=False 가 전 경로 보존되나? FindingReport 가 "확정"으로 오해되지 않게?
6. 전체 배선이 기존 gates/RunStatus/"빈 결과 오독 금지"를 깨지 않나? 단계 실패(S1 parse 실패, S2 CodeQL 실패, S3 API 실패)별 fail-closed 가 일관되나?
7. MVP 범위가 과대(한 번에 너무 많음)인가? 분해 순서 제안(예: S1→S4 골격 먼저, S3 실LLM 마지막)?

## 12. 검증 단계 — 기제보 중복 취약점 판별 (★최종 추가 기능, 사용자 2026-06-21 / codex 검토 필요)
**요구**: 검증 단계에서, 발견 취약점이 "GitHub 제보방식"(공개 취약점)으로 **이미 제보된 중복**인지 아닌지 판별하는 로직을 넣는다. 신규(novel) vs 기제보(duplicate)를 구분해 PoC 가 **신규 취약점에 집중**하게 한다. **지금 MVP 개발 완료 후 마지막에** 추가(현재 미착수).

**위치/흐름**: S3 judge 산출 → S4 FindingReport enrichment 단계. judged 후보를 리포트로 초안화하기 전/직후에 novelty 판정.

**판별 대상 = 공개 제보 소스**: GitHub Security Advisory(GHSA), OSV.dev(GHSA/CVE 패키지 생태계 집계), CVE, 대상 repo 의 security advisory/issue. (네트워크 의존 신규 — 오프라인/실패 시 fail-closed.)

**로직(초안, codex 검토 대상)**:
- 입력: 대상 repo/패키지 + finding 의 {CWE, sink/capability, 파일·컴포넌트, (가능 시) 버전}.
- 조회: OSV.dev API(패키지→known vulns) + GHSA(repo) → 후보 advisory 목록.
- 매칭: 패키지 + CWE + 영향 컴포넌트 + 설명 유사도. **의미 매칭은 S3 LLM 보조**(advisory 설명 vs finding 의미 비교) — 단 evidence 없는 추측 금지 원칙 유지.
- 출력(계약 확장 필요): `FindingReport.known_advisory_refs: list[str]`(GHSA/CVE id) + `novelty: novel|likely_duplicate|uncertain`. duplicate 는 표시·강등, novel 은 부각.
- **fail-closed/정직**: 조회 불가/불확실 → `uncertain`(절대 거짓 "novel" 금지 — 기제보를 신규로 오인해 재제보하면 안 됨). uncertain 은 사람검토 플래그.

**PoC 연계**: LangGraph Check Point 체인(CVE-2025-67644 / CVE-2026-28277 / CVE-2026-27022)은 `likely_duplicate`(known)로 분류 → 신규 탐색에 집중. [[auditai-poc-langgraph]].

**구현 전제**: [[codex-review-mandatory-auditai]] — PLAN 검토 후 착수. MVP(S0~S4 end-to-end + 실 타깃 FN/FP) 완료가 선행.
