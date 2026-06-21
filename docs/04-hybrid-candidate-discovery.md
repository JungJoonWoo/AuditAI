# AuditAI — Hybrid Candidate Discovery (S1 개정 설계, draft)

> 상태: **codex 검증 대기.** 기반: [03-blueprint.md](03-blueprint.md)(canonical, codex 96/100).
> 동기(사용자 피드백 2026-06-19): static-only 후보탐지는 KB/Semgrep 룰에 없는 **신규·unknown 취약 패턴**(unknown deserialization, unsafe parser/loader, source→state→sink chain 후보, 신규 library API)을 놓친다 → CVE급 발굴 north-star와 충돌. 그래서 S1(후보탐지)을 **hybrid**로 개정한다.
> 이 설계는 03 §3.2(후보 타입)·§5 S1 을 대체/확장한다. **나머지 codex-cleared 계약(S2.5 게이트, G3 도달성=static, 등급 정직성, candidate≠finding)은 그대로 보존.**

## 0. 스테이지 번호 정합 (혼동 방지)

사용자 피드백의 "Stage 3 candidate discovery / Stage 6 judge" = 본 청사진의 **S1 후보탐지 / S3 LLM judge**. 본 문서는 S1 을 4개 하위단계(S1A~S1D)로 나눈다. LLM 은 **두 곳에서만** 등장: S1C(후보 제안) + S3(semantic judge). **워크플로 제어는 AuditAI runner 가 소유**(LLM 은 운전 안 함).

## 1. 개정된 S1 — Hybrid Candidate Discovery

```
[S1A Known Static]    Semgrep + AST scanner + KB(YAML) → known source/sink/config 후보
[S1B Unknown Surface] changed scope 의 모든 call/import/state 수집 → unknown_api/suspicious 표시
[S1C LLM Miner]       changed-function 단위 compact slice → LLM 이 'additional candidate' 제안
[S1D Validation Gate] LLM 후보의 file/line/snippet 이 실제 AST 노드와 일치하는지 검증, 불일치 폐기
         ↓ 통합 candidates (전부 candidate, finding 아님)
[S2 Flow Validation]  CodeQL split-config taint evidence (03 §5 S2 그대로)
```

### S1A — Known Static Discovery
Semgrep custom rules + lightweight AST/call scanner + KB YAML 기반 known source/sink/config 탐지. 목적: known bad 를 빠르고 안정적으로. (= 03 기존 S1 의 static 부분)

### S1B — Unknown Risk Surface Inventory (LLM 없음, 결정적)
changed scope 내:
- 모든 `CallExpression` 수집 (line, callee, receiver, args, context).
- import/module/receiver/type 수집.
- KB 에 없는 API → `unknown_api` 표시.
- 이름이 `parse|load|decode|restore|checkpoint|serialize|deserialize|render|query|execute|open|request` 계열 → `suspicious_api` 표시.
- state read/write 후보 수집(예: checkpoint/persistence store).
목적: KB 에 없는 위험 surface 를 **구조화**해 S1C LLM 이 판단할 입력으로.

### S1C — LLM Candidate Miner (NEW LLM 사용점 — 가드레일 필수)
- **입력 = 전체 repo 아님. LLM-authored changed function 단위 compact slice 만**(§3 입력 스키마). function code + imports + call inventory + known static candidates + mini KB capability list.
- LLM 은 **취약점 확정 금지** — `additional FindingCandidate` 만 제안.
- 특히: unknown deserialization/object materialization, source→state→sink chain 후보, unsafe parser/loader/decoder, model output/tool result 가 위험 capability 로 흐를 가능성, 신규 library API 의 source/sink/propagator 가능성, static rule 엔 없지만 suspicious 한 조합.
- **S1C 예산 게이트(codex 대비, S2.5 와 동형)**: `miner_budget.max_functions_per_repo`(예: 200), AI-authored(confirmed/probable) changed function 만 대상, `dedup_key=(repo,sha,function)`, 예산 초과 시 `defer_no_llm`. 비-AI 함수는 S1C 미전송.

### S1D — Candidate Validation Gate (환각 차단, 결정적)
- LLM 제안 후보의 `file/line/snippet` 이 **실제 코드의 AST 노드(CallExpression/Assignment/Config)와 일치**하는지 검증. 불일치 → **폐기**(`rejected_hallucination`).
- capability 는 known capability 에 매핑하거나 `unknown_capability` 로 저장.
- 모든 통과 후보는 **candidate** 로 유지(finding 아님) → S2 flow validation 으로.

## 2. 신규 후보 타입과 G3(도달성=static) 정합 — codex 핵심 검증 포인트

- 신규 `candidate_type = unknown_risk_surface`, `evidence_kind = llm_mined`(downstream CodeQL 검증 필요).
- **G3 보존**: LLM 이 제안한 unknown 후보도 **도달성은 여전히 static 이 보장**해야 한다. 두 갈래:
  - (a) S2 CodeQL 이 해당 sink/flow 를 모델링할 수 있으면 → taint evidence 복원 → `taint_path` 로 승격, S2.5 게이트 통과 시 S3 judge.
  - (b) CodeQL 모델이 없어 static 으로 도달성 확인 불가 → **S3 judge 로 보내지 않음**(G3 위반 방지). 대신 두 출구:
    - **KB 확장 제안**(`kb_expansion_proposal`): 새 source/sink/propagator 후보를 사람 검토 큐로 → 승인 시 KB/CodeQL 모델 추가 → 다음 실행에 static 으로 잡힘(학습 루프).
    - **`needs_manual_review` 인벤토리**.
  - 즉 unknown 후보가 LLM 단독 판정으로 "취약"이 되는 경로는 **없다**. LLM 은 발견(propose)하고, 확정 가능성은 static 이 연다.
- 이로써 "신규 취약점도 놓치지 않는다"(발견은 LLM)와 "도달성은 static 이 보장"(확정은 CodeQL)을 동시에 만족.

## 3. LLM Candidate Miner 입력 스키마 (S1C)

```json
{
  "scope_id": "func_001",
  "repo": "target",
  "commit_sha": "...",
  "file": "app/routes.py",
  "function_name": "run_task",
  "ai_attribution": "probable_ai",
  "imports": ["import pickle", "from langgraph.checkpoint.sqlite import SqliteSaver"],
  "function_code": "...",
  "call_inventory": [
    {"line": 42, "callee": "saver.get_tuple", "receiver": "saver", "args": ["config"], "known_capability": null},
    {"line": 45, "callee": "serializer.loads", "receiver": "serializer", "args": ["row['checkpoint']"], "known_capability": "unsafe_deserialization"}
  ],
  "known_static_candidates": [],
  "mini_security_kb": {"capabilities": ["command_execution","sql_execution","unsafe_deserialization","path_traversal","ssrf","template_injection","state_boundary","dangerous_config"]}
}
```

## 4. LLM Candidate Miner 출력 스키마 (S1C → S1D 입력)

```json
{
  "additional_candidates": [
    {
      "candidate_type": "unknown_risk_surface",
      "capability_guess": "unsafe_deserialization",
      "file": "app/routes.py", "line": 45,
      "code_snippet": "serializer.loads(row['checkpoint'])",
      "reason": "Data loaded from persistent checkpoint state is passed into a serializer loads function...",
      "required_followup": ["Determine serializer implementation","Trace row['checkpoint'] origin","Check whether attacker can influence checkpoint state"],
      "confidence": "medium"
    }
  ],
  "unknown_api_classifications": [
    {"callee": "saver.get_tuple", "line": 42, "classification": "state_read", "reason": "The call appears to read persisted checkpoint state."}
  ],
  "state_boundary_candidates": [
    {"boundary_type": "checkpoint_store", "read_api": "saver.get_tuple", "write_api": null, "line": 42, "confidence": "medium"}
  ]
}
```
- `state_boundary_candidates`: Slice 1 에서는 **inventory 로만 수집**(chain 분석은 V3, 03 로드맵). 자동 확정·chain 생성 금지.
- 모든 `additional_candidates`: S1D 검증 게이트 통과 후 candidate 로만 다음 단계.

## 5. Stage 3(=S1) 로그 형식

```
[S1] Hybrid candidate discovery
  [S1A] Known static discovery
    - semgrep candidates: 27 / kb sink candidates: 8 / config·smell candidates: 11
  [S1B] Unknown risk surface inventory
    - changed functions analyzed: 39 / call expressions indexed: 184
    - unknown APIs: 73 / suspicious parser·loader·state APIs: 12 / state boundary candidates: 5
  [S1C] LLM candidate mining
    - functions sent to LLM: 21 (budget 200) / additional candidates: 14 / unknown api classifications: 19
  [S1D] Candidate validation gate
    - accepted: 9 / rejected(hallucination): 5 / merged candidates: 47
[S1] Completed → candidates.jsonl
```

## 6. Slice 1 범위 (과대 금지 — codex arch 교훈 유지)

- 포함: S1A + S1B + S1C(**changed function 단위만**) + S1D.
- 제외(이후 버전): 전체 repo LLM scan, RAG, chain DB 자동 확정, exploit validation, whole-repo unknown mining.
- state_boundary 는 수집만(V3 chain 입력 예약).

## 7. codex 검증 요청 포인트 (이 개정이 만든 새 리스크)

1. S1C 가 LLM 을 후보탐지에 도입 — `miner_budget` 게이트가 firehose/비용을 실제로 막는가, 아니면 또 선언인가.
2. S1D 검증 게이트의 AST 일치 검사가 환각을 충분히 거르는가(실재 line+다른 capability 오제안은 어떻게 처리되는가 → §2 (b) 경로로 흡수됨을 확인).
3. §2 의 G3 정합(unknown 후보가 LLM 단독으로 "취약" 안 됨, 확정은 static) 이 빈틈없는가.
4. unknown_risk_surface/llm_mined 후보가 03 의 candidate 3타입·llm_eligible 산식과 충돌하지 않는가(S3 judge 진입 조건).
5. Slice 1 범위가 여전히 분해가능·작게 유지되는가(LLM miner 추가로 비대화되지 않는가).
6. KB 확장 제안(학습 루프)이 순환/무한확장 없이 사람 검토 게이트를 강제하는가.
