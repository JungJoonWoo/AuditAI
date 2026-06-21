# docs 인덱스

AuditAI 설계·계획·검증 문서. **난잡 방지 규칙**: codex 작업 파일(`.codex-prompt-*`, `.codex-out-*`)은
transient — 검증 step 이 끝나면 삭제하고 점수만 `CODEX_HISTORY.md` 에 남긴다(.gitignore 처리).

| 문서 | 역할 | 상태 |
|---|---|---|
| [03-blueprint.md](03-blueprint.md) | **★ canonical 청사진** — AuditAI 가 무엇인지(4-state, Track A/B, 게이트, 데이터계약) | 활성 (codex 96 sign-off) |
| [05-p0-blockers.md](05-p0-blockers.md) | **P0 구현 계획** (B1~B4 + 게이트) — 현재 구현이 따르는 계약 | 활성 |
| [04-hybrid-candidate-discovery.md](04-hybrid-candidate-discovery.md) | S1 hybrid 후보탐지(LLM miner 등) — **로드맵 설계**(MVP 밖) | 참고/로드맵 |
| [01-direction-review.md](01-direction-review.md) | 방향성·기술계약 상세 — **03 이 QL split-config 계약을 normative 로 상속**(출처) | 유지(참조됨) |
| [02-architecture.md](02-architecture.md) | 초기 아키텍처(MVP/로드맵 분리) — 03 에 통합됨 | history(참고) |
| [efficacy-report.md](efficacy-report.md) | **효과 실측 리포트** — Track A/B recall+precision 통제 실험(MVP 목적 달성 실증) | 활성(self-review, codex 재검증 대기) |
| [CODEX_HISTORY.md](CODEX_HISTORY.md) | codex 검증 라운드별 점수·결론 요약(원본 삭제 후 보존) | 활성 |
| [CODEX_VERIFICATION_QUEUE.md](CODEX_VERIFICATION_QUEUE.md) | codex 리밋 중 개발분의 **미검증 항목 Q1~Q5** | 활성(리밋 해제 시 소비) |

루트 [README.md](../README.md) = 사용자용 개요/실행/한계. 코드: `auditai/`, 테스트: `tests/`,
평가셋: `eval_targets/`, framework fixtures: `tests/framework_sources/`.
