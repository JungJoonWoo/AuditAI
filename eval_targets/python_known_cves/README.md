# python_known_cves (target_type=known_cve) — real-world 효과 입증 (T5)
**선별 기준** (초기 5~10개 수동):
- Python-heavy repo
- GHSA/CVE/NVD 또는 advisory 존재
- vulnerable commit vs fixed commit 비교 가능, patch diff 명확
- source→sink 또는 removed guard 로 설명 가능
대상 후보군: LangChain/LangGraph류 agent/checkpointer/memory/persistence 역직렬화·SSRF,
deser→SQLi→RCE chain 사례. **실선별·구축은 P0-3b(CodeQL 설치) 이후** (P0 에선 기준만).
mutation/shadow 와 달리 이게 유일한 real-world recall 입증 트랙.
