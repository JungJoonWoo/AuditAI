# synthetic_python (runtime TargetType=synthetic; eval_config type=**plumbing**)
> 두 축 구분(codex Q4): `--target-type synthetic`(런타임 RunReport.target_type)과 eval_config 의
> `type`(plumbing/efficacy/known_cve/smoke)은 별개다. 이 corpus 는 런타임상 synthetic 이지만 효과입증
> 축에서는 **plumbing**(효과입증 아님).

파이프라인 동작/회귀 검증용 의도적 취약 스니펫. 효과 입증 타겟 아님(우리가 만든 것).
포함: command/sql/path/ssrf/deserialization/code injection, unsafe config,
sanitizer sufficient·insufficient, guard removal(before/after).

## ⚠️ Track A 탐지 한계 (실측, codex Q2 재확인 대상)
이 스니펫들은 `def handler(user_input): subprocess.run(user_input, shell=True)` 처럼 **bare 함수
파라미터**를 sink 에 쓴다. CodeQL taint(Track A)는 **인식된 source**(remote/user-controlled)가
있어야 flow 를 잡는데, 맨 함수 파라미터는 RemoteFlowSource 가 아니다 → **현재 Track A 로는
0 findings → NO_VULN_FOUND**. (동일 sink 를 FastAPI 핸들러로 감싸면 source 인식 → CWE-78 탐지됨, 실측 확인.)
따라서 `# ... TP` 라벨은 *source-aware 탐지기 기준* 이며, **MVP Track A 단독으로는 미탐지**다.
- 이 corpus 의 실제 회귀 역할: 파이프라인 plumbing(G2 skip / s2 완료 / AI-라인 필터 / Track B 가드제거),
  taint 탐지 역할 아님. Track A taint 효과는 source-bearing fixture(`tests/.../fastapi_*`)로 검증.
- "위험 sink + 임의 입력" 패턴 탐지(source 무관)는 청사진 S1 Semgrep/KB 후보탐지 = **post-MVP**.
