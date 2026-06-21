# owasp_sourced (runtime TargetType=synthetic; eval_config type=**efficacy**)
> 두 축 구분(codex Q4): 런타임 `--target-type synthetic` 과 eval_config `type=efficacy` 는 별개. 이
> corpus 는 **효과입증(efficacy)** 축의 타겟이다.


`synthetic_python`(plumbing) 과 달리, 이 corpus 는 **source-bearing**(FastAPI route param = 인식된
remote source) + **인식된 sink**(라이브러리 provenance) 형태로 6개 OWASP 클래스를 담는다.
실측으로 **Track A(CodeQL python-security-extended)가 6/6 탐지**함을 확인했다(codex Q2 R2-3/R2-4).

| 파일 | CWE | sink |
|---|---|---|
| command_injection.py | CWE-78 | subprocess.run(shell=True) |
| sql_injection.py | CWE-89 | sqlite3 cursor.execute(f"...") |
| path_traversal.py | CWE-22 | open(user_path) |
| unsafe_deserialization.py | CWE-502 | pickle.loads |
| ssrf.py | CWE-918 | requests.get(user_url) |
| code_execution.py | CWE-94 | eval |

회귀 잠금: `tests/test_run.py::test_track_a_efficacy_owasp_classes`(fixture `owasp_efficacy_repo`).
G3 는 이 corpus(또는 python_known_cves/ghsa 실제 케이스)가 eval target 에 있어야 효과입증으로 PASS.

**탐지 전제(정직 고지)**: source(framework route) + 라이브러리 sink 인식이 필요. bare 함수 파라미터
(`def f(x): subprocess.run(x, shell=True)`)나 duck-typed sink 는 Track A 미탐지 — 그 케이스는
`synthetic_python`(plumbing) 및 청사진 S1 Semgrep/KB(post-MVP) 영역.
