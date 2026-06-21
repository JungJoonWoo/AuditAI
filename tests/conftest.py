"""테스트 공용 — 합성 git 저장소 fixture.

실제 AI 귀속 시나리오(직접 author=Claude / Co-authored-by 트레일러 / claude[bot] /
subject 언급만)를 가진 결정적 repo 를 생성해 S0 를 단위 검증한다(네트워크 불필요).
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest


def _run(repo: Path, *args: str, env: dict[str, str] | None = None) -> None:
    full_env = {
        "GIT_CONFIG_NOSYSTEM": "1",
        "HOME": str(repo),  # 글로벌 설정 격리
        "PATH": _path_env(),
    }
    if env:
        full_env.update(env)
    proc = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        env=full_env,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"git {args} failed: {proc.stderr}")


def _path_env() -> str:
    import os

    return os.environ.get("PATH", "")


def _commit(
    repo: Path,
    path: str,
    content: str,
    message: str,
    author: tuple[str, str],
    committer: tuple[str, str] | None = None,
    epoch: int = 1700000000,
) -> None:
    committer = committer or author
    f = repo / path
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(content, encoding="utf-8")
    _run(repo, "add", path)
    env = {
        "GIT_AUTHOR_NAME": author[0],
        "GIT_AUTHOR_EMAIL": author[1],
        "GIT_COMMITTER_NAME": committer[0],
        "GIT_COMMITTER_EMAIL": committer[1],
        "GIT_AUTHOR_DATE": f"@{epoch} +0000",
        "GIT_COMMITTER_DATE": f"@{epoch} +0000",
    }
    _run(repo, "commit", "-m", message, env=env)


HUMAN = ("Mikyo King", "mikyo@example.com")
CLAUDE_AUTHOR = ("Claude", "noreply@anthropic.com")
CLAUDE_BOT = ("claude[bot]", "41898282+claude[bot]@users.noreply.github.com")

_COAUTH_BODY = "feat: add helper\n\nCo-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>\n"


@pytest.fixture
def git_repo(tmp_path: Path) -> Path:
    """app.py 를 5커밋에 걸쳐 누적 작성해 라인별 귀속이 갈리게 만든다.

    라인 1-3 human / 4-5 confirmed_ai(직접 author=Claude) / 6-7 probable_ai(트레일러) /
    8 confirmed_ai(claude[bot]) / 9 human(subject 에 claude 언급만). + 제외 대상 generated 파일.
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    _run(repo, "init", "-b", "main")

    base = ["L1 human", "L2 human", "L3 human"]
    _commit(repo, "app.py", "\n".join(base) + "\n", "init", HUMAN, epoch=1700000000)

    v2 = base + ["L4 claude", "L5 claude"]
    _commit(
        repo,
        "app.py",
        "\n".join(v2) + "\n",
        "feat: claude-authored block",
        CLAUDE_AUTHOR,
        committer=HUMAN,  # author=Claude, committer=human (6fc9dfc 패턴)
        epoch=1700000100,
    )

    v3 = v2 + ["L6 coauth", "L7 coauth"]
    # Co-authored-by 트레일러는 commit message body 로 들어가야 하므로 -F 사용
    f = repo / "app.py"
    f.write_text("\n".join(v3) + "\n", encoding="utf-8")
    _run(repo, "add", "app.py")
    msg = repo / ".msg"
    msg.write_text(_COAUTH_BODY, encoding="utf-8")
    _run(
        repo,
        "commit",
        "-F",
        str(msg),
        env={
            "GIT_AUTHOR_NAME": HUMAN[0],
            "GIT_AUTHOR_EMAIL": HUMAN[1],
            "GIT_COMMITTER_NAME": HUMAN[0],
            "GIT_COMMITTER_EMAIL": HUMAN[1],
            "GIT_AUTHOR_DATE": "@1700000200 +0000",
            "GIT_COMMITTER_DATE": "@1700000200 +0000",
        },
    )

    v4 = v3 + ["L8 bot"]
    _commit(repo, "app.py", "\n".join(v4) + "\n", "docs: weekly audit", CLAUDE_BOT, epoch=1700000300)

    v5 = v4 + ["L9 human"]
    _commit(
        repo,
        "app.py",
        "\n".join(v5) + "\n",
        "ci: Add Claude Code GitHub Workflow",  # 'claude' 언급만, author=human
        HUMAN,
        epoch=1700000400,
    )

    # 제외 대상 generated 파일
    _commit(
        repo,
        "pkg/__generated__/api.py",
        "X = 1\n",
        "chore: generated",
        CLAUDE_AUTHOR,
        epoch=1700000500,
    )
    # dot-dir 경로 (정규화가 '.github' 를 깎지 않아야 함 — codex Q3)
    _commit(
        repo,
        ".github/workflows/ci.yml",
        "name: ci\n",
        "ci: add workflow",
        HUMAN,
        epoch=1700000600,
    )
    return repo


@pytest.fixture
def diff_repo(tmp_path: Path) -> Path:
    """PR 시나리오: base(human) → head(Claude 단일 commit)가 authz 가드 삭제 +
    run()→subprocess.run(shell=True) 변경. build_diff_scope 는 base='HEAD~1', head='HEAD'.
    """
    repo = tmp_path / "diff"
    repo.mkdir()
    _run(repo, "init", "-b", "main")
    base = (
        "def handler(req):\n"
        "    if not req.user.is_admin:\n"
        "        raise PermissionError\n"
        "    data = req.args.get('q')\n"
        "    run(data)\n"
    )
    _commit(repo, "app.py", base, "init", HUMAN, epoch=1700000000)
    head = (
        "def handler(req):\n"
        "    data = req.args.get('q')\n"
        "    subprocess.run(data, shell=True)\n"
    )
    f = repo / "app.py"
    f.write_text(head, encoding="utf-8")
    _run(repo, "add", "app.py")
    _run(
        repo,
        "commit",
        "-m",
        "refactor: simplify handler",
        env={
            "GIT_AUTHOR_NAME": CLAUDE_AUTHOR[0],
            "GIT_AUTHOR_EMAIL": CLAUDE_AUTHOR[1],
            "GIT_COMMITTER_NAME": HUMAN[0],
            "GIT_COMMITTER_EMAIL": HUMAN[1],
            "GIT_AUTHOR_DATE": "@1700000100 +0000",
            "GIT_COMMITTER_DATE": "@1700000100 +0000",
        },
    )
    return repo


@pytest.fixture
def weaken_repo(tmp_path: Path) -> Path:
    """약화 시나리오: Claude commit 이 verify=True→False, safe_load→load 로 변경."""
    repo = tmp_path / "weaken"
    repo.mkdir()
    _run(repo, "init", "-b", "main")
    base = (
        "import requests, yaml\n"
        "def fetch(url, blob):\n"
        "    r = requests.get(url, verify=True)\n"
        "    cfg = yaml.safe_load(blob)\n"
        "    return r, cfg\n"
    )
    _commit(repo, "net.py", base, "init", HUMAN, epoch=1700000000)
    head = (
        "import requests, yaml\n"
        "def fetch(url, blob):\n"
        "    r = requests.get(url, verify=False)\n"
        "    cfg = yaml.load(blob)\n"
        "    return r, cfg\n"
    )
    f = repo / "net.py"
    f.write_text(head, encoding="utf-8")
    _run(repo, "add", "net.py")
    _run(
        repo, "commit", "-m", "perf: tweak",
        env={
            "GIT_AUTHOR_NAME": CLAUDE_AUTHOR[0],
            "GIT_AUTHOR_EMAIL": CLAUDE_AUTHOR[1],
            "GIT_COMMITTER_NAME": HUMAN[0],
            "GIT_COMMITTER_EMAIL": HUMAN[1],
            "GIT_AUTHOR_DATE": "@1700000100 +0000",
            "GIT_COMMITTER_DATE": "@1700000100 +0000",
        },
    )
    return repo


@pytest.fixture
def multi_commit_repo(tmp_path: Path) -> Path:
    """PR 에 2개 commit: human 이 라인 추가, Claude 가 GUARD 삭제 → log -S 검증 경로."""
    repo = tmp_path / "multi"
    repo.mkdir()
    _run(repo, "init", "-b", "main")
    _commit(
        repo, "app.py",
        "A = 1\nGUARD_CHECK_TOKEN = require_admin()\nC = 3\n",
        "init", HUMAN, epoch=1700000000,
    )
    _commit(repo, "app.py", "A = 1\nGUARD_CHECK_TOKEN = require_admin()\nC = 3\nD = 4\n",
            "feat: add D", HUMAN, epoch=1700000100)
    _commit(repo, "app.py", "A = 1\nC = 3\nD = 4\n",
            "refactor: drop guard", CLAUDE_AUTHOR, committer=HUMAN, epoch=1700000200)
    return repo


@pytest.fixture
def multi_import_repo(tmp_path: Path) -> Path:
    """helper-only PR: 변경 파일(helper.py)은 framework import 없음, 미변경 파일(routes.py)이
    `import os, fastapi` 다중 import. repo-wide grep 이 과소탐지 없이 fastapi 를 잡아야 함(R4-2)."""
    repo = tmp_path / "multiimp"
    repo.mkdir()
    _run(repo, "init", "-b", "main")
    _commit(repo, "routes.py",
            "import os, fastapi\n\napp = fastapi.FastAPI()\n", "init", HUMAN, epoch=1700000000)
    _commit(repo, "helper.py", "def util():\n    return 1\n", "init helper", HUMAN, epoch=1700000050)
    # PR: Claude 가 helper.py 만 수정(framework import 없음)
    (repo / "helper.py").write_text("def util():\n    return 2\n", encoding="utf-8")
    _run(repo, "add", "helper.py")
    _run(repo, "commit", "-m", "tweak helper", env={
        "GIT_AUTHOR_NAME": CLAUDE_AUTHOR[0], "GIT_AUTHOR_EMAIL": CLAUDE_AUTHOR[1],
        "GIT_COMMITTER_NAME": HUMAN[0], "GIT_COMMITTER_EMAIL": HUMAN[1],
        "GIT_AUTHOR_DATE": "@1700000100 +0000", "GIT_COMMITTER_DATE": "@1700000100 +0000",
    })
    return repo


@pytest.fixture
def dynamic_import_repo(tmp_path: Path) -> Path:
    """동적 import(importlib.import_module("fastapi"))만 쓰는 repo — 정적 import 탐지로는 못 잡음(R5-1)."""
    repo = tmp_path / "dynimp"
    repo.mkdir()
    _run(repo, "init", "-b", "main")
    _commit(repo, "app.py", "import importlib\n\napp = None\n", "init", HUMAN, epoch=1700000000)
    (repo / "app.py").write_text(
        'import importlib\n\nfa = importlib.import_module("fastapi")\napp = fa.FastAPI()\n',
        encoding="utf-8")
    _run(repo, "add", "app.py")
    _run(repo, "commit", "-m", "use dynamic import", env={
        "GIT_AUTHOR_NAME": CLAUDE_AUTHOR[0], "GIT_AUTHOR_EMAIL": CLAUDE_AUTHOR[1],
        "GIT_COMMITTER_NAME": HUMAN[0], "GIT_COMMITTER_EMAIL": HUMAN[1],
        "GIT_AUTHOR_DATE": "@1700000100 +0000", "GIT_COMMITTER_DATE": "@1700000100 +0000",
    })
    return repo


@pytest.fixture
def declared_not_imported_repo(tmp_path: Path) -> Path:
    """requirements.txt 에 fastapi 선언됐지만 어떤 .py 도 import 안 함(난독화 동적 import 모사) →
    의존성 fallback 이 fail-closed 로 잡아야 함(R5-1)."""
    repo = tmp_path / "declonly"
    repo.mkdir()
    _run(repo, "init", "-b", "main")
    _commit(repo, "requirements.txt", "fastapi>=0.100\n", "deps", HUMAN, epoch=1700000000)
    _commit(repo, "app.py", "X = 1\n", "init", HUMAN, epoch=1700000050)
    (repo / "app.py").write_text("X = 2\n", encoding="utf-8")
    _run(repo, "add", "app.py")
    _run(repo, "commit", "-m", "tweak", env={
        "GIT_AUTHOR_NAME": CLAUDE_AUTHOR[0], "GIT_AUTHOR_EMAIL": CLAUDE_AUTHOR[1],
        "GIT_COMMITTER_NAME": HUMAN[0], "GIT_COMMITTER_EMAIL": HUMAN[1],
        "GIT_AUTHOR_DATE": "@1700000100 +0000", "GIT_COMMITTER_DATE": "@1700000100 +0000",
    })
    return repo


@pytest.fixture
def owasp_efficacy_repo(tmp_path: Path) -> Path:
    """AI 가 6개 OWASP 클래스 취약점을 추가(FastAPI source + 인식 sink 형태).

    실측으로 Track A 가 6/6 탐지함을 확인한 형태(CWE-78/89/22/502/918/94). 효과 회귀 잠금용."""
    repo = tmp_path / "owasp"
    repo.mkdir()
    _run(repo, "init", "-b", "main")
    _commit(repo, "app.py", "from fastapi import FastAPI\napp = FastAPI()\nX = 1\n",
            "init", HUMAN, epoch=1700000000)
    head = (
        "import subprocess, pickle, yaml, requests, sqlite3\n"
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n\n\n"
        "@app.get('/c')\n"
        "def cmd(i: str):\n    return subprocess.run(i, shell=True)\n\n\n"      # CWE-78
        "@app.get('/s')\n"
        "def sql(name: str):\n    cur = sqlite3.connect('db').cursor()\n"
        "    return cur.execute(f\"SELECT * FROM u WHERE n='{name}'\")\n\n\n"    # CWE-89
        "@app.get('/p')\n"
        "def path(fn: str):\n    return open(fn).read()\n\n\n"                   # CWE-22
        "@app.get('/d')\n"
        "def deser(b: str):\n    return pickle.loads(b.encode())\n\n\n"         # CWE-502
        "@app.get('/u')\n"
        "def ssrf(url: str):\n    return requests.get(url).text\n\n\n"          # CWE-918
        "@app.get('/e')\n"
        "def ce(x: str):\n    return eval(x)\n"                                  # CWE-94
    )
    (repo / "app.py").write_text(head, encoding="utf-8")
    _run(repo, "add", "app.py")
    _run(repo, "commit", "-m", "feat: add endpoints", env={
        "GIT_AUTHOR_NAME": CLAUDE_AUTHOR[0], "GIT_AUTHOR_EMAIL": CLAUDE_AUTHOR[1],
        "GIT_COMMITTER_NAME": HUMAN[0], "GIT_COMMITTER_EMAIL": HUMAN[1],
        "GIT_AUTHOR_DATE": "@1700000100 +0000", "GIT_COMMITTER_DATE": "@1700000100 +0000",
    })
    return repo


@pytest.fixture
def dep_boundary_repo(tmp_path: Path) -> Path:
    """requirements.txt 경계 케이스: fastapi-utils/starlette-x/strawberry_graphql 는 배제,
    strawberry-graphql 만 strawberry 로 매핑(codex Q1r6 R6-4)."""
    repo = tmp_path / "depbound"
    repo.mkdir()
    _run(repo, "init", "-b", "main")
    _commit(repo, "requirements.txt",
            "fastapi-utils>=1\nstarlette-x==0.1\nstrawberry-graphql==0.2\nstrawberry_graphql==0.3\n",
            "deps", HUMAN, epoch=1700000000)
    return repo


@pytest.fixture
def fastapi_pr_repo(tmp_path: Path) -> Path:
    """base(safe FastAPI handler) → head(Claude adds subprocess shell=True). CodeQL Track A 검증용."""
    repo = tmp_path / "fapr"
    repo.mkdir()
    _run(repo, "init", "-b", "main")
    base = (
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n\n\n"
        "@app.get('/x')\n"
        "def x(cmd: str):\n"
        "    return {'echo': cmd}\n"
    )
    _commit(repo, "api.py", base, "init", HUMAN, epoch=1700000000)
    head = (
        "import subprocess\n"
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n\n\n"
        "@app.get('/x')\n"
        "def x(cmd: str):\n"
        "    return subprocess.run(cmd, shell=True)\n"
    )
    (repo / "api.py").write_text(head, encoding="utf-8")
    _run(repo, "add", "api.py")
    _run(
        repo, "commit", "-m", "feat: run cmd",
        env={
            "GIT_AUTHOR_NAME": CLAUDE_AUTHOR[0], "GIT_AUTHOR_EMAIL": CLAUDE_AUTHOR[1],
            "GIT_COMMITTER_NAME": HUMAN[0], "GIT_COMMITTER_EMAIL": HUMAN[1],
            "GIT_AUTHOR_DATE": "@1700000100 +0000", "GIT_COMMITTER_DATE": "@1700000100 +0000",
        },
    )
    return repo


def _claude_commit(repo: Path, path: str, content: str, msg: str, epoch: int = 1700000100) -> None:
    """변경 파일 1개를 Claude author 로 커밋(committer=human)하는 헬퍼."""
    (repo / path).parent.mkdir(parents=True, exist_ok=True)
    (repo / path).write_text(content, encoding="utf-8")
    _run(repo, "add", path)
    _run(repo, "commit", "-m", msg, env={
        "GIT_AUTHOR_NAME": CLAUDE_AUTHOR[0], "GIT_AUTHOR_EMAIL": CLAUDE_AUTHOR[1],
        "GIT_COMMITTER_NAME": HUMAN[0], "GIT_COMMITTER_EMAIL": HUMAN[1],
        "GIT_AUTHOR_DATE": f"@{epoch} +0000", "GIT_COMMITTER_DATE": f"@{epoch} +0000",
    })


@pytest.fixture
def fastapi_internal_starlette_repo(tmp_path: Path) -> Path:
    """G2 over-flag 시나리오(codex 판정): 변경 파일(api.py)은 fastapi 만 import, repo 내부 미변경
    파일(internal/server.py)은 starlette import(FastAPI 가 Starlette 위에 빌드된 transitive 모사).

    case A(framework 없는 변경 .py 없음) → G2 스코프 = {fastapi}, starlette 무시 → over-flag 없음."""
    repo = tmp_path / "fapi_starlette"
    repo.mkdir()
    _run(repo, "init", "-b", "main")
    _commit(repo, "internal/server.py",
            "from starlette.applications import Starlette\napp = Starlette()\n",
            "init internal", HUMAN, epoch=1700000000)
    _commit(repo, "api.py",
            "from fastapi import FastAPI\napp = FastAPI()\n", "init api", HUMAN, epoch=1700000050)
    # PR: Claude 가 api.py(fastapi 만)에 라우트 추가 — starlette 파일은 안 건드림.
    _claude_commit(repo, "api.py",
                   "import subprocess\nfrom fastapi import FastAPI\napp = FastAPI()\n\n\n"
                   "@app.get('/c')\ndef c(i: str):\n    return subprocess.run(i, shell=True)\n",
                   "feat: add cmd route")
    return repo


@pytest.fixture
def starlette_helper_only_repo(tmp_path: Path) -> Path:
    """helper-only PR: 변경 파일(helper.py)은 framework import 없음, 미변경 routes.py 가 starlette
    import. case B → repo-wide fallback 이 starlette 를 잡아 under-detection 방지(MODEL_MISSING)."""
    repo = tmp_path / "stl_helper"
    repo.mkdir()
    _run(repo, "init", "-b", "main")
    _commit(repo, "routes.py",
            "from starlette.routing import Route\nroutes = []\n", "init routes", HUMAN, epoch=1700000000)
    _commit(repo, "helper.py", "def util():\n    return 1\n", "init helper", HUMAN, epoch=1700000050)
    _claude_commit(repo, "helper.py", "def util():\n    return 2\n", "tweak helper")
    return repo


@pytest.fixture
def mixed_fastapi_helper_starlette_repo(tmp_path: Path) -> Path:
    """혼합 PR(codex 가 지적한 제안 구멍): 변경 파일 둘 — api.py(fastapi import) + helper.py(framework
    없음). 미변경 routes.py 는 starlette import.

    "변경 framework 가 비었나"로 fallback 을 끄면(틀린 트리거) helper 의 frameworkless 가 묻혀 starlette
    under-detection. 올바른 트리거("framework 없는 변경 .py 존재")면 case B → starlette 잡아 MODEL_MISSING."""
    repo = tmp_path / "mixed"
    repo.mkdir()
    _run(repo, "init", "-b", "main")
    _commit(repo, "routes.py",
            "from starlette.routing import Route\nroutes = []\n", "init routes", HUMAN, epoch=1700000000)
    _commit(repo, "api.py",
            "from fastapi import FastAPI\napp = FastAPI()\n", "init api", HUMAN, epoch=1700000040)
    _commit(repo, "helper.py", "def util():\n    return 1\n", "init helper", HUMAN, epoch=1700000060)
    # PR: 두 파일 동시 변경 — api.py(fastapi) + helper.py(frameworkless), 같은 commit.
    (repo / "api.py").write_text(
        "import subprocess\nfrom fastapi import FastAPI\napp = FastAPI()\n\n\n"
        "@app.get('/c')\ndef c(i: str):\n    return subprocess.run(i, shell=True)\n", encoding="utf-8")
    (repo / "helper.py").write_text("def util():\n    return 2\n", encoding="utf-8")
    _run(repo, "add", "api.py", "helper.py")
    _run(repo, "commit", "-m", "feat: route + helper tweak", env={
        "GIT_AUTHOR_NAME": CLAUDE_AUTHOR[0], "GIT_AUTHOR_EMAIL": CLAUDE_AUTHOR[1],
        "GIT_COMMITTER_NAME": HUMAN[0], "GIT_COMMITTER_EMAIL": HUMAN[1],
        "GIT_AUTHOR_DATE": "@1700000100 +0000", "GIT_COMMITTER_DATE": "@1700000100 +0000",
    })
    return repo


@pytest.fixture
def fastapi_var_dynamic_starlette_repo(tmp_path: Path) -> Path:
    """codex G2 over-flag r2 #2: 변경 파일이 fastapi 를 정적 import 하면서 동시에 변수 동적 import
    (`mod=...; import_module(mod)`)로 미검증 starlette 를 끌어옴 + requirements 에 starlette 선언.

    변수 동적 import 는 정적으로 대상 미상(불확실) → case A 라도 dep-fallback 활성 → declared starlette
    미탐지 → fail-closed NOT_RUN(빈 결과 오독 금지)."""
    repo = tmp_path / "vardyn"
    repo.mkdir()
    _run(repo, "init", "-b", "main")
    _commit(repo, "requirements.txt", "fastapi>=0.100\nstarlette>=0.27\n", "deps", HUMAN, epoch=1700000000)
    _commit(repo, "api.py",
            "from fastapi import FastAPI\napp = FastAPI()\n", "init api", HUMAN, epoch=1700000050)
    # PR: Claude 가 fastapi import 를 유지하면서 변수 동적 import 로 starlette 를 끌어옴(정적 미탐지).
    _claude_commit(repo, "api.py",
                   "import importlib\nfrom fastapi import FastAPI\n\n"
                   "app = FastAPI()\nname = 'starl' + 'ette'\nmod = importlib.import_module(name)\n",
                   "feat: dynamic plugin load")
    return repo


@pytest.fixture
def starlette_helper_space_dyn_repo(tmp_path: Path) -> Path:
    """codex G2 over-flag r4 #1: helper-only PR(변경 helper.py frameworkless) + 미변경 파일이 공백 표기
    동적 import(`importlib.import_module ("starlette")`). repo-wide grep 이 공백 표기도 잡아야 한다."""
    repo = tmp_path / "spacedyn"
    repo.mkdir()
    _run(repo, "init", "-b", "main")
    _commit(repo, "loader.py",
            'import importlib\nm = importlib.import_module ("starlette")\n', "init loader", HUMAN,
            epoch=1700000000)
    _commit(repo, "helper.py", "def util():\n    return 1\n", "init helper", HUMAN, epoch=1700000050)
    _claude_commit(repo, "helper.py", "def util():\n    return 2\n", "tweak helper")
    return repo


@pytest.fixture
def helper_only_line_continuation_repo(tmp_path: Path) -> Path:
    """codex G2 over-flag r7 #1 (under-detection): helper-only PR + 미변경 파일이 line-continuation
    import(`import os, \\`↵`fastapi`). line-anchored grep 은 후보로 못 올리지만 토큰 grep→AST 는 잡아야 한다."""
    repo = tmp_path / "linecont"
    repo.mkdir()
    _run(repo, "init", "-b", "main")
    _commit(repo, "cont.py", "import os, \\\n    fastapi\n\napp = fastapi.FastAPI()\n",
            "init cont", HUMAN, epoch=1700000000)
    _commit(repo, "helper.py", "def util():\n    return 1\n", "init helper", HUMAN, epoch=1700000050)
    _claude_commit(repo, "helper.py", "def util():\n    return 2\n", "tweak helper")
    return repo


@pytest.fixture
def helper_only_unparseable_candidate_repo(tmp_path: Path) -> Path:
    """codex G2 over-flag r7 #2 (fail-closed): helper-only PR + 미변경 파일이 framework 토큰(`fastapi`)을
    가졌지만 syntactically invalid(parse 불가). 후보로는 잡히나 AST 확정 불가 → repo_wide_incomplete=True
    → detection-incomplete → NOT_RUN(빈 결과 오독 금지)."""
    repo = tmp_path / "unparse"
    repo.mkdir()
    _run(repo, "init", "-b", "main")
    _commit(repo, "broken.py", "import fastapi\ndef f(:\n    pass\n", "init broken", HUMAN, epoch=1700000000)
    _commit(repo, "helper.py", "def util():\n    return 1\n", "init helper", HUMAN, epoch=1700000050)
    _claude_commit(repo, "helper.py", "def util():\n    return 2\n", "tweak helper")
    return repo


@pytest.fixture
def helper_only_string_import_repo(tmp_path: Path) -> Path:
    """codex G2 over-flag r6 #2 (over-detection negative): helper-only PR + 미변경 파일이 multiline
    문자열 안에 줄-시작 `import fastapi` 를 포함(실제 import 아님, docstring/예시). line-anchored grep 은
    오탐하지만 repo-wide AST 확정은 안 잡아야 한다 → repo_wide 에 fastapi 없음."""
    repo = tmp_path / "stringimp"
    repo.mkdir()
    _run(repo, "init", "-b", "main")
    _commit(repo, "docs_example.py",
            'EXAMPLE = """\nUsage:\nimport fastapi\napp = fastapi.FastAPI()\n"""\n',
            "init docs", HUMAN, epoch=1700000000)
    _commit(repo, "helper.py", "def util():\n    return 1\n", "init helper", HUMAN, epoch=1700000050)
    _claude_commit(repo, "helper.py", "def util():\n    return 2\n", "tweak helper")
    return repo


@pytest.fixture
def helper_only_spaced_method_repo(tmp_path: Path) -> Path:
    """codex G2 over-flag r5 #1 (over-detection negative): helper-only PR + 미변경 파일이 임의 객체
    메서드 `obj . import_module("fastapi")`(importlib 아님, 공백 속성 접근). repo-wide AST 스캔이
    callee qualifier 로 이를 정확히 걸러야 한다 → repo_wide 에 fastapi 가 들어가면 안 됨(over-flag 방지)."""
    repo = tmp_path / "spacedmethod"
    repo.mkdir()
    _run(repo, "init", "-b", "main")
    _commit(repo, "loader.py",
            'class L:\n    def import_module(self, n):\n        return n\n\n'
            'obj = L()\nx = obj . import_module("fastapi")\n', "init loader", HUMAN, epoch=1700000000)
    _commit(repo, "helper.py", "def util():\n    return 1\n", "init helper", HUMAN, epoch=1700000050)
    _claude_commit(repo, "helper.py", "def util():\n    return 2\n", "tweak helper")
    return repo


@pytest.fixture
def fastapi_var_dynamic_no_dep_repo(tmp_path: Path) -> Path:
    """codex G2 over-flag r3 #3: 변경 파일이 fastapi import + 변수 동적 import 인데 **매니페스트 선언도
    없고 repo 내 다른 정적 import 도 없음**. 불확실성 신호는 보강을 켜지만 해소할 게 없다.

    → 불확실성 신호 자체는 NOT_RUN 을 만들지 않는다((B) 계약): G2 는 fastapi(검증됨)만으로 PASS.
    어떤 framework 인지 미상인 순수 변수 동적 import 는 MVP 미탐지(README ⑥)."""
    repo = tmp_path / "vardynnodep"
    repo.mkdir()
    _run(repo, "init", "-b", "main")
    _commit(repo, "api.py",
            "from fastapi import FastAPI\napp = FastAPI()\n", "init api", HUMAN, epoch=1700000050)
    _claude_commit(repo, "api.py",
                   "import importlib\nfrom fastapi import FastAPI\n\n"
                   "app = FastAPI()\nname = input()\nmod = importlib.import_module(name)\n",
                   "feat: dynamic plugin load")
    return repo


@pytest.fixture
def fastapi_aux_dynamic_starlette_repo(tmp_path: Path) -> Path:
    """codex G2 over-flag r2 #1/#4: 변경 파일이 `__import__("fastapi", globals(), locals(), [...])`
    (대상은 리터럴, 보조 인자는 비-리터럴 Call) + 미변경 starlette 파일.

    대상 인자만 보므로 uncertain=False → case A 유지 → starlette 무시(over-flag 재발 없음)."""
    repo = tmp_path / "auxdyn"
    repo.mkdir()
    _run(repo, "init", "-b", "main")
    _commit(repo, "internal/server.py",
            "from starlette.applications import Starlette\napp = Starlette()\n",
            "init internal", HUMAN, epoch=1700000000)
    _commit(repo, "api.py", "fa = None\n", "init api", HUMAN, epoch=1700000050)
    _claude_commit(repo, "api.py",
                   'fastapi = __import__("fastapi", globals(), locals(), ["FastAPI"])\n'
                   "app = fastapi.FastAPI()\n",
                   "feat: lazy import fastapi")
    return repo


@pytest.fixture
def danger_add_repo(tmp_path: Path) -> Path:
    """안전형 제거 없이 위험 라인만 추가 (verify=False 신규) → 약화 후보 아님(Track A)."""
    repo = tmp_path / "danger"
    repo.mkdir()
    _run(repo, "init", "-b", "main")
    _commit(repo, "n.py", "import requests\ndef f(u):\n    pass\n", "init", HUMAN, epoch=1700000000)
    head = "import requests\ndef f(u):\n    return requests.get(u, verify=False)\n"
    (repo / "n.py").write_text(head, encoding="utf-8")
    _run(repo, "add", "n.py")
    _run(
        repo, "commit", "-m", "feat",
        env={
            "GIT_AUTHOR_NAME": CLAUDE_AUTHOR[0], "GIT_AUTHOR_EMAIL": CLAUDE_AUTHOR[1],
            "GIT_COMMITTER_NAME": HUMAN[0], "GIT_COMMITTER_EMAIL": HUMAN[1],
            "GIT_AUTHOR_DATE": "@1700000100 +0000", "GIT_COMMITTER_DATE": "@1700000100 +0000",
        },
    )
    return repo


@pytest.fixture
def moved_repo(tmp_path: Path) -> Path:
    """파일 rename 시나리오 — blame 의 rename 추적으로 file_move 손실모드 검출 (codex Q7)."""
    repo = tmp_path / "moved"
    repo.mkdir()
    _run(repo, "init", "-b", "main")
    _commit(repo, "orig.py", "a\nb\nc\n", "init", HUMAN, epoch=1700000000)
    _run(repo, "mv", "orig.py", "renamed.py")
    _run(
        repo,
        "commit",
        "-m",
        "refactor: rename",
        env={
            "GIT_AUTHOR_NAME": CLAUDE_AUTHOR[0],
            "GIT_AUTHOR_EMAIL": CLAUDE_AUTHOR[1],
            "GIT_COMMITTER_NAME": HUMAN[0],
            "GIT_COMMITTER_EMAIL": HUMAN[1],
            "GIT_AUTHOR_DATE": "@1700000100 +0000",
            "GIT_COMMITTER_DATE": "@1700000100 +0000",
        },
    )
    return repo
