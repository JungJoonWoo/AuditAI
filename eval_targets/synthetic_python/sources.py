"""KB SourceSpec test_fixture — tainted source 예시(선언적 검증용)."""
import os
import flask
import requests

app = flask.Flask(__name__)


@app.get("/a")
def from_flask_args():
    return flask.request.args.get("q")          # flask.request.args (http_request)


@app.post("/b")
def from_flask_json():
    return flask.request.get_json()             # flask.request.json (http_request)


def from_env():
    return os.environ.get("SECRET")             # os.environ (environment)


def from_llm(agent):
    return agent.run("summarize")               # llm/agent tool result (llm_output)
