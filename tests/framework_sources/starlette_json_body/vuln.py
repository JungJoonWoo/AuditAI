# 의도적 취약: Starlette Request.json(source) → yaml.load(sink). CWE-502.
import yaml
from starlette.requests import Request


async def handler(request: Request):
    body = await request.json()  # source
    return yaml.load(body["cfg"], Loader=yaml.Loader)  # sink: unsafe deserialization
