# 의도적 취약: Starlette Request.query_params(source) → open(sink). CWE-22.
from starlette.requests import Request
from starlette.responses import PlainTextResponse


async def handler(request: Request):  # Starlette route
    name = request.query_params["name"]  # source
    with open(name) as f:  # sink: path traversal
        return PlainTextResponse(f.read())
