import warnings
import os
import json

import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.security import HTTPBearer
from fastapi.middleware.cors import CORSMiddleware
from fastapi.templating import Jinja2Templates
from fastapi.responses import Response
from starlette.middleware.base import BaseHTTPMiddleware

from utils.configs import enable_gateway, api_prefix

warnings.filterwarnings("ignore")


# ============================================================
#  Middleware
# ============================================================
class TokenExtractorMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        token = None
        auth_header = request.headers.get("authorization")
        if auth_header:
            if auth_header.lower().startswith("bearer "):
                token = auth_header[7:].strip()
            else:
                token = auth_header.strip()

        if not token:
            token = request.headers.get("x-api-key")
            if token:
                token = token.strip()

        if not token:
            token = request.headers.get("api-key")
            if token:
                token = token.strip()

        if not token:
            token = request.query_params.get("key") or request.query_params.get("api_key")
            if token:
                token = token.strip()

        request.state.token = token

        # حقن الهيدر عشان الـ Gateway يقراه
        if token:
            new_headers = [(k, v) for k, v in request.scope["headers"] if k.lower() != b"authorization"]
            new_headers.append((b"authorization", f"Bearer {token}".encode()))
            request.scope["headers"] = new_headers

        return await call_next(request)


log_config = uvicorn.config.LOGGING_CONFIG
default_format = "%(asctime)s | %(levelname)s | %(message)s"
access_format = r'%(asctime)s | %(levelname)s | %(client_addr)s: %(request_line)s %(status_code)s'
log_config["formatters"]["default"]["fmt"] = default_format
log_config["formatters"]["access"]["fmt"] = access_format


app = FastAPI(
    docs_url=f"/{api_prefix}/docs" if api_prefix else "/docs",
    redoc_url=f"/{api_prefix}/redoc" if api_prefix else "/redoc",
    openapi_url=f"/{api_prefix}/openapi.json" if api_prefix else "/openapi.json",
)

app.add_middleware(TokenExtractorMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

templates = Jinja2Templates(directory="templates")
security_scheme = HTTPBearer(auto_error=False)


# ============================================================
#  راوتاتنا (قبل الـ Gateway)
# ============================================================
@app.get("/ping")
async def ping():
    return {"status": "ok"}


@app.get("/check-token")
async def check_token(request: Request):
    token = getattr(request.state, "token", None)
    return {"token_received": bool(token), "preview": token[:10] + "..." if token else None}


@app.get("/v1/models")
async def list_models(request: Request):
    from utils.configs import authorization_list
    token = getattr(request.state, "token", None)
    if not token or token not in authorization_list:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return {
        "object": "list",
        "data": [
            {"id": "gpt-4o", "object": "model", "created": 1688888888, "owned_by": "openai"},
            {"id": "gpt-4o-mini", "object": "model", "created": 1688888888, "owned_by": "openai"},
            {"id": "gpt-4", "object": "model", "created": 1688888888, "owned_by": "openai"},
            {"id": "gpt-3.5-turbo", "object": "model", "created": 1688888888, "owned_by": "openai"},
            {"id": "o1", "object": "model", "created": 1688888888, "owned_by": "openai"},
            {"id": "o1-mini", "object": "model", "created": 1688888888, "owned_by": "openai"},
        ]
    }


# ============================================================
#  إضافة التوكنات - يدعم JSON و text/plain
# ============================================================
@app.post("/tokens/upload")
@app.post("/api/tokens/upload")
async def upload_tokens(request: Request):
    from utils.configs import authorization_list
    import utils.globals as globals
    from utils.Logger import logger

    token = getattr(request.state, "token", None)
    if not token or token not in authorization_list:
        raise HTTPException(status_code=401, detail="Unauthorized")

    # اقرا البودي بأي شكل
    body = b""
    try:
        body = await request.body()
    except Exception:
        pass

    text = ""
    content_type = request.headers.get("content-type", "")

    # لو JSON
    if "application/json" in content_type:
        try:
            data = json.loads(body.decode("utf-8"))
            if isinstance(data, dict):
                text = data.get("text", "") or data.get("token", "") or data.get("tokens", "")
            elif isinstance(data, list):
                text = "\n".join(data)
        except Exception as e:
            logger.error(f"JSON parse error: {e}")

    # لو form-urlencoded
    elif "application/x-www-form-urlencoded" in content_type or "multipart/form-data" in content_type:
        try:
            form = await request.form()
            text = form.get("text", "") or form.get("token", "")
        except Exception as e:
            logger.error(f"Form parse error: {e}")

    # لو text/plain أو أي حاجة تانية
    else:
        text = body.decode("utf-8", errors="ignore")

    if not text:
        raise HTTPException(status_code=400, detail="No token text provided")

    count = 0
    for line in text.split("\n"):
        line = line.strip()
        if line and not line.startswith("#"):
            globals.token_list.append(line)
            with open(globals.TOKENS_FILE, "a", encoding="utf-8") as f:
                f.write(line + "\n")
            count += 1

    tokens_count = len(set(globals.token_list) - set(globals.error_token_list))
    logger.info(f"Uploaded {count} tokens. Total: {tokens_count}")
    return {"status": "success", "uploaded": count, "total": tokens_count}


@app.get("/tokens")
@app.get("/api/tokens")
async def tokens_page(request: Request):
    """يرجع عدد التوكنات في المخزن"""
    import utils.globals as globals
    return {
        "total_tokens": len(globals.token_list),
        "error_tokens": len(globals.error_token_list),
        "available": len(set(globals.token_list) - set(globals.error_token_list)),
    }


# ============================================================
#  استيراد الـ Gateway بعد راوتاتنا
# ============================================================
import api.chat2api

if enable_gateway:
    import gateway.share
    import gateway.login
    import gateway.chatgpt
    import gateway.gpts
    import gateway.admin
    import gateway.v1
    import gateway.backend
else:
    @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH", "TRACE"])
    async def reverse_proxy():
        raise HTTPException(status_code=404, detail="Gateway is disabled")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5005))
    uvicorn.run("app:app", host="0.0.0.0", port=port)