import warnings
import os

import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.security import HTTPBearer
from fastapi.middleware.cors import CORSMiddleware
from fastapi.templating import Jinja2Templates
from starlette.middleware.base import BaseHTTPMiddleware

from utils.configs import enable_gateway, api_prefix

warnings.filterwarnings("ignore")


# ============================================================
#  Middleware: استخراج التوكن + حقنه في الهيدر تاني
#  (عشان الـ Gateway يقدر يقراه بـ HTTPBearer)
# ============================================================
class TokenExtractorMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        token = None

        # 1. هيدر Authorization
        auth_header = request.headers.get("authorization")
        if auth_header:
            if auth_header.lower().startswith("bearer "):
                token = auth_header[7:].strip()
            else:
                token = auth_header.strip()

        # 2. x-api-key
        if not token:
            token = request.headers.get("x-api-key")
            if token:
                token = token.strip()

        # 3. api-key
        if not token:
            token = request.headers.get("api-key")
            if token:
                token = token.strip()

        # 4. Query parameter
        if not token:
            token = request.query_params.get("key") or request.query_params.get("api_key")
            if token:
                token = token.strip()

        # حفظ التوكن في state
        request.state.token = token

        # ============================================================
        #  الأهم: حقن التوكن في الهيدر عشان الـ Gateway يقدر يقراه
        # ============================================================
        if token:
            # شيل أي هيدر authorization قديم
            new_headers = [
                (k, v) for k, v in request.scope["headers"]
                if k.lower() != b"authorization"
            ]
            # ضيف هيدر authorization جديد بالتوكن
            new_headers.append(
                (b"authorization", f"Bearer {token}".encode())
            )
            request.scope["headers"] = new_headers

        response = await call_next(request)
        return response


# ============================================================
#  إعدادات الـ Logging
# ============================================================
log_config = uvicorn.config.LOGGING_CONFIG
default_format = "%(asctime)s | %(levelname)s | %(message)s"
access_format = r'%(asctime)s | %(levelname)s | %(client_addr)s: %(request_line)s %(status_code)s'
log_config["formatters"]["default"]["fmt"] = default_format
log_config["formatters"]["access"]["fmt"] = access_format


# ============================================================
#  إنشاء تطبيق FastAPI
# ============================================================
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
    return {"status": "ok", "message": "Chat2API is running"}


@app.get("/check-token")
async def check_token(request: Request):
    token = getattr(request.state, "token", None)
    # اقفل الهيدر اللي اتحقن عشان نتأكد
    injected_auth = request.headers.get("authorization", "none")
    if token:
        return {
            "status": "ok",
            "token_received": True,
            "token_preview": token[:10] + "...",
            "injected_auth_header": injected_auth[:20] + "..." if injected_auth != "none" else "none"
        }
    return {
        "status": "no_token",
        "message": "No token received from any source"
    }


@app.get("/v1/models")
async def list_models(request: Request):
    from utils.configs import authorization_list
    token = getattr(request.state, "token", None)
    if not token or token not in authorization_list:
        raise HTTPException(status_code=401, detail="Unauthorized")

    return {
        "object": "list",
        "data": [
            {"id": "gpt-4o", "object": "model", "created": 1688888888, "owned_by": "chatgpt-to-api"},
            {"id": "gpt-4o-mini", "object": "model", "created": 1688888888, "owned_by": "chatgpt-to-api"},
            {"id": "gpt-4", "object": "model", "created": 1688888888, "owned_by": "chatgpt-to-api"},
            {"id": "gpt-3.5-turbo", "object": "model", "created": 1688888888, "owned_by": "chatgpt-to-api"},
            {"id": "o1", "object": "model", "created": 1688888888, "owned_by": "chatgpt-to-api"},
            {"id": "o1-mini", "object": "model", "created": 1688888888, "owned_by": "chatgpt-to-api"},
        ]
    }


# ============================================================
#  استيراد التطبيق الأساسي والـ Gateway
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


# ============================================================
#  تشغيل السيرفر
# ============================================================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5005))
    uvicorn.run("app:app", host="0.0.0.0", port=port)