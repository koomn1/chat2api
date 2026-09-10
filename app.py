import warnings
import os

import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.templating import Jinja2Templates
from starlette.middleware.base import BaseHTTPMiddleware

from utils.configs import enable_gateway, api_prefix

warnings.filterwarnings("ignore")


# ============================================================
#  Middleware: استخراج التوكن من مصادر متعددة
#  (لأن Railway أحياناً بيشيل هيدر Authorization)
# ============================================================
class TokenExtractorMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        token = None

        # 1. هيدر Authorization (Bearer أو مباشر)
        auth_header = request.headers.get("authorization")
        if auth_header:
            if auth_header.lower().startswith("bearer "):
                token = auth_header[7:].strip()
            else:
                token = auth_header.strip()

        # 2. هيدر x-api-key
        if not token:
            token = request.headers.get("x-api-key")
            if token:
                token = token.strip()

        # 3. هيدر api-key
        if not token:
            token = request.headers.get("api-key")
            if token:
                token = token.strip()

        # 4. Query parameter (key أو api_key)
        if not token:
            token = request.query_params.get("key") or request.query_params.get("api_key")
            if token:
                token = token.strip()

        # تخزين التوكن في request.state
        request.state.token = token

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

# إضافة الـ Middleware (قبل الـ CORS)
app.add_middleware(TokenExtractorMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

templates = Jinja2Templates(directory="templates")

# ============================================================
#  تعديل مهم: auto_error=False عشان ميطلعش خطأ لما مفيش توكن
# ============================================================
security_scheme = HTTPBearer(auto_error=False)


# ============================================================
#  استيراد التطبيق الأساسي والـ Gateway
# ============================================================
from app import app

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
#  نقاط نهاية للفحص
# ============================================================
@app.get("/ping")
async def ping():
    return {"status": "ok", "message": "Chat2API is running"}


@app.get("/check-token")
async def check_token(request: Request):
    token = getattr(request.state, "token", None)
    if token:
        return {
            "status": "ok",
            "token_received": True,
            "token_preview": token[:10] + "..."
        }
    return {
        "status": "no_token",
        "message": "No token received from any source"
    }


# ============================================================
#  تشغيل السيرفر
# ============================================================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5005))
    uvicorn.run("app:app", host="0.0.0.0", port=port)