from __future__ import annotations

import os
import base64
import time
import uuid
from collections import defaultdict, deque
from typing import Optional

from fastapi import FastAPI, Body, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict
from starlette.middleware.base import BaseHTTPMiddleware

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.exceptions import InvalidSignature

# -----------------------------
# App
# -----------------------------
app = FastAPI(
    title="Secure Context Verifier (No Auth)",
    description="Trusted signature verification + untrusted sandbox (no authentication, hardened)",
    version="1.0.0",
)

# -----------------------------
# Safety knobs (MVP defaults)
# -----------------------------
MAX_BODY_BYTES = 64 * 1024         # 64KB request body limit
MAX_MESSAGE_LEN = 10_000           # /verify-signature message max length
MAX_CONTENT_LEN = 20_000           # /sandbox-untrusted content max length (truncate)

RATE_LIMIT_VERIFY = 60             # 60 req/min per IP
RATE_LIMIT_SANDBOX = 15            # 15 req/min per IP
WINDOW_SEC = 60

# In-memory buckets (single instance MVP; serverless에선 best-effort)
_bucket_verify = defaultdict(deque)
_bucket_sandbox = defaultdict(deque)

# -----------------------------
# Public key loading (ENV-based, non-fatal)
# -----------------------------
# Vercel Environment Variable:
#   PUBLIC_KEY_PEM_DEFAULT = "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
# 줄바꿈이 힘들면 \\n 로 넣고 아래에서 복원합니다.
PUBLIC_KEYS = {}

def _load_public_key_from_env(var_name: str):
    raw = os.getenv(var_name, "").strip()
    if not raw:
        return None
    try:
        pem_bytes = raw.replace("\\n", "\n").encode("utf-8")
        return load_pem_public_key(pem_bytes)
    except Exception:
        return None

default_key = _load_public_key_from_env("PUBLIC_KEY_PEM_DEFAULT")
if default_key is not None:
    PUBLIC_KEYS["default"] = default_key


# -----------------------------
# Helpers
# -----------------------------
def make_request_id() -> str:
    return uuid.uuid4().hex


def error_payload(error: str, message: str, request_id: str) -> dict:
    return {"error": error, "message": message, "request_id": request_id}


def error_json(status_code: int, error: str, message: str, request_id: str) -> JSONResponse:
    return JSONResponse(status_code=status_code, content=error_payload(error, message, request_id))


def client_ip(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def allow_rate(bucket: defaultdict, key: str, limit: int, window_sec: int) -> bool:
    now = time.time()
    q = bucket[key]
    while q and (now - q[0]) > window_sec:
        q.popleft()
    if len(q) >= limit:
        return False
    q.append(now)
    return True


# -----------------------------
# Middleware: Max body size
# -----------------------------
class MaxBodySizeMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request_id = make_request_id()

        cl = request.headers.get("content-length")
        if cl and cl.isdigit() and int(cl) > MAX_BODY_BYTES:
            return error_json(413, "payload_too_large", "Request body too large.", request_id)

        body = await request.body()
        if len(body) > MAX_BODY_BYTES:
            return error_json(413, "payload_too_large", "Request body too large.", request_id)

        # body를 읽었으니 downstream에서 다시 읽을 수 있게 재주입
        async def receive():
            return {"type": "http.request", "body": body, "more_body": False}

        request._receive = receive  # Starlette 내부 패턴
        return await call_next(request)


app.add_middleware(MaxBodySizeMiddleware)


# -----------------------------
# Models (match OpenAPI)
# -----------------------------
class ErrorResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    error: str
    message: str
    request_id: Optional[str] = None


class SignatureVerifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    message: str
    signature: str  # base64
    public_key_id: str = "default"


class VerifyResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    is_trusted: bool
    restricted_mode: bool
    reason: str
    safe_summary: Optional[str] = None


class SandboxRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    content: str


class SandboxResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    safe_to_execute: bool
    summary: str
    injection_detected: Optional[bool] = None
    reason: Optional[str] = None


# -----------------------------
# Routes
# -----------------------------
@app.post("/verify-signature", response_model=VerifyResponse)
async def verify_signature(req: SignatureVerifyRequest, request: Request):
    request_id = make_request_id()
    ip = client_ip(request)

    if not allow_rate(_bucket_verify, ip, RATE_LIMIT_VERIFY, WINDOW_SEC):
        return error_json(429, "rate_limited", "Too many requests to /verify-signature.", request_id)

    if len(req.message) > MAX_MESSAGE_LEN:
        return error_json(400, "bad_request", f"message too long (max {MAX_MESSAGE_LEN}).", request_id)

    public_key = PUBLIC_KEYS.get(req.public_key_id)
    if not public_key:
        return error_json(
            503,
            "not_configured",
            "Public key is not configured (set PUBLIC_KEY_PEM_DEFAULT env var).",
            request_id,
        )

    try:
        signature_bytes = base64.b64decode(req.signature, validate=True)
    except Exception:
        return error_json(400, "bad_request", "Invalid base64 in signature.", request_id)

    digest_ctx = hashes.Hash(hashes.SHA256())
    digest_ctx.update(req.message.encode("utf-8"))
    digest = digest_ctx.finalize()

    try:
        public_key.verify(signature_bytes, digest, ec.ECDSA(Prehashed(hashes.SHA256())))
    except InvalidSignature:
        return error_json(401, "invalid_signature", "Signature verification failed.", request_id)
    except Exception as e:
        return error_json(400, "bad_request", f"Verification failed: {e}", request_id)

    return VerifyResponse(
        is_trusted=True,
        restricted_mode=False,
        reason="Signature valid → Trusted context",
    )


@app.post("/sandbox-untrusted", response_model=SandboxResponse)
async def sandbox_untrusted(req: SandboxRequest = Body(...), request: Request = ...):
    request_id = make_request_id()
    ip = client_ip(request)

    if not allow_rate(_bucket_sandbox, ip, RATE_LIMIT_SANDBOX, WINDOW_SEC):
        return error_json(429, "rate_limited", "Too many requests to /sandbox-untrusted.", request_id)

    content = (req.content or "").strip()
    if not content:
        return error_json(400, "bad_request", "content must be a non-empty string.", request_id)

    if len(content) > MAX_CONTENT_LEN:
        content = content[:MAX_CONTENT_LEN]

    dangerous_patterns = [
        "ignore previous instructions",
        "system prompt",
        "forget all rules",
        "delete everything",
        "you are an ai",
    ]
    lowered = content.lower()
    injection_detected = any(pat in lowered for pat in dangerous_patterns)

    snippet = content[:200] + ("..." if len(content) > 200 else "")
    summary = f"[SANDBOX SUMMARY] {snippet}"

    return SandboxResponse(
        safe_to_execute=False,
        summary=summary,
        injection_detected=injection_detected,
        reason=(
            "Untrusted content processed in sandbox. Execution blocked."
            + (" Potential injection detected!" if injection_detected else "")
        ),
    )


@app.get("/health")
async def health():
    return {
        "ok": True,
        "public_key_configured": ("default" in PUBLIC_KEYS),
        "rate_limit_mode": "best_effort_in_memory",
    }
