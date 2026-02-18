from __future__ import annotations

import base64
import os
import time
import uuid
from collections import defaultdict, deque
from typing import Optional, Tuple

import httpx
from fastapi import FastAPI, Body, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from starlette.middleware.base import BaseHTTPMiddleware

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.exceptions import InvalidSignature

# -----------------------------
# App
# -----------------------------
app = FastAPI(
    title="Prompt Firewall Backend (P-256 + Session Keys)",
    description="Trusted signature verification using ephemeral session keys and sandbox for untrusted content.",
    version="2.0.0",
)

# -----------------------------
# Safety knobs
# -----------------------------
MAX_BODY_BYTES = 64 * 1024
MAX_MESSAGE_LEN = 10_000
MAX_CONTENT_LEN = 20_000

RATE_LIMIT_REGISTER = 30
RATE_LIMIT_VERIFY = 60
RATE_LIMIT_SANDBOX = 15
WINDOW_SEC = 60

_bucket_register = defaultdict(deque)
_bucket_verify = defaultdict(deque)
_bucket_sandbox = defaultdict(deque)

SESSION_TTL_SECONDS = int(os.getenv("SESSION_TTL_SECONDS", "1800"))  # 30 min default
SESSION_KEY_PREFIX = "pfw:sess:"  # redis key prefix

UPSTASH_URL = os.getenv("UPSTASH_REDIS_REST_URL", "").strip()
UPSTASH_TOKEN = os.getenv("UPSTASH_REDIS_REST_TOKEN", "").strip()
USE_UPSTASH = bool(UPSTASH_URL and UPSTASH_TOKEN)

print("BOOT: has_url=", bool(UPSTASH_URL), "has_token=", bool(UPSTASH_TOKEN))


# best-effort in-memory fallback (serverless에선 불완전)
_mem_sessions: dict[str, Tuple[bytes, float]] = {}  # session_id -> (pem_bytes, expires_at_epoch)


# -----------------------------
# Helpers
# -----------------------------
def make_request_id() -> str:
    return uuid.uuid4().hex


def error_json(status_code: int, error: str, message: str, request_id: str) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={"error": error, "message": message, "request_id": request_id},
    )


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


def now_epoch() -> float:
    return time.time()


def epoch_to_iso(ts: float) -> str:
    # 간단 ISO-ish (UTC 표기용)
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


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

        async def receive():
            return {"type": "http.request", "body": body, "more_body": False}

        request._receive = receive
        return await call_next(request)


app.add_middleware(MaxBodySizeMiddleware)

# -----------------------------
# Upstash REST helpers
# -----------------------------
async def upstash_set(session_id: str, pem_bytes: bytes, ttl_sec: int) -> None:
    # store value as base64 to avoid escaping issues
    key = SESSION_KEY_PREFIX + session_id
    val_b64 = base64.b64encode(pem_bytes).decode("ascii")

    # Upstash REST: POST {URL}/set/{key}/{value}?EX={ttl}
    url = f"{UPSTASH_URL}/set/{key}/{val_b64}"
    headers = {"Authorization": f"Bearer {UPSTASH_TOKEN}"}
    params = {"EX": str(ttl_sec)}
    async with httpx.AsyncClient(timeout=5.0) as client:
        r = await client.post(url, headers=headers, params=params)
        r.raise_for_status()


async def upstash_get(session_id: str) -> Optional[bytes]:
    key = SESSION_KEY_PREFIX + session_id
    url = f"{UPSTASH_URL}/get/{key}"
    headers = {"Authorization": f"Bearer {UPSTASH_TOKEN}"}
    async with httpx.AsyncClient(timeout=5.0) as client:
        r = await client.get(url, headers=headers)
        r.raise_for_status()
        data = r.json()
        # {"result": "<value or null>"}
        val = data.get("result")
        if not val:
            return None
        try:
            return base64.b64decode(val.encode("ascii"))
        except Exception:
            return None


async def store_session(session_id: str, pem_bytes: bytes, ttl_sec: int) -> None:
    if USE_UPSTASH:
        await upstash_set(session_id, pem_bytes, ttl_sec)
    else:
        _mem_sessions[session_id] = (pem_bytes, now_epoch() + ttl_sec)


async def load_session_pem(session_id: str) -> Optional[bytes]:
    if USE_UPSTASH:
        return await upstash_get(session_id)
    # in-memory fallback
    item = _mem_sessions.get(session_id)
    if not item:
        return None
    pem_bytes, exp = item
    if now_epoch() > exp:
        _mem_sessions.pop(session_id, None)
        return None
    return pem_bytes


# -----------------------------
# Models
# -----------------------------
class RegisterKeyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    public_key_pem: str = Field(..., description="PEM-encoded public key (SPKI).")


class RegisterKeyResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    session_id: str
    expires_at: str
    ttl_seconds: int


class VerifySignatureRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    session_id: str
    message: str
    signature: str = Field(..., description="Base64 signature (DER-encoded ECDSA).")
    signature_format: str = Field("der", description="Only 'der' supported in this backend.")


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
@app.post("/register-key", response_model=RegisterKeyResponse)
async def register_key(req: RegisterKeyRequest, request: Request):
    request_id = make_request_id()
    ip = client_ip(request)

    if not allow_rate(_bucket_register, ip, RATE_LIMIT_REGISTER, WINDOW_SEC):
        return error_json(429, "rate_limited", "Too many requests to /register-key.", request_id)

    pem_str = (req.public_key_pem or "").strip()
    if not pem_str:
        return error_json(400, "bad_request", "public_key_pem must be non-empty.", request_id)

    # Normalize newlines: accept \n sequences too
    pem_str = pem_str.replace("\\n", "\n")
    pem_bytes = pem_str.encode("utf-8")

    # Validate that it's a P-256 key
    try:
        pub = load_pem_public_key(pem_bytes)
        if not isinstance(pub, ec.EllipticCurvePublicKey) or not isinstance(pub.curve, ec.SECP256R1):
            return error_json(400, "bad_request", "Public key must be ECDSA P-256 (secp256r1).", request_id)
    except Exception as e:
        return error_json(400, "bad_request", f"Invalid PEM public key: {e}", request_id)

    session_id = uuid.uuid4().hex
    await store_session(session_id, pem_bytes, SESSION_TTL_SECONDS)

    exp = now_epoch() + SESSION_TTL_SECONDS
    return RegisterKeyResponse(
        session_id=session_id,
        expires_at=epoch_to_iso(exp),
        ttl_seconds=SESSION_TTL_SECONDS,
    )


@app.post("/verify-signature", response_model=VerifyResponse)
async def verify_signature(req: VerifySignatureRequest, request: Request):
    request_id = make_request_id()
    ip = client_ip(request)

    if not allow_rate(_bucket_verify, ip, RATE_LIMIT_VERIFY, WINDOW_SEC):
        return error_json(429, "rate_limited", "Too many requests to /verify-signature.", request_id)

    if len(req.message) > MAX_MESSAGE_LEN:
        return error_json(400, "bad_request", f"message too long (max {MAX_MESSAGE_LEN}).", request_id)

    if req.signature_format.lower() != "der":
        return error_json(400, "bad_request", "Only signature_format='der' is supported.", request_id)

    pem_bytes = await load_session_pem(req.session_id)
    if not pem_bytes:
        return error_json(401, "invalid_session", "Session not found or expired. Start a new session.", request_id)

    try:
        public_key = load_pem_public_key(pem_bytes)
    except Exception:
        return error_json(400, "bad_request", "Stored public key is invalid.", request_id)

    try:
        sig_bytes = base64.b64decode(req.signature, validate=True)
    except Exception:
        return error_json(400, "bad_request", "Invalid base64 in signature.", request_id)

    # P-256 ECDSA verify over message bytes, SHA-256 done internally
    msg_bytes = req.message.encode("utf-8")
    try:
        public_key.verify(sig_bytes, msg_bytes, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return error_json(401, "invalid_signature", "Signature verification failed.", request_id)
    except Exception as e:
        return error_json(400, "bad_request", f"Verification failed: {e}", request_id)

    return VerifyResponse(
        is_trusted=True,
        restricted_mode=False,
        reason="Signature valid (P-256) → Trusted session context",
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
    info = {
        "ok": True,
        "redis_mode": ("upstash" if USE_UPSTASH else "in_memory_best_effort"),
        "session_ttl_seconds": SESSION_TTL_SECONDS,
        "env": {
            "has_upstash_url": bool(UPSTASH_URL),
            "has_upstash_token": bool(UPSTASH_TOKEN),
        },
    }

    # Optional: probe upstash connectivity (only if env present)
    if USE_UPSTASH:
        try:
            key = "pfw:health_probe"
            url = f"{UPSTASH_URL}/set/{key}/ok"
            headers = {"Authorization": f"Bearer {UPSTASH_TOKEN}"}
            params = {"EX": "10"}
            async with httpx.AsyncClient(timeout=5.0) as client:
                r = await client.post(url, headers=headers, params=params)
                r.raise_for_status()
            info["upstash_probe"] = {"ok": True}
        except Exception as e:
            info["upstash_probe"] = {"ok": False, "error": str(e)}

    return info

