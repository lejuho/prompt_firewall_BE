from __future__ import annotations

import os
import json
import base64
import time
import uuid
from typing import Optional, Dict, Any

import httpx
from fastapi import FastAPI, Body, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.exceptions import InvalidSignature


# -----------------------------
# App
# -----------------------------
app = FastAPI(
    title="Prompt Firewall Backend (P-256 + Upstash + Replay Protection)",
    version="2.2.0",
    description="Ephemeral session keys + verifySignature (P-256) + sandbox for untrusted content.",
)

# -----------------------------
# Config
# -----------------------------
UPSTASH_URL = os.getenv("UPSTASH_REDIS_REST_URL", "").strip()
UPSTASH_TOKEN = os.getenv("UPSTASH_REDIS_REST_TOKEN", "").strip()
USE_UPSTASH = bool(UPSTASH_URL and UPSTASH_TOKEN)

# Session TTL (sliding) + absolute max TTL
SESSION_TTL_SECONDS = int(os.getenv("SESSION_TTL_SECONDS", "1800"))          # 30m sliding
ABSOLUTE_MAX_SECONDS = int(os.getenv("ABSOLUTE_MAX_SECONDS", "28800"))       # 8h hard cap

# Nonce replay window (store nonce keys with TTL)
NONCE_TTL_SECONDS = int(os.getenv("NONCE_TTL_SECONDS", "600"))               # 10m

# Signature freshness window (optional)
MAX_SKEW_SECONDS = int(os.getenv("MAX_SKEW_SECONDS", "300"))                 # 5m: reject too old/far-future ts

# Body limits
MAX_BODY_BYTES = int(os.getenv("MAX_BODY_BYTES", str(64 * 1024)))

print(
    "BOOT:",
    "use_upstash=", USE_UPSTASH,
    "has_url=", bool(UPSTASH_URL),
    "has_token=", bool(UPSTASH_TOKEN),
    "session_ttl=", SESSION_TTL_SECONDS,
    "abs_max=", ABSOLUTE_MAX_SECONDS,
    "nonce_ttl=", NONCE_TTL_SECONDS,
)

# -----------------------------
# Helpers
# -----------------------------
def now_s() -> int:
    return int(time.time())

def make_request_id() -> str:
    return uuid.uuid4().hex

def error_json(status_code: int, error: str, message: str, request_id: str) -> JSONResponse:
    return JSONResponse(status_code=status_code, content={"error": error, "message": message, "request_id": request_id})

def client_ip(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"

def b64decode_strict(s: str) -> bytes:
    return base64.b64decode(s, validate=True)

def parse_iso8601_or_epoch(ts: str) -> Optional[int]:
    """
    Accept either:
    - ISO8601 like 2026-02-18T10:27:29.567Z
    - or epoch seconds as string/int
    Return epoch seconds int if parseable.
    """
    if ts is None:
        return None
    ts = str(ts).strip()
    if not ts:
        return None
    # epoch seconds
    if ts.isdigit():
        try:
            return int(ts)
        except Exception:
            return None
    # ISO8601 Z
    try:
        # very small parser to avoid extra deps
        # expects ...Z; strip millis if present
        if ts.endswith("Z"):
            ts2 = ts[:-1]
            # split date/time
            # 2026-02-18T10:27:29.567
            if "T" not in ts2:
                return None
            date_part, time_part = ts2.split("T", 1)
            y, m, d = [int(x) for x in date_part.split("-")]
            # remove millis
            if "." in time_part:
                time_part = time_part.split(".", 1)[0]
            hh, mm, ss = [int(x) for x in time_part.split(":")]
            # convert to epoch using time module (UTC)
            import calendar
            return int(calendar.timegm((y, m, d, hh, mm, ss)))
        return None
    except Exception:
        return None

def build_canonical_v2(session_id: str, ts: str, nonce: str, message: str) -> bytes:
    """
    V2 signing format:
      session_id: <id>
      ts: <ts>
      nonce: <nonce>
      message: <message>
    NOTE: exact bytes must match extension.
    """
    # Keep it dead simple and stable
    canon = (
        f"session_id:{session_id}\n"
        f"ts:{ts}\n"
        f"nonce:{nonce}\n"
        f"message:{message}"
    )
    return canon.encode("utf-8")

# -----------------------------
# Upstash REST helpers
# -----------------------------
async def upstash_request(method: str, path: str, *, params: Optional[dict] = None) -> Any:
    if not USE_UPSTASH:
        raise RuntimeError("Upstash not configured")
    headers = {"Authorization": f"Bearer {UPSTASH_TOKEN}"}
    url = f"{UPSTASH_URL}{path}"
    async with httpx.AsyncClient(timeout=5.0) as client:
        r = await client.request(method, url, headers=headers, params=params)
        r.raise_for_status()
        return r.json()

async def upstash_get(key: str) -> Optional[str]:
    data = await upstash_request("GET", f"/get/{key}")
    return data.get("result")

async def upstash_set(key: str, value: str, ex: int, nx: bool = False) -> bool:
    params = {"EX": str(ex)}
    if nx:
        params["NX"] = "1"
    data = await upstash_request("POST", f"/set/{key}/{value}", params=params)
    # result is usually "OK" or None
    return data.get("result") == "OK"

async def upstash_del(key: str) -> int:
    data = await upstash_request("POST", f"/del/{key}")
    res = data.get("result")
    return int(res) if res is not None else 0

# -----------------------------
# Models
# -----------------------------
class ErrorResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    error: str
    message: str
    request_id: Optional[str] = None

class RegisterKeyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    public_key_pem: str = Field(..., description="PEM-encoded SPKI public key (P-256). Can include literal newlines or \\n.")

class RegisterKeyResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    session_id: str
    expires_at: str
    ttl_seconds: int

class VerifySignatureRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    session_id: str
    message: str
    signature: str  # base64 DER
    signature_format: str = "der"
    # V2 fields (required for replay protection)
    ts: Optional[str] = None
    nonce: Optional[str] = None
    version: str = "v2"  # default v2

class VerifyResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    is_trusted: bool
    restricted_mode: bool
    reason: str

class SandboxRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    content: str

class SandboxResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    safe_to_execute: bool = False
    summary: str
    injection_detected: bool = False
    reason: str = ""

# -----------------------------
# Minimal body size guard (simple)
# -----------------------------
@app.middleware("http")
async def body_limit_mw(request: Request, call_next):
    rid = make_request_id()
    cl = request.headers.get("content-length")
    if cl and cl.isdigit() and int(cl) > MAX_BODY_BYTES:
        return error_json(413, "payload_too_large", "Request body too large.", rid)

    body = await request.body()
    if len(body) > MAX_BODY_BYTES:
        return error_json(413, "payload_too_large", "Request body too large.", rid)

    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}
    request._receive = receive  # noqa
    return await call_next(request)

# -----------------------------
# Storage keys
# -----------------------------
def k_session_pub(session_id: str) -> str:
    return f"pfw:session:{session_id}:pub"

def k_session_meta(session_id: str) -> str:
    return f"pfw:session:{session_id}:meta"

def k_nonce(session_id: str, nonce: str) -> str:
    return f"pfw:nonce:{session_id}:{nonce}"

# -----------------------------
# Routes
# -----------------------------
@app.post("/register-key", response_model=RegisterKeyResponse)
async def register_key(req: RegisterKeyRequest, request: Request):
    rid = make_request_id()

    pem = (req.public_key_pem or "").strip()
    if not pem:
        return error_json(400, "bad_request", "public_key_pem is required.", rid)

    # Allow \n in env-like string
    pem_fixed = pem.replace("\\n", "\n").encode("utf-8")

    # Validate key loads and is P-256 EC
    try:
        pub = load_pem_public_key(pem_fixed)
        if not isinstance(pub, ec.EllipticCurvePublicKey):
            return error_json(400, "bad_request", "Public key must be EC (P-256).", rid)
        if pub.curve.name not in ("secp256r1", "prime256v1"):
            return error_json(400, "bad_request", f"Unsupported curve: {pub.curve.name}. Expected P-256.", rid)
    except Exception as e:
        return error_json(400, "bad_request", f"Invalid PEM public key: {e}", rid)

    if not USE_UPSTASH:
        return error_json(503, "not_configured", "Upstash is not configured.", rid)

    session_id = uuid.uuid4().hex
    created_at = now_s()

    # Store public key pem + meta
    meta = {"created_at": created_at}

    # session key TTL is sliding; start with SESSION_TTL, but absolute max is enforced by meta key
    ttl = min(SESSION_TTL_SECONDS, ABSOLUTE_MAX_SECONDS)

    ok1 = await upstash_set(k_session_pub(session_id), base64.b64encode(pem_fixed).decode("ascii"), ex=ttl, nx=True)
    ok2 = await upstash_set(k_session_meta(session_id), json.dumps(meta), ex=ABSOLUTE_MAX_SECONDS, nx=True)

    if not (ok1 and ok2):
        # Best-effort cleanup
        await upstash_del(k_session_pub(session_id))
        await upstash_del(k_session_meta(session_id))
        return error_json(500, "server_error", "Failed to create session.", rid)

    expires_at_epoch = created_at + ttl
    # just return epoch as string to keep simple; your OpenAPI can describe it
    return RegisterKeyResponse(
        session_id=session_id,
        expires_at=str(expires_at_epoch),
        ttl_seconds=ttl,
    )

@app.post("/verify-signature", response_model=VerifyResponse)
async def verify_signature(req: VerifySignatureRequest, request: Request):
    rid = make_request_id()

    if req.signature_format != "der":
        return error_json(400, "bad_request", "Only signature_format='der' is supported.", rid)

    if not USE_UPSTASH:
        return error_json(503, "not_configured", "Upstash is not configured.", rid)

    # Fetch pubkey + meta
    pub_b64 = await upstash_get(k_session_pub(req.session_id))
    meta_json = await upstash_get(k_session_meta(req.session_id))
    if not pub_b64 or not meta_json:
        return error_json(401, "invalid_session", "Session not found or expired.", rid)

    try:
        meta = json.loads(meta_json)
        created_at = int(meta.get("created_at", 0))
    except Exception:
        return error_json(500, "server_error", "Corrupt session metadata.", rid)

    # Enforce absolute max (even if pub key TTL got extended incorrectly)
    now = now_s()
    if created_at <= 0 or now > (created_at + ABSOLUTE_MAX_SECONDS):
        # expire keys
        await upstash_del(k_session_pub(req.session_id))
        await upstash_del(k_session_meta(req.session_id))
        return error_json(401, "invalid_session", "Session expired (absolute max).", rid)

    # V2 required fields (for replay protection)
    if (req.version or "v2") != "v2":
        return error_json(400, "bad_request", "Only version='v2' is supported on this server.", rid)

    if not req.ts or not req.nonce:
        return error_json(400, "bad_request", "ts and nonce are required for v2 verification.", rid)

    # Freshness check
    ts_epoch = parse_iso8601_or_epoch(req.ts)
    if ts_epoch is None:
        return error_json(400, "bad_request", "Invalid ts format. Use ISO8601 ...Z or epoch seconds.", rid)

    if abs(now - ts_epoch) > MAX_SKEW_SECONDS:
        return error_json(401, "stale_request", "Timestamp outside allowed skew window.", rid)

    # Replay protection: nonce must be unique within NONCE_TTL_SECONDS
    nonce_key = k_nonce(req.session_id, req.nonce)
    nonce_ok = await upstash_set(nonce_key, "1", ex=NONCE_TTL_SECONDS, nx=True)
    if not nonce_ok:
        return error_json(401, "replay_detected", "Nonce already used (replay detected).", rid)

    # Load pubkey
    try:
        pem_fixed = base64.b64decode(pub_b64)
        pub = load_pem_public_key(pem_fixed)
    except Exception as e:
        return error_json(500, "server_error", f"Failed to load stored public key: {e}", rid)

    # Decode signature
    try:
        sig_bytes = b64decode_strict(req.signature)
    except Exception:
        return error_json(400, "bad_request", "Invalid base64 in signature.", rid)

    # Verify: signature over canonical v2 bytes (includes session_id, ts, nonce, message)
    to_verify = build_canonical_v2(req.session_id, req.ts, req.nonce, req.message)
    digest_ctx = hashes.Hash(hashes.SHA256())
    digest_ctx.update(to_verify)
    digest = digest_ctx.finalize()

    try:
        pub.verify(sig_bytes, digest, ec.ECDSA(Prehashed(hashes.SHA256())))
    except InvalidSignature:
        return error_json(401, "invalid_signature", "Signature verification failed.", rid)
    except Exception as e:
        return error_json(400, "bad_request", f"Verification failed: {e}", rid)

    # Sliding TTL refresh (bounded by absolute max)
    remaining_abs = (created_at + ABSOLUTE_MAX_SECONDS) - now
    new_ttl = min(SESSION_TTL_SECONDS, max(1, remaining_abs))
    # Refresh session public key TTL only; meta keeps absolute max TTL
    # Keep same value
    await upstash_set(k_session_pub(req.session_id), pub_b64, ex=new_ttl, nx=False)

    return VerifyResponse(
        is_trusted=True,
        restricted_mode=False,
        reason="Signature valid (P-256 v2) → Trusted session context",
    )

@app.post("/sandbox-untrusted", response_model=SandboxResponse)
async def sandbox_untrusted(req: SandboxRequest, request: Request):
    # MVP: simple pattern-based classifier; you can replace with LLM later.
    content = (req.content or "").strip()
    if not content:
        return JSONResponse(status_code=400, content={"error": "bad_request", "message": "content must be non-empty.", "request_id": make_request_id()})

    lowered = content.lower()
    dangerous_patterns = [
        "ignore previous instructions",
        "system prompt",
        "forget all rules",
        "delete everything",
        "you are an ai",
        "exfiltrate",
        "api key",
        "password",
        "run this command",
    ]
    inj = any(p in lowered for p in dangerous_patterns)

    snippet = content[:500] + ("..." if len(content) > 500 else "")
    summary = f"[SANDBOX SUMMARY] {snippet}"

    return SandboxResponse(
        safe_to_execute=False,
        summary=summary,
        injection_detected=inj,
        reason="Untrusted content processed in sandbox. Execution blocked."
               + (" Potential injection detected!" if inj else "")
    )

@app.get("/health")
async def health():
    info: Dict[str, Any] = {
        "ok": True,
        "redis_mode": ("upstash" if USE_UPSTASH else "in_memory_best_effort"),
        "session_ttl_seconds": SESSION_TTL_SECONDS,
        "absolute_max_seconds": ABSOLUTE_MAX_SECONDS,
        "nonce_ttl_seconds": NONCE_TTL_SECONDS,
        "max_skew_seconds": MAX_SKEW_SECONDS,
        "env": {
            "has_upstash_url": bool(UPSTASH_URL),
            "has_upstash_token": bool(UPSTASH_TOKEN),
        },
    }

    if USE_UPSTASH:
        try:
            key = "pfw:health_probe"
            ok = await upstash_set(key, "ok", ex=10, nx=False)
            info["upstash_probe"] = {"ok": bool(ok)}
        except Exception as e:
            info["upstash_probe"] = {"ok": False, "error": str(e)}
    return info
