from __future__ import annotations

import os
import urllib.parse
import json
import base64
import time
import uuid
from typing import Optional, Dict, Any, List

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.exceptions import InvalidSignature


app = FastAPI(
    title="Prompt Firewall Backend (P-256 + Upstash + Replay Protection)",
    version="2.3.0",
    description="Ephemeral session keys + verifySignature v2 (P-256) + sandbox for untrusted content (2-layer).",
)

# -----------------------------
# Config
# -----------------------------
UPSTASH_URL = os.getenv("UPSTASH_REDIS_REST_URL", "").strip()
UPSTASH_TOKEN = os.getenv("UPSTASH_REDIS_REST_TOKEN", "").strip()
USE_UPSTASH = bool(UPSTASH_URL and UPSTASH_TOKEN)

SESSION_TTL_SECONDS = int(os.getenv("SESSION_TTL_SECONDS", "1800"))     # sliding TTL (e.g., 30m)
ABSOLUTE_MAX_SECONDS = int(os.getenv("ABSOLUTE_MAX_SECONDS", "28800")) # absolute max (e.g., 8h)
NONCE_TTL_SECONDS = int(os.getenv("NONCE_TTL_SECONDS", "600"))         # replay window (e.g., 10m)
MAX_SKEW_SECONDS = int(os.getenv("MAX_SKEW_SECONDS", "300"))           # ts freshness (e.g., 5m)
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

def b64decode_strict(s: str) -> bytes:
    return base64.b64decode(s, validate=True)

def parse_ts(ts: str) -> Optional[int]:
    """
    Accept ISO8601 ...Z or epoch seconds string.
    Return epoch seconds.
    """
    if ts is None:
        return None
    ts = str(ts).strip()
    if not ts:
        return None
    if ts.isdigit():
        try:
            return int(ts)
        except Exception:
            return None
    try:
        # minimal ISO8601 Z parser
        if ts.endswith("Z") and "T" in ts:
            import calendar
            ts2 = ts[:-1]
            date_part, time_part = ts2.split("T", 1)
            if "." in time_part:
                time_part = time_part.split(".", 1)[0]
            y, m, d = [int(x) for x in date_part.split("-")]
            hh, mm, ss = [int(x) for x in time_part.split(":")]
            return int(calendar.timegm((y, m, d, hh, mm, ss)))
        return None
    except Exception:
        return None

def build_canonical_v2(session_id: str, ts: str, nonce: str, message: str) -> bytes:
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
def _enc(seg: str) -> str:
    # encode everything (including ":" "/" "+" "=")
    return urllib.parse.quote(seg, safe="")

async def upstash_request(method: str, path: str, *, params: Optional[dict] = None) -> Any:
    if not USE_UPSTASH:
        raise RuntimeError("Upstash not configured")
    headers = {"Authorization": f"Bearer {UPSTASH_TOKEN}"}
    url = f"{UPSTASH_URL}{path}"
    async with httpx.AsyncClient(timeout=5.0) as client:
        r = await client.request(method, url, headers=headers, params=params)
        # 디버깅 쉽게: Upstash가 4xx면 body까지 포함해서 에러로 올림
        if r.status_code >= 400:
            raise RuntimeError(f"Upstash HTTP {r.status_code}: {r.text[:500]}")
        return r.json()

async def upstash_get(key: str) -> Optional[str]:
    ek = _enc(key)
    data = await upstash_request("GET", f"/get/{ek}")
    return data.get("result")

async def upstash_set(key: str, value: str, ex: int, nx: bool = False) -> bool:
    ek = _enc(key)
    ev = _enc(value)  # ★ 핵심: value도 인코딩
    params = {"EX": str(ex)}
    if nx:
        params["NX"] = "1"
    data = await upstash_request("POST", f"/set/{ek}/{ev}", params=params)
    return data.get("result") == "OK"

async def upstash_del(key: str) -> int:
    ek = _enc(key)
    data = await upstash_request("POST", f"/del/{ek}")
    res = data.get("result")
    return int(res) if res is not None else 0
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
# Models
# -----------------------------
class ErrorResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    error: str
    message: str
    request_id: Optional[str] = None

class RegisterKeyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    public_key_pem: str = Field(..., description="PEM-encoded SPKI public key (P-256). Accepts literal newlines or \\n.")

class RegisterKeyResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    session_id: str
    expires_at: str
    ttl_seconds: int

class VerifySignatureRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    session_id: str
    message: str
    signature: str                  # base64 DER
    ts: str
    nonce: str
    version: str = "v2"
    signature_format: str = "der"

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
    injection_detected: bool
    risk_level: str
    strong_hits: List[str] = []
    soft_hits: List[str] = []
    reason: str

# -----------------------------
# Middleware: body size
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
# Routes
# -----------------------------
@app.post("/register-key", response_model=RegisterKeyResponse)
async def register_key(req: RegisterKeyRequest, request: Request):
    rid = make_request_id()

    if not USE_UPSTASH:
        return error_json(503, "not_configured", "Upstash is not configured.", rid)

    pem = (req.public_key_pem or "").strip()
    if not pem:
        return error_json(400, "bad_request", "public_key_pem is required.", rid)

    pem_fixed = pem.replace("\\n", "\n").encode("utf-8")

    # validate EC P-256
    try:
        pub = load_pem_public_key(pem_fixed)
        if not isinstance(pub, ec.EllipticCurvePublicKey):
            return error_json(400, "bad_request", "Public key must be EC (P-256).", rid)
        if pub.curve.name not in ("secp256r1", "prime256v1"):
            return error_json(400, "bad_request", f"Unsupported curve: {pub.curve.name}. Expected P-256.", rid)
    except Exception as e:
        return error_json(400, "bad_request", f"Invalid PEM public key: {e}", rid)

    session_id = uuid.uuid4().hex
    created_at = now_s()
    meta = {"created_at": created_at}

    ttl = min(SESSION_TTL_SECONDS, ABSOLUTE_MAX_SECONDS)
    pub_value = base64.urlsafe_b64encode(pem_fixed).decode("ascii").rstrip("=")

    ok1 = await upstash_set(k_session_pub(session_id), pub_value, ex=ttl, nx=True)
    ok2 = await upstash_set(k_session_meta(session_id), json.dumps(meta), ex=ABSOLUTE_MAX_SECONDS, nx=True)

    if not (ok1 and ok2):
        await upstash_del(k_session_pub(session_id))
        await upstash_del(k_session_meta(session_id))
        return error_json(500, "server_error", "Failed to create session.", rid)

    return RegisterKeyResponse(
        session_id=session_id,
        expires_at=str(created_at + ttl),
        ttl_seconds=ttl,
    )

@app.post("/verify-signature", response_model=VerifyResponse)
async def verify_signature(req: VerifySignatureRequest, request: Request):
    rid = make_request_id()

    if not USE_UPSTASH:
        return error_json(503, "not_configured", "Upstash is not configured.", rid)

    if req.version != "v2":
        return error_json(400, "bad_request", "Only version='v2' is supported.", rid)

    if req.signature_format != "der":
        return error_json(400, "bad_request", "Only signature_format='der' is supported.", rid)

    pub_b64 = await upstash_get(k_session_pub(req.session_id))
    meta_json = await upstash_get(k_session_meta(req.session_id))
    if not pub_b64 or not meta_json:
        return error_json(401, "invalid_session", "Session not found or expired.", rid)

    try:
        meta = json.loads(meta_json)
        created_at = int(meta.get("created_at", 0))
    except Exception:
        return error_json(500, "server_error", "Corrupt session metadata.", rid)

    now = now_s()
    if created_at <= 0 or now > (created_at + ABSOLUTE_MAX_SECONDS):
        await upstash_del(k_session_pub(req.session_id))
        await upstash_del(k_session_meta(req.session_id))
        return error_json(401, "invalid_session", "Session expired (absolute max).", rid)

    ts_epoch = parse_ts(req.ts)
    if ts_epoch is None:
        return error_json(400, "bad_request", "Invalid ts format. Use ISO8601 ...Z or epoch seconds.", rid)

    if abs(now - ts_epoch) > MAX_SKEW_SECONDS:
        return error_json(401, "stale_request", "Timestamp outside allowed skew window.", rid)

    # replay protection: nonce must be new
    nonce_key = k_nonce(req.session_id, req.nonce)
    nonce_ok = await upstash_set(nonce_key, "1", ex=NONCE_TTL_SECONDS, nx=True)
    if not nonce_ok:
        return error_json(401, "replay_detected", "Nonce already used (replay detected).", rid)

    # load pubkey
    try:
        pad = "=" * ((4 - (len(pub_b64) % 4)) % 4)
        pem_fixed = base64.urlsafe_b64decode(pub_b64 + pad)
        pub = load_pem_public_key(pem_fixed)
    except Exception as e:
        return error_json(500, "server_error", f"Failed to load stored public key: {e}", rid)

    # signature decode
    try:
        sig_bytes = b64decode_strict(req.signature)
    except Exception:
        return error_json(400, "bad_request", "Invalid base64 in signature.", rid)

    # verify signature over canonical v2 bytes (session_id, ts, nonce, message)
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

    # sliding TTL refresh (bounded by absolute max)
    remaining_abs = (created_at + ABSOLUTE_MAX_SECONDS) - now
    new_ttl = min(SESSION_TTL_SECONDS, max(1, remaining_abs))
    await upstash_set(k_session_pub(req.session_id), pub_b64, ex=new_ttl, nx=False)

    return VerifyResponse(
        is_trusted=True,
        restricted_mode=False,
        reason="Signature valid (P-256 v2) → Trusted session context",
    )

# -----------------------------
# Sandbox (2-layer): Strong vs Soft
# -----------------------------
STRONG_PATTERNS = [
    # instruction override / jailbreak / policy
    "ignore previous", "disregard above", "override instructions", "bypass",
    "jailbreak", "dan", "do anything now",
    "developer message", "system message", "system prompt", "system instructions",
    "reveal hidden", "show me your prompt", "print the system prompt", "policy",

    # explicit tool calling / execution
    "tool call", "function call", "call the tool", "use the tool",
    "enable browsing", "open the link",
    "run code", "execute", "shell", "terminal",
    "powershell", "cmd.exe", "bash", "zsh",
    "curl ", "wget ", "invoke-webrequest",
    "python -c", "node -e",
    "chmod +x", "sudo",
    "reverse shell", "payload", "exploit", "sqlmap", "mimikatz",
]

SOFT_PATTERNS = [
    # data/credential context (can be benign in discussion)
    "api key", "access token", "refresh token", "bearer ", "secret",
    "private key", "seed phrase", "mnemonic", "recovery phrase",
    "2fa", "otp", "verification code", "password reset",
    "credit card", "billing", "ssn", "passport",

    # exfil channels / persistence hints (sometimes benign)
    "webhook", "pastebin", "requestbin", "ngrok", "tunnel",
    "discord webhook", "slack webhook", "telegram bot",
    "export all", "dump", "leak", "steal",
    "cron", "task scheduler", "systemd", "autorun", "startup", "registry",
    "set environment variable", "modify config", "write a file", "install this",

    # obfuscation/encoding (often benign, but suspicious in untrusted blobs)
    "base64", "rot13", "hex", "decode this", "obfuscate",
    "atob(", "eval(", "powershell -enc",
]

def _hits(text: str, patterns: List[str]) -> List[str]:
    t = text.lower()
    hits = []
    for p in patterns:
        if p.lower() in t:
            hits.append(p)
    # dedupe preserving order
    seen = set()
    out = []
    for h in hits:
        if h not in seen:
            out.append(h)
            seen.add(h)
    return out

def _risk_level(strong_hits: List[str], soft_hits: List[str]) -> str:
    if strong_hits:
        return "high"
    if len(soft_hits) >= 3:
        return "medium"
    if len(soft_hits) >= 1:
        return "low"
    return "none"

@app.post("/sandbox-untrusted", response_model=SandboxResponse)
async def sandbox_untrusted(req: SandboxRequest, request: Request):
    rid = make_request_id()
    content = (req.content or "").strip()
    if not content:
        return error_json(400, "bad_request", "content must be a non-empty string.", rid)

    strong_hits = _hits(content, STRONG_PATTERNS)
    soft_hits = _hits(content, SOFT_PATTERNS)

    risk = _risk_level(strong_hits, soft_hits)
    injection_detected = bool(strong_hits)  # **Two-layer rule**: only strong triggers injection_detected

    snippet = content[:500] + ("..." if len(content) > 500 else "")
    summary = f"[SANDBOX SUMMARY] {snippet}"

    reason_parts = ["Untrusted content processed in sandbox. Execution blocked."]
    if injection_detected:
        reason_parts.append("Potential prompt injection detected (strong indicators).")
    elif soft_hits:
        reason_parts.append("Suspicious indicators found (soft signals).")

    return SandboxResponse(
        safe_to_execute=False,
        summary=summary,
        injection_detected=injection_detected,
        risk_level=risk,
        strong_hits=strong_hits,
        soft_hits=soft_hits,
        reason=" ".join(reason_parts),
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
            ok = await upstash_set("pfw:health_probe", "ok", ex=10, nx=False)
            info["upstash_probe"] = {"ok": bool(ok)}
        except Exception as e:
            info["upstash_probe"] = {"ok": False, "error": str(e)}

    return info
