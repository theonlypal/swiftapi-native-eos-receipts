import base64
import os
import re
import sqlite3
import time
import uuid
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .common import canonical, digest, read, require, save

ISSUER = "LOCAL_TEST_AUTHORITY"


def evaluate(condition):
    m = re.fullmatch(r"EQ\(([1-9][0-9]{5}),([1-9][0-9]{5})\)", condition)
    require(m is not None, "Invalid EQ condition")
    return m[1] == m[2]


def public_info(private):
    raw = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {"issuer": ISSUER, "key_id": digest(raw), "public_key": base64.b64encode(raw).decode()}


def init_authority(folder):
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=False, mode=0o700)
    key = Ed25519PrivateKey.generate()
    raw = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    fd = os.open(folder / "private.key", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(raw)
    save(folder / "public.json", public_info(key))
    save(folder / "revoked.json", [])
    return public_info(key)


def load_private(folder):
    return Ed25519PrivateKey.from_private_bytes((Path(folder) / "private.key").read_bytes())


def sign(payload, key):
    info = public_info(key)
    return {"payload": payload, "issuer": info["issuer"], "key_id": info["key_id"],
            "signature": base64.b64encode(key.sign(canonical(payload))).decode()}


def authenticate(envelope, trusted):
    require(envelope["issuer"] == trusted["issuer"] == ISSUER, "Untrusted issuer")
    raw = base64.b64decode(trusted["public_key"], validate=True)
    require(digest(raw) == trusted["key_id"] == envelope["key_id"], "Untrusted key")
    Ed25519PublicKey.from_public_bytes(raw).verify(base64.b64decode(envelope["signature"], validate=True), canonical(envelope["payload"]))
    return envelope["payload"]


def issue(request, key, now=None, ttl=300):
    now = time.time() if now is None else now
    return sign({"schema": "swiftapi-eos-authorization/1", "request": request,
                 "request_hash": digest(canonical(request)), "approved": evaluate(request["condition"]),
                 "jti": str(uuid.uuid4()), "issued_at": now, "expires_at": now + ttl}, key)


def assess(envelope, request, trusted, now, seen, revoked):
    try:
        p = authenticate(envelope, trusted)
    except Exception:
        return "INVALID_SIGNATURE"
    if p.get("schema") != "swiftapi-eos-authorization/1":
        return "INVALID_SCHEMA"
    if p.get("request") != request or p.get("request_hash") != digest(canonical(request)):
        return "BINDING_MISMATCH"
    if not isinstance(p.get("jti"), str) or not p["jti"]:
        return "INVALID_JTI"
    try:
        if not (p["issued_at"] <= now < p["expires_at"]):
            return "EXPIRED_OR_FUTURE"
    except (KeyError, TypeError):
        return "INVALID_TIME"
    if p["jti"] in revoked:
        return "REVOKED"
    if p["jti"] in seen:
        return "REPLAYED"
    if type(p.get("approved")) is not bool or p["approved"] != evaluate(request["condition"]):
        return "VERDICT_MISMATCH"
    return "VALID_ALLOW" if p["approved"] else "VALID_DENY"


def consume(envelope, request, trusted, folder, now, revoked):
    # Atomic check-and-consume, before selection. Concurrent consumers cannot reuse JTI.
    with sqlite3.connect(Path(folder) / "used.sqlite", timeout=30) as db:
        db.execute("CREATE TABLE IF NOT EXISTS used (jti TEXT PRIMARY KEY)")
        db.execute("BEGIN IMMEDIATE")
        seen = {r[0] for r in db.execute("SELECT jti FROM used")}
        verdict = assess(envelope, request, trusted, now, seen, revoked)
        if verdict in ("VALID_ALLOW", "VALID_DENY"):
            db.execute("INSERT INTO used VALUES (?)", (envelope["payload"]["jti"],))
        db.commit()
    return verdict
