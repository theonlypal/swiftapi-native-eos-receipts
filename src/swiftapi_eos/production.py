"""Optional SwiftAPI 1.3.1 adapter. Not exercised by the local benchmark.

No credentials are discovered automatically. A production attestation cannot be
converted to a LOCAL_TEST_AUTHORITY signature or silently accepted offline when
its online revocation status is unavailable.
"""
import hashlib
import json

from .authority import evaluate
from .common import require


def verify_production(client, attestation, request, seen_jtis):
    from swiftapi.verifier import verify_signature
    verify_signature(attestation)
    fingerprint = hashlib.sha256(json.dumps(request, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:32]
    require(attestation.get("action_type") == request["scope"], "Wrong production action")
    require(attestation.get("action_fingerprint") == fingerprint, "Wrong production request binding")
    require(type(attestation.get("approved")) is bool, "Missing signed verdict")
    jti = attestation["jti"]
    require(jti not in seen_jtis, "Replayed production authorization")
    # SDK raises on unavailable or malformed revocation status. Never fail open.
    require(client.check_revocation(jti) is False, "Revoked production authorization")
    require(attestation["approved"] == evaluate(request["condition"]), "Authority verdict conflicts with prerequisite")
    seen_jtis.add(jti)
    return "VALID_ALLOW" if attestation["approved"] else "VALID_DENY"


def request_production(client, request, seen_jtis):
    """Client must be explicitly configured by the caller with user credentials.

Returns evidence and status; caller must pass status to decoder.boundary before
selection. The default CLI deliberately does not use this unqualified adapter.
"""
    result = client.attest(action_type=request["scope"], action_data=request)
    attestation = result.get("execution_attestation", result)
    return attestation, verify_production(client, attestation, request, seen_jtis)
