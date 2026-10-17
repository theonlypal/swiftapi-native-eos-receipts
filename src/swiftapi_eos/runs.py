import base64
import copy
import platform
import time
import uuid
from pathlib import Path

import torch

from .authority import assess, authenticate, consume, issue, load_private, sign
from .common import EOS, FALSE, QUESTION, REVISION, ROOT, TRUE, canonical, digest, filehash, read, require, save
from .decoder import boundary
from .source import inventory, load_gate, non_eos, stock_witness, tensor_bytes, verify_source, verify_witness

TESTS = ["T1", "T2", "T3", "T4", "T5", "T6", "T7a", "T7b", "T8", "T13"]


def request(condition, mode, nonce=None):
    m = inventory()
    return {"condition": condition, "question_sha256": digest(QUESTION.encode()), "scope": "pccg2.first-token",
            "revision": REVISION, "gate_sha256": m["files"]["gate/permission.safetensors"]["sha256"],
            "content_identity_sha256": m["files"]["evidence/base-identity.json"]["sha256"],
            "source_manifest_sha256": filehash(ROOT / "SOURCE_MANIFEST.json"),
            "mode": mode, "nonce": nonce or str(uuid.uuid4())}


def runtime():
    import importlib.metadata
    return {"python": platform.python_version(), "torch": str(torch.__version__), "machine": platform.machine(),
            "system": platform.system(), "device": "cpu", "dtype": "bfloat16", "gate_dtype": "float32",
            "dependencies": {n: importlib.metadata.version(n) for n in ("torch", "numpy", "safetensors", "cryptography")}}


def execute_replay(source, authority, output):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    key = load_private(authority)
    trusted = read(Path(authority) / "public.json")
    save(output / "public.json", trusted)
    witness = verify_witness(source)
    save(output / "upstream-witness.json", witness)
    module, gate = load_gate(source)
    stock = stock_witness(source)
    records = []
    first_auth = first_request = None
    revoked = read(Path(authority) / "revoked.json")
    for test in TESTS:
        condition = FALSE if test in ("T2", "T7b", "T8") else TRUE
        req = request(condition, "SAVED_LOGIT_REPLAY")
        now = time.time()
        authorization = issue(req, key, now=now - 1)
        if test == "T1":
            first_auth, first_request = authorization, req
        elif test == "T3":
            authorization["signature"] = base64.b64encode(bytes(64)).decode()
        elif test == "T4":
            authorization = issue(req, key, now=now - 600, ttl=1)
        elif test == "T5":
            authorization, req = copy.deepcopy(first_auth), copy.deepcopy(first_request)
        elif test == "T6":
            wrong = dict(req, scope="different.action")
            authorization = issue(wrong, key, now=now - 1)
        elif test == "T13":
            revoked = revoked + [authorization["payload"]["jti"]]
            save(Path(authority) / "revoked.json", revoked)
        original = test in ("T7a", "T7b", "T8")
        permission_sign = -1.0 if test in ("T7a", "T7b") else 1.0
        if original:
            authorization = None
            status = "ORIGINAL_ONLY"
        else:
            status = consume(authorization, req, trusted, authority, now, revoked)
        logits, state, intervention = boundary(module, gate, stock, condition, permission_sign, status)
        token = int(logits.float().argmax())
        require(token in (19, EOS), "Witness emitted unexpected token")
        # Only ONE token is selected in replay. Never append an uncomputed EOS.
        text = b"" if token == EOS else b"4"
        folder = output / test
        folder.mkdir()
        (folder / "stock.bf16.bin").write_bytes(tensor_bytes(stock))
        (folder / "selected.bf16.bin").write_bytes(tensor_bytes(logits))
        record = {"schema": "swiftapi-eos-execution/1", "test_id": test, "mode": "SAVED_LOGIT_REPLAY",
                  "request": req, "request_hash": digest(canonical(req)), "authorization": authorization,
                  "authorization_status": status, "revoked_jtis": revoked, "decision_time": now,
                  "execution_id": str(uuid.uuid4()), "permission_sign": permission_sign, "permission_state": state,
                  "intervention": intervention, "native_eos": EOS, "vocabulary_size": stock.numel(),
                  "stock_eos_logit": float(stock[EOS]), "intervened_eos_logit": float(logits[EOS]),
                  "stock_vector_sha256": digest(tensor_bytes(stock)), "first_vector_sha256": digest(tensor_bytes(logits)),
                  "non_eos_sha256": digest(tensor_bytes(non_eos(logits))), "selected_first_token": token,
                  "generated_token_ids": [token], "generation_complete": token == EOS, "max_new_tokens": 1,
                  "output_utf8_base64": base64.b64encode(text).decode(), "output_bytes": len(text),
                  "output_sha256": digest(text), "runtime": runtime(), "verification_status": "CAPTURED_PENDING_REPLAY"}
        save(folder / "receipt.json", sign(record, key))
        records.append(test)
    manifest = {"schema": "swiftapi-eos-run/1", "mode": "SAVED_LOGIT_REPLAY", "tests": records,
                "source_manifest_sha256": filehash(ROOT / "SOURCE_MANIFEST.json"),
                "files": {str(p.relative_to(output)): filehash(p) for p in sorted(output.rglob("*")) if p.is_file()}}
    save(output / "manifest.json", sign(manifest, key))
    return verify_run(source, output, trusted)


def tensor_from(path):
    raw = Path(path).read_bytes()
    require(len(raw) == 151936 * 2, "Invalid vector length")
    return torch.frombuffer(bytearray(raw), dtype=torch.bfloat16).clone()


def verify_run(source, output, trusted):
    output = Path(output)
    verify_source(source)
    m = authenticate(read(output / "manifest.json"), trusted)
    require(m["schema"] == "swiftapi-eos-run/1" and m["mode"] == "SAVED_LOGIT_REPLAY", "Unknown run schema/mode")
    require(m["tests"] == TESTS, "INCOMPLETE_RUN: frozen matrix differs")
    require(m["source_manifest_sha256"] == filehash(ROOT / "SOURCE_MANIFEST.json"), "Source manifest mismatch")
    required = {"public.json", "upstream-witness.json"} | {f"{t}/{f}" for t in TESTS for f in ("receipt.json", "stock.bf16.bin", "selected.bf16.bin")}
    require(set(m["files"]) == required, "INCOMPLETE_RUN: missing required record")
    for name, expected in m["files"].items():
        require((output / name).is_file() and filehash(output / name) == expected, "Run file integrity: " + name)
    require(read(output / "upstream-witness.json") == verify_witness(source), "Archived witness mismatch")
    module, gate = load_gate(source)
    stock = stock_witness(source)
    seen = set()
    verified = []
    expected_tokens = {t: (19 if t in ("T1", "T7b") else EOS) for t in TESTS}
    for t in TESTS:
        folder = output / t
        r = authenticate(read(folder / "receipt.json"), trusted)
        require(r["schema"] == "swiftapi-eos-execution/1" and r["test_id"] == t and r["mode"] == m["mode"], "Record schema")
        req = r["request"]
        condition = FALSE if t in ("T2", "T7b", "T8") else TRUE
        require(req == request(condition, m["mode"], req["nonce"]), "Model/gate/request identity mismatch")
        require(r["request_hash"] == digest(canonical(req)), "Request hash")
        original = t in ("T7a", "T7b", "T8")
        if original:
            require(r["authorization"] is None, "Original diagnostic conflated with authorization")
            status = "ORIGINAL_ONLY"
        else:
            status = assess(r["authorization"], req, trusted, r["decision_time"], seen, r["revoked_jtis"])
            if status in ("VALID_ALLOW", "VALID_DENY"):
                seen.add(r["authorization"]["payload"]["jti"])
        require(status == r["authorization_status"], "Authorization decision mismatch")
        expected_status = {"T1": "VALID_ALLOW", "T2": "VALID_DENY", "T3": "INVALID_SIGNATURE",
                           "T4": "EXPIRED_OR_FUTURE", "T5": "REPLAYED", "T6": "BINDING_MISMATCH", "T13": "REVOKED"}
        require(status == expected_status.get(t, "ORIGINAL_ONLY"), "Frozen test did not exercise intended failure")
        psign = -1.0 if t in ("T7a", "T7b") else 1.0
        require(r["permission_sign"] == psign, "Permission sign")
        computed, state, intervention = boundary(module, gate, stock, condition, psign, status)
        captured_stock = tensor_from(folder / "stock.bf16.bin")
        captured = tensor_from(folder / "selected.bf16.bin")
        require(tensor_bytes(captured_stock) == tensor_bytes(stock), "Stock vector is not upstream")
        require(tensor_bytes(captured) == tensor_bytes(computed), "Intervention replay failed")
        require(r["permission_state"] == state and r["intervention"] == intervention, "Mechanism mismatch")
        token = int(computed.float().argmax())
        require(token == expected_tokens[t] == r["selected_first_token"], "Forged selected token")
        require(r["generated_token_ids"] == [token] and r["generation_complete"] == (token == EOS), "Invented continuation")
        require(r["native_eos"] == EOS and r["vocabulary_size"] == len(stock) and r["max_new_tokens"] == 1, "Decode contract")
        require(r["stock_eos_logit"] == float(stock[EOS]) and r["intervened_eos_logit"] == float(computed[EOS]), "EOS scores")
        for key, value in (("stock_vector_sha256", stock), ("first_vector_sha256", computed), ("non_eos_sha256", non_eos(computed))):
            require(r[key] == digest(tensor_bytes(value)), "Vector hash")
        require(tensor_bytes(non_eos(computed)) == tensor_bytes(non_eos(stock)), "Non-EOS changed")
        text = b"" if token == EOS else b"4"
        require(base64.b64decode(r["output_utf8_base64"], validate=True) == text and r["output_bytes"] == len(text) and r["output_sha256"] == digest(text), "Output bytes mismatch")
        verified.append({"test": t, "selected": token, "authorization": status})
    return {"status": "PASS", "mode": m["mode"], "records_verified": len(verified), "results": verified,
            "trust": "Signatures bind records to the supplied public key, not physical inference or an external identity."}
