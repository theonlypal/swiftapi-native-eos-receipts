"""Optional local BF16 decoding. No downloads, quantization, or training."""
import base64
import copy
import time
import uuid
from pathlib import Path

import torch

from .authority import assess, authenticate, consume, issue, load_private, sign
from .common import EOS, FALSE, QUESTION, ROOT, TRUE, canonical, digest, filehash, read, require, save
from .decoder import boundary
from .runs import TESTS, request, runtime, tensor_from
from .source import inventory, load_gate, non_eos, tensor_bytes, verify_source


def check_content(content):
    m = inventory()
    required = {n: h for n, h in m["all_upstream_files"].items() if n.startswith("content/")}
    for name, expected in required.items():
        require(filehash(Path(content) / name.removeprefix("content/")) == expected, "Content identity mismatch: " + name)
    return required


def infer(source, authority, output, content, device):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    verify_source(source)
    # Resource check is explicit and preserved, never silently substituted with replay.
    try:
        import psutil
        weights = sum(p.stat().st_size for p in Path(content).glob("model-*.safetensors"))
        available = psutil.virtual_memory().available
        required = int(weights * 1.5 + 2 * 1024**3)
        require(weights > 0, "No local full model shards")
        if available < required:
            result = {"status": "UNAVAILABLE_HARDWARE", "reason": "Conservative BF16 memory preflight",
                      "available_bytes": available, "required_bytes": required, "local_weight_bytes": weights,
                      "inference_executed": False, "quantization": False, "downloaded": False}
            save(output / "status.json", result)
            return result
        from transformers import AutoModelForCausalLM, AutoTokenizer
    except ImportError as exc:
        result = {"status": "UNAVAILABLE_DEPENDENCY", "reason": str(exc), "inference_executed": False}
        save(output / "status.json", result)
        return result
    identities = check_content(content)
    device = ("mps" if torch.backends.mps.is_available() else "cpu") if device == "auto" else device
    try:
        if device == "mps" and not torch.backends.mps.is_available():
            raise RuntimeError("MPS unavailable; explicitly choose --device cpu")
        torch.zeros(1, dtype=torch.bfloat16, device=device)  # No dtype fallback.
        model = AutoModelForCausalLM.from_pretrained(content, local_files_only=True, torch_dtype=torch.bfloat16,
                                                   attn_implementation="sdpa").eval().requires_grad_(False).to(device)
    except (RuntimeError, MemoryError, TypeError) as exc:
        result = {"status": "UNAVAILABLE_HARDWARE", "reason": str(exc), "inference_executed": False, "device": device}
        save(output / "status.json", result)
        return result
    tokenizer = AutoTokenizer.from_pretrained(content, local_files_only=True)
    require(tokenizer.eos_token_id == EOS and tokenizer.encode("4", add_special_tokens=False) == [19], "Tokenizer contract")
    module, gate = load_gate(source)
    gate.to(device)
    key = load_private(authority)
    trusted = read(Path(authority) / "public.json")
    save(output / "public.json", trusted)
    system = read(Path(source) / "config.json")["system"]
    from core import prompt
    rendered = prompt(system, QUESTION)
    prompt_ids = tokenizer.encode(rendered, add_special_tokens=False)
    revoked = read(Path(authority) / "revoked.json")
    first = None
    for test in TESTS:
        condition = FALSE if test in ("T2", "T7b", "T8") else TRUE
        req = request(condition, "FRESH_LOCAL_INFERENCE")
        now = time.time()
        authorization = issue(req, key, now=now - 1)
        if test == "T1":
            first = (copy.deepcopy(req), copy.deepcopy(authorization))
        elif test == "T3":
            authorization["signature"] = base64.b64encode(bytes(64)).decode()
        elif test == "T4":
            authorization = issue(req, key, now=now - 600, ttl=1)
        elif test == "T5":
            req, authorization = copy.deepcopy(first)
        elif test == "T6":
            authorization = issue(dict(req, scope="different.action"), key, now=now - 1)
        elif test == "T13":
            revoked = revoked + [authorization["payload"]["jti"]]
        original = test in ("T7a", "T7b", "T8")
        if original:
            authorization, status = None, "ORIGINAL_ONLY"
        else:
            status = consume(authorization, req, trusted, authority, now, revoked)
        psign = -1.0 if test in ("T7a", "T7b") else 1.0
        folder = output / test
        folder.mkdir()
        x = torch.tensor([prompt_ids], device=device)
        tokens, steps, cache = [], [], None
        with torch.inference_mode():
            for i in range(4):
                out = model(input_ids=x, past_key_values=cache, use_cache=True, logits_to_keep=1)
                stock = out.logits[0, -1, :]
                require(stock.dtype == torch.bfloat16, "Unexpected content dtype")
                if i == 0:
                    selected, state, intervention = boundary(module, gate, stock, condition, psign, status)
                else:
                    selected, state, intervention = stock, None, "NONE"
                token = int(selected.float().argmax())
                for label, tensor in (("stock", stock), ("selected", selected)):
                    (folder / f"{i}-{label}.bf16.bin").write_bytes(tensor_bytes(tensor))
                steps.append({"index": i, "stock_vector_sha256": digest(tensor_bytes(stock)),
                              "selected_vector_sha256": digest(tensor_bytes(selected)),
                              "non_eos_sha256": digest(tensor_bytes(non_eos(selected))),
                              "stock_eos_logit": float(stock[EOS]), "intervened_eos_logit": float(selected[EOS]),
                              "selected_token": token, "permission_state": state, "intervention": intervention})
                tokens.append(token)
                if token == EOS:
                    break
                x, cache = torch.tensor([[token]], device=device), out.past_key_values
        visible = tokens[:-1] if tokens[-1] == EOS else tokens
        raw = tokenizer.decode(visible, skip_special_tokens=False).encode("utf-8")
        env = dict(runtime(), device=device, transformers=__import__("transformers").__version__)
        row = {"schema": "swiftapi-eos-fresh/1", "mode": "FRESH_LOCAL_INFERENCE", "test_id": test,
               "request": req, "request_hash": digest(canonical(req)), "authorization": authorization,
               "authorization_status": status, "decision_time": now, "revoked_jtis": revoked,
               "permission_sign": psign, "execution_id": str(uuid.uuid4()), "runtime": env,
               "rendered_prompt_utf8_sha256": digest(rendered.encode()), "input_ids": prompt_ids,
               "steps": steps, "generated_token_ids": tokens, "max_new_tokens": 4,
               "generation_complete": tokens[-1] == EOS, "native_eos": EOS,
               "output_utf8_base64": base64.b64encode(raw).decode(), "output_bytes": len(raw), "output_sha256": digest(raw),
               "content_files": identities, "verification_status": "CAPTURED_PENDING_REPLAY"}
        save(folder / "receipt.json", sign(row, key))
    files = {str(p.relative_to(output)): filehash(p) for p in sorted(output.rglob("*")) if p.is_file()}
    save(output / "manifest.json", sign({"schema": "swiftapi-eos-run/1", "mode": "FRESH_LOCAL_INFERENCE",
                                        "tests": TESTS, "files": files}, key))
    return verify_fresh(source, output, trusted)


def verify_fresh(source, output, trusted):
    """Check captured vectors and decode; does NOT recompute Qwen forward passes."""
    from transformers import AutoTokenizer
    verify_source(source)
    output = Path(output)
    m = authenticate(read(output / "manifest.json"), trusted)
    require(m["schema"] == "swiftapi-eos-run/1" and m["mode"] == "FRESH_LOCAL_INFERENCE" and m["tests"] == TESTS, "Incomplete fresh run")
    for name, h in m["files"].items():
        require(not Path(name).is_absolute() and ".." not in Path(name).parts, "Unsafe file path")
        require(filehash(output / name) == h, "Fresh file integrity")
    module, gate = load_gate(source)
    tok = AutoTokenizer.from_pretrained(Path(source) / "content", local_files_only=True)
    from core import prompt
    rendered = prompt(read(Path(source) / "config.json")["system"], QUESTION)
    seen, required_files, outcomes = set(), {"public.json"}, []
    identity = {n: h for n, h in inventory()["all_upstream_files"].items() if n.startswith("content/")}
    for test in TESTS:
        required_files.add(f"{test}/receipt.json")
        r = authenticate(read(output / test / "receipt.json"), trusted)
        require(r["schema"] == "swiftapi-eos-fresh/1" and r["mode"] == "FRESH_LOCAL_INFERENCE" and r["test_id"] == test, "Fresh schema")
        c = FALSE if test in ("T2", "T7b", "T8") else TRUE
        require(r["request"] == request(c, "FRESH_LOCAL_INFERENCE", r["request"]["nonce"]), "Fresh identity")
        require(r["request_hash"] == digest(canonical(r["request"])) and r["content_files"] == identity, "Fresh hashes")
        require(r["input_ids"] == tok.encode(rendered, add_special_tokens=False) and r["rendered_prompt_utf8_sha256"] == digest(rendered.encode()), "Question-only input mismatch")
        original = test in ("T7a", "T7b", "T8")
        psign = -1.0 if test in ("T7a", "T7b") else 1.0
        status = "ORIGINAL_ONLY" if original else assess(r["authorization"], r["request"], trusted, r["decision_time"], seen, r["revoked_jtis"])
        if status in ("VALID_ALLOW", "VALID_DENY"):
            seen.add(r["authorization"]["payload"]["jti"])
        expected_status = {"T1": "VALID_ALLOW", "T2": "VALID_DENY", "T3": "INVALID_SIGNATURE", "T4": "EXPIRED_OR_FUTURE", "T5": "REPLAYED", "T6": "BINDING_MISMATCH", "T13": "REVOKED"}
        require(status == expected_status.get(test, "ORIGINAL_ONLY") == r["authorization_status"], "Fresh authorization")
        require(r["permission_sign"] == psign and r["max_new_tokens"] == 4 and r["native_eos"] == EOS, "Fresh settings")
        require(1 <= len(r["steps"]) <= 4, "Invalid sequence length")
        tokens = []
        for i, step in enumerate(r["steps"]):
            paths = [f"{test}/{i}-{label}.bf16.bin" for label in ("stock", "selected")]
            required_files.update(paths)
            stock, captured = [tensor_from(output / name) for name in paths]
            computed, state, intervention = boundary(module, gate, stock, c, psign, status) if i == 0 else (stock, None, "NONE")
            require(tensor_bytes(computed) == tensor_bytes(captured), "Fresh EOS-only numerical replay mismatch")
            token = int(computed.float().argmax())
            require(step["index"] == i and step["selected_token"] == token and EOS not in tokens, "Forged token/continuation after EOS")
            for k, t in (("stock_vector_sha256", stock), ("selected_vector_sha256", captured), ("non_eos_sha256", non_eos(captured))):
                require(step[k] == digest(tensor_bytes(t)), "Fresh vector hash")
            require(step["permission_state"] == state and step["intervention"] == intervention, "Fresh mechanism")
            require(step["stock_eos_logit"] == float(stock[EOS]) and step["intervened_eos_logit"] == float(computed[EOS]), "Fresh EOS metadata")
            tokens.append(token)
        require(tokens == r["generated_token_ids"] and r["generation_complete"] == (tokens[-1] == EOS), "Fresh trace mismatch")
        require(tokens[-1] == EOS or len(tokens) == 4, "Premature stopping")
        raw = tok.decode(tokens[:-1] if tokens[-1] == EOS else tokens, skip_special_tokens=False).encode()
        require(base64.b64decode(r["output_utf8_base64"], validate=True) == raw and r["output_bytes"] == len(raw) and r["output_sha256"] == digest(raw), "Fresh output mismatch")
        outcomes.append({"test": test, "tokens": tokens, "bytes": len(raw), "expected_behavior": tokens == ([19, EOS] if test in ("T1", "T7b") else [EOS])})
    require(set(m["files"]) == required_files, "Incomplete/extra fresh files")
    return {"status": "PASS", "mode": "FRESH_LOCAL_INFERENCE", "results": outcomes,
            "behavioral_reproduction": all(x["expected_behavior"] for x in outcomes),
            "verification_scope": "Signed captured-vector replay; forward-pass provenance requires independent full-model rerun."}
