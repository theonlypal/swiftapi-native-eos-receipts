import importlib.util
import shutil
import sys
import urllib.request
from pathlib import Path

from .common import ROOT, REVISION, EOS, QUESTION, digest, filehash, read, require


def inventory():
    m = read(ROOT / "SOURCE_MANIFEST.json")
    require(m["revision"] == REVISION, "Revision mismatch")
    require(filehash(ROOT / "upstream/SHA256SUMS.original") == m["upstream_manifest_sha256"], "Manifest changed")
    original = dict((n, h) for h, n in (line.split("  ", 1) for line in (ROOT / "upstream/SHA256SUMS.original").read_text().splitlines()))
    require(original == m["all_upstream_files"], "Upstream inventory mismatch")
    for name, item in m["files"].items():
        require(original[name] == item["sha256"], "Source pin mismatch")
    return m


def fetch(destination, local=None):
    destination = Path(destination)
    m = inventory()
    for name, item in m["files"].items():
        out = destination / name
        if out.exists():
            require(filehash(out) == item["sha256"], "Existing source corrupted: " + name)
            continue
        out.parent.mkdir(parents=True, exist_ok=True)
        if local:
            require(filehash(Path(local) / name) == item["sha256"], "Local source corrupted: " + name)
            shutil.copyfile(Path(local) / name, out)
        else:
            url = f"https://huggingface.co/{m['repository']}/resolve/{REVISION}/{name}"
            with urllib.request.urlopen(url, timeout=120) as r, out.open("xb") as f:
                shutil.copyfileobj(r, f)
        require(filehash(out) == item["sha256"], "Downloaded hash mismatch: " + name)
    return verify_source(destination)


def verify_source(root):
    root = Path(root)
    m = inventory()
    for name, item in m["files"].items():
        require(filehash(root / name) == item["sha256"], "Source hash mismatch: " + name)
    require(read(root / "config.json")["EOS"] == EOS, "EOS configuration")
    vocab = read(root / "content/vocab.json")
    # Qwen added special tokens are specified in tokenizer_config, not base vocab.
    added = read(root / "content/tokenizer_config.json")["added_tokens_decoder"]
    require(added[str(EOS)]["content"] == "<|im_end|>" and vocab["4"] == 19, "Native token identity")
    return {"status": "PASS", "files": len(m["files"]), "revision": REVISION}


def upstream_model(root):
    # Execute only previously hash-verified original source, without edits.
    root = Path(root)
    verify_source(root)
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(root / "src"))
    try:
        spec = importlib.util.spec_from_file_location("pccg2_original_model", root / "src/model.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path.pop(0)


def tensor_bytes(tensor):
    import torch
    return tensor.detach().contiguous().view(torch.uint8).cpu().numpy().tobytes()


def non_eos(tensor):
    import torch
    return torch.cat((tensor[:EOS], tensor[EOS + 1:]))


def load_gate(root):
    from safetensors.torch import load_file
    module = upstream_model(root)
    gate = module.ConditionChannel(32.0)
    gate.load_state_dict(load_file(str(Path(root) / "gate/permission.safetensors")))
    gate.eval().requires_grad_(False)
    require(sum(p.numel() for p in gate.parameters()) == 101, "Gate size")
    return module, gate


def stock_witness(root):
    from safetensors import safe_open
    bank = read(Path(root) / "evidence/bank.json")
    hits = [i for i, r in enumerate(bank) if r["question"] == QUESTION]
    require(len(hits) == 1, "Ambiguous bank witness")
    with safe_open(str(Path(root) / "evidence/bank-first-logits.safetensors"), framework="pt", device="cpu") as f:
        stock = f.get_slice("first_logits")[hits[0]].clone()
    require(digest(tensor_bytes(non_eos(stock))) == bank[hits[0]]["nonEOS_bf16_sha256"], "Stock non-EOS identity")
    return stock


def verify_witness(root):
    import torch
    module, gate = load_gate(root)
    model = module.SeparatedContinuationModel(torch.nn.Identity(), gate)
    stock = stock_witness(root)
    results = []
    rows = read(Path(root) / "evidence/witness-2plus2.json")
    require(len(rows) == 5, "Witness incomplete")
    traces = [[19, EOS], [EOS], [EOS], [19, EOS], [EOS]]
    for row, trace in zip(rows, traces):
        ids = torch.tensor([module.condition_tokens(row["condition"])])
        logits, state = model.boundary(stock[None], ids, True, row["permission_sign"])
        raw = tensor_bytes(logits[0])
        require(raw == (Path(root) / row["first_logits_file"]).read_bytes(), "Witness vector differs")
        require(tensor_bytes(non_eos(logits[0])) == tensor_bytes(non_eos(stock)), "Non-EOS changed")
        require(int(logits[0].argmax()) == trace[0], "Wrong first-token argmax")
        require(row["generated_ids"] == trace, "Recorded trace differs")
        require(float(logits[0, 19]) == 53.0, "Answer score changed")
        results.append({"arm": row["label"], "replayed_first_token": trace[0], "archived_generated_ids": trace,
                        "eos_logit": float(logits[0, EOS]), "full_vector_sha256": digest(raw)})
    return {"status": "PASS", "mode": "SAVED_LOGIT_REPLAY", "arms": results,
            "scope": "Full-vocabulary first-token replay; later tokens are authenticated archived traces, not freshly generated."}
