"""Build the pinned source inventory from an existing authenticated release.

Maintainer utility; never called by receipt verification. Does not alter upstream.
"""
import argparse
import hashlib
import json
from pathlib import Path

p = argparse.ArgumentParser()
p.add_argument("release", type=Path)
p.add_argument("cached_snapshot", type=Path)
a = p.parse_args()
manifest = (a.release / "SHA256SUMS").read_bytes()
if manifest != (a.cached_snapshot / "SHA256SUMS").read_bytes():
    raise SystemExit("Local release differs from pinned cached manifest")
inventory = dict((name, h) for h, name in (line.split("  ", 1) for line in manifest.decode().splitlines()))
selected = [n for n in inventory if n.startswith(("src/", "gate/", "evidence/witness/"))]
selected += ["config.json", "LICENSE", "NOTICE", "evidence/witness-2plus2.json", "evidence/audit.json",
             "evidence/bank.json", "evidence/bank-first-logits.safetensors", "evidence/base-identity.json",
             "evidence/records/causal-freeze.json", "evidence/witness-non-eos-vector.sha256",
             "content/config.json", "content/tokenizer.json", "content/tokenizer_config.json",
             "content/vocab.json", "content/merges.txt", "content/generation_config.json"]
files = {}
for name in sorted(set(selected)):
    path = a.release / name
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != inventory[name]:
        raise SystemExit("Hash failure: " + name)
    files[name] = {"sha256": actual, "bytes": path.stat().st_size}
root = Path(__file__).resolve().parents[1]
(root / "upstream").mkdir(exist_ok=True)
(root / "upstream/SHA256SUMS.original").write_bytes(manifest)
result = {"schema": "pccg2-source/1", "repository": "sharthokrayanpal/PCCG-2-Qwen3-4B",
          "revision": "a3b952458a46b5547ba3cec7d03a37b395bed03a",
          "upstream_manifest_sha256": hashlib.sha256(manifest).hexdigest(), "files": files,
          "all_upstream_files": inventory}
(root / "SOURCE_MANIFEST.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
print(len(files), "pinned artifacts", sum(v["bytes"] for v in files.values()), "bytes")
