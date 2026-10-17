"""Check staged/public files for key leakage and accidental local paths."""
import base64
import re
import subprocess
from pathlib import Path

root = Path(__file__).resolve().parents[1]
names = subprocess.check_output(["git", "ls-files", "-z"], cwd=root).decode().split("\0")
keypath = root / ".authority/private.key"
key = keypath.read_bytes() if keypath.exists() else None
patterns = [rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", rb"gh[pousr]_[A-Za-z0-9]{30,}", rb"sk-[A-Za-z0-9]{32,}"]
failures = []
for name in filter(None, names):
    raw = (root / name).read_bytes()
    if key and any(value in raw for value in (key, key.hex().encode(), base64.b64encode(key))):
        failures.append((name, "local private key material"))
    if any(re.search(pattern, raw) for pattern in patterns):
        failures.append((name, "credential pattern"))
    if name != "tools/check_public_files.py" and (b"/Users/" in raw or b"/home/" in raw):
        failures.append((name, "absolute local home path"))
if failures:
    raise SystemExit(str(failures))
print("PASS: tracked files contain no local signing key, matched credential pattern, or absolute home path")
