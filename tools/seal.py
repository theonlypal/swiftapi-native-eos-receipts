"""Seal tracked public files and optionally bundle the verified offline evidence."""
import argparse
import hashlib
import subprocess
import zipfile
import tomllib
from pathlib import Path

p = argparse.ArgumentParser()
p.add_argument("--bundle", action="store_true")
a = p.parse_args()
root = Path(__file__).resolve().parents[1]
names = subprocess.check_output(["git", "ls-files", "-z"], cwd=root).decode().split("\0")
names = sorted(n for n in names if n and n != "SHA256SUMS")
for name in names:
    if any(part in (".authority", ".deps", ".venv", "__pycache__") for part in Path(name).parts) or name.endswith((".key", ".pem")):
        raise SystemExit("Private/unnecessary file staged: " + name)
sha = lambda raw: hashlib.sha256(raw).hexdigest()
(root / "SHA256SUMS").write_text("".join(f"{sha((root / n).read_bytes())}  {n}\n" for n in names))
print("Sealed", len(names), "tracked public files")
if a.bundle:
    from swiftapi_eos.source import inventory, verify_source
    verify_source(root / ".cache/pccg2")
    paths = names + ["SHA256SUMS"] + [".cache/pccg2/" + n for n in inventory()["files"]]
    folder = root / "dist"; folder.mkdir(exist_ok=True)
    version = tomllib.loads((root / "pyproject.toml").read_text())["project"]["version"]
    dest = folder / f"swiftapi-native-eos-receipts-v{version}.zip"
    with zipfile.ZipFile(dest, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for name in sorted(paths):
            info = zipfile.ZipInfo(name, date_time=(2026, 10, 16, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            z.writestr(info, (root / name).read_bytes())
    with zipfile.ZipFile(dest) as z:
        if z.testzip() is not None:
            raise SystemExit("ZIP integrity failed")
    h = sha(dest.read_bytes())
    (folder / "SHA256SUMS").write_text(f"{h}  {dest.name}\n")
    print(dest.name, dest.stat().st_size, h)
