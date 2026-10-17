import argparse
import json
from pathlib import Path

from .common import read


def main():
    p = argparse.ArgumentParser(description="Pinned PCCG-2 evidence and Ed25519 EOS receipts")
    sub = p.add_subparsers(dest="command", required=True)
    for name in ("fetch-witness", "verify-source", "replay-witness", "verify-run", "infer-local"):
        q = sub.add_parser(name)
        q.add_argument("--source", type=Path, default=Path(".cache/pccg2"))
        if name == "fetch-witness":
            q.add_argument("--local-release", type=Path)
        if name in ("replay-witness", "infer-local"):
            q.add_argument("--authority", type=Path, default=Path(".authority"))
            q.add_argument("--out", type=Path, required=True)
        if name == "infer-local":
            q.add_argument("--content", type=Path, required=True)
            q.add_argument("--device", choices=["mps", "cpu", "auto"], default="auto")
        if name == "verify-run":
            q.add_argument("--run", type=Path, required=True)
            q.add_argument("--trusted-key", type=Path, required=True)
    q = sub.add_parser("init-local-authority")
    q.add_argument("--out", type=Path, default=Path(".authority"))
    a = p.parse_args()
    from .source import fetch, verify_source
    from .authority import init_authority
    from .runs import execute_replay, verify_run
    if a.command == "fetch-witness":
        result = fetch(a.source, a.local_release)
    elif a.command == "verify-source":
        result = verify_source(a.source)
    elif a.command == "init-local-authority":
        result = init_authority(a.out)
    elif a.command == "replay-witness":
        result = execute_replay(a.source, a.authority, a.out)
    elif a.command == "verify-run":
        envelope = read(a.run / "manifest.json")
        if envelope["payload"].get("mode") == "FRESH_LOCAL_INFERENCE":
            from .fresh import verify_fresh
            result = verify_fresh(a.source, a.run, read(a.trusted_key))
        else:
            result = verify_run(a.source, a.run, read(a.trusted_key))
    else:
        from .fresh import infer
        try:
            result = infer(a.source, a.authority, a.out, a.content, a.device)
        except (MemoryError, RuntimeError) as exc:
            from .common import save
            result = {"status": "UNAVAILABLE_HARDWARE", "reason": str(exc), "stage": "local execution",
                      "partial_records_preserved": True, "complete_run": False}
            save(a.out / "failure.json", result)
    print(json.dumps(result, indent=2))
    if result.get("status") not in (None, "PASS"):
        raise SystemExit(2)


if __name__ == "__main__":
    main()
