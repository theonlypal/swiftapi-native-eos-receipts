import hashlib
import json
from pathlib import Path

REVISION = "a3b952458a46b5547ba3cec7d03a37b395bed03a"
EOS = 151645
QUESTION = "What is 2 + 2?"
TRUE = "EQ(485487,485487)"
FALSE = "EQ(485487,485489)"
ROOT = Path(__file__).resolve().parents[2]


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def filehash(path):
    with Path(path).open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def read(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "Duplicate JSON key")
            result[key] = value
        return result
    def bad_constant(value):
        raise ValueError("Nonfinite JSON constant: " + value)
    return json.loads(Path(path).read_text(), object_pairs_hook=unique, parse_constant=bad_constant)


def save(path, value):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_bytes(canonical(value) + b"\n")


def require(value, message):
    if not value:
        raise ValueError(message)
