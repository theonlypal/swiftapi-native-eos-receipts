# Retained development failures

1. Original upstream verifier invoked with system Python 3.9.6 failed before checks because `hashlib.file_digest` is unavailable. Reinvoked unchanged with Python 3.12; 82 hashes and all five witness arms passed.
2. Initial unittest harness used `cls.run` for a directory, shadowing `unittest.TestCase.run`; runner failed with `TypeError: 'PosixPath' object is not callable`. Renamed the attribute to `run_dir`. This was a test-harness error, not a decoder result.
3. Fresh inference attempt: resource preflight returned `UNAVAILABLE_HARDWARE`; preserved in `receipts/fresh-attempt-001/status.json`. No full-model forward pass occurred.
