# Retained development failures

1. Original upstream verifier invoked with system Python 3.9.6 failed before checks because `hashlib.file_digest` is unavailable. Reinvoked unchanged with Python 3.12; 82 hashes and all five witness arms passed.
2. Initial unittest harness used `cls.run` for a directory, shadowing `unittest.TestCase.run`; runner failed with `TypeError: 'PosixPath' object is not callable`. Renamed the attribute to `run_dir`. This was a test-harness error, not a decoder result.
3. Fresh inference attempt: resource preflight returned `UNAVAILABLE_HARDWARE`; preserved in `receipts/fresh-attempt-001/status.json`. No full-model forward pass occurred.
4. First clean Linux CI run (38988860809) verified source fetch/hashes, then failed importing `safetensors.torch`: its `packaging` dependency was absent. Explicitly pinned `packaging==25.0` in version 0.1.1. No numerical test had failed. The original 0.1.0 release and failed workflow remain public.
