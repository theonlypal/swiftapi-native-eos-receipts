"""Persist observed unittest results, including failures, without inventing counts."""
import io
import json
import unittest
from pathlib import Path

stream = io.StringIO()
suite = unittest.defaultTestLoader.discover("tests")
result = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
print(stream.getvalue())
folder = Path("verification"); folder.mkdir(exist_ok=True)
(folder / "tests.log").write_text(stream.getvalue())
(folder / "tests.json").write_text(json.dumps({"tests_run": result.testsRun,
    "failures": [(str(t), e) for t, e in result.failures], "errors": [(str(t), e) for t, e in result.errors],
    "skipped": result.skipped, "passed": result.wasSuccessful()}, indent=2) + "\n")
raise SystemExit(0 if result.wasSuccessful() else 1)
