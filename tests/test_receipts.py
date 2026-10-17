import copy
import json
import shutil
import tempfile
import time
import unittest
from pathlib import Path

from swiftapi_eos.authority import authenticate, consume, init_authority, issue, load_private, sign
from swiftapi_eos.common import EOS, ROOT, TRUE, filehash, read, save
from swiftapi_eos.runs import execute_replay, request, verify_run
from swiftapi_eos.source import verify_source, verify_witness


class Receipts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.base = Path(cls.temp.name)
        cls.source = ROOT / ".cache/pccg2"
        cls.authority = cls.base / "authority"
        cls.trusted = init_authority(cls.authority)
        cls.key = load_private(cls.authority)
        cls.run_dir = cls.base / "run"
        cls.result = execute_replay(cls.source, cls.authority, cls.run_dir)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def modified(self):
        out = self.base / ("mutant-" + str(time.time_ns()))
        shutil.copytree(self.run_dir, out)
        return out

    def reseal(self, out):
        m = read(out / "manifest.json")["payload"]
        m["files"] = {n: filehash(out / n) for n in m["files"] if (out / n).exists()}
        save(out / "manifest.json", sign(m, self.key))

    def test_upstream_source(self):
        self.assertEqual(verify_source(self.source)["status"], "PASS")

    def test_original_five_arms(self):
        arms = verify_witness(self.source)["arms"]
        self.assertEqual([r["replayed_first_token"] for r in arms], [19, EOS, EOS, 19, EOS])

    def test_T1_T8_and_revocation(self):
        self.assertEqual(self.result["records_verified"], 10)
        self.assertEqual([r["selected"] for r in self.result["results"]], [19, EOS, EOS, EOS, EOS, EOS, EOS, 19, EOS, EOS])

    def test_T9_tamper_signature(self):
        out = self.modified()
        r = read(out / "T1/receipt.json")
        r["payload"]["output_bytes"] = 999
        save(out / "T1/receipt.json", r)
        self.reseal(out)
        with self.assertRaises(Exception):
            verify_run(self.source, out, self.trusted)

    def test_T10_resigned_wrong_model(self):
        out = self.modified()
        r = read(out / "T1/receipt.json")["payload"]
        r["request"]["revision"] = "wrong"
        save(out / "T1/receipt.json", sign(r, self.key))
        self.reseal(out)
        with self.assertRaisesRegex(ValueError, "identity"):
            verify_run(self.source, out, self.trusted)

    def test_T10_resigned_wrong_gate(self):
        out = self.modified()
        r = read(out / "T1/receipt.json")["payload"]
        r["request"]["gate_sha256"] = "0" * 64
        save(out / "T1/receipt.json", sign(r, self.key))
        self.reseal(out)
        with self.assertRaisesRegex(ValueError, "identity"):
            verify_run(self.source, out, self.trusted)

    def test_T11_resigned_forged_token(self):
        out = self.modified()
        r = read(out / "T1/receipt.json")["payload"]
        r["selected_first_token"] = EOS
        save(out / "T1/receipt.json", sign(r, self.key))
        self.reseal(out)
        with self.assertRaisesRegex(ValueError, "Forged selected token"):
            verify_run(self.source, out, self.trusted)

    def test_T12_drop_required_record_even_with_new_signature(self):
        out = self.modified()
        (out / "T8/receipt.json").unlink()
        self.reseal(out)
        with self.assertRaisesRegex(ValueError, "INCOMPLETE_RUN"):
            verify_run(self.source, out, self.trusted)

    def test_wrong_trust_anchor(self):
        other = init_authority(self.base / "other")
        with self.assertRaises(Exception):
            verify_run(self.source, self.run_dir, other)

    def test_non_eos_tamper_even_with_new_manifest(self):
        out = self.modified()
        p = out / "T1/selected.bf16.bin"
        b = bytearray(p.read_bytes()); b[38] ^= 1; p.write_bytes(b)
        self.reseal(out)
        with self.assertRaisesRegex(ValueError, "replay failed"):
            verify_run(self.source, out, self.trusted)

    def test_atomic_replay_across_connections(self):
        req = request(TRUE, "SAVED_LOGIT_REPLAY")
        auth = issue(req, self.key)
        self.assertEqual(consume(auth, req, self.trusted, self.authority, time.time(), []), "VALID_ALLOW")
        self.assertEqual(consume(auth, req, self.trusted, self.authority, time.time(), []), "REPLAYED")

    def test_future_authorization(self):
        req = request(TRUE, "SAVED_LOGIT_REPLAY")
        auth = issue(req, self.key, now=time.time() + 1000)
        self.assertEqual(consume(auth, req, self.trusted, self.authority, time.time(), []), "EXPIRED_OR_FUTURE")

    def test_signed_false_allow_is_rejected(self):
        from swiftapi_eos.common import FALSE
        req = request(FALSE, "SAVED_LOGIT_REPLAY")
        a = issue(req, self.key)["payload"]; a["approved"] = True
        self.assertEqual(consume(sign(a, self.key), req, self.trusted, self.authority, time.time(), []), "VERDICT_MISMATCH")

    def test_auth_veto_before_argmax_non_eos_unchanged(self):
        r = authenticate(read(self.run_dir / "T3/receipt.json"), self.trusted)
        self.assertEqual(r["intervention"], "AUTHORIZATION_EOS_VETO")
        self.assertEqual(r["selected_first_token"], EOS)
        self.assertEqual(r["output_bytes"], 0)
        a = authenticate(read(self.run_dir / "T1/receipt.json"), self.trusted)
        self.assertEqual(r["non_eos_sha256"], a["non_eos_sha256"])

    def test_cannot_invent_second_token(self):
        out = self.modified()
        r = read(out / "T1/receipt.json")["payload"]
        r["generated_token_ids"] = [19, EOS]
        save(out / "T1/receipt.json", sign(r, self.key)); self.reseal(out)
        with self.assertRaisesRegex(ValueError, "Invented continuation"):
            verify_run(self.source, out, self.trusted)


if __name__ == "__main__":
    unittest.main(verbosity=2)
