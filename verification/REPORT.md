# Qualification report

Date: October 16, 2026. No paid inference, provider model API, RunPod, retraining or weight download.

## Executed

- The original, unchanged PCCG-2 `src/verify.py` passed under Python 3.12: **82 hashes and 5/5 original witness arms**, including the released behavioral/causal checks. This is archived-evidence verification, not fresh forward inference.
- The original release inventory was compared byte-for-byte with the manifest fetched from the pinned Hugging Face revision. Match.
- The harness verified **35 pinned source/evidence/tokenizer artifacts**, 76,484,908 bytes. All were copied from the existing local release. Only the small public manifest was fetched for an independent origin comparison.
- Original five-arm replay reproduced all five first-token vectors byte-for-byte, including complete non-EOS invariance and the recorded first-token argmax.
- `replay-002`: **10 signed decoder records verified**, covering T1–T6, both T7 directions, T8, and extra revocation case T13. Two selected answer token 19; eight selected native EOS 151645. Every EOS record has exactly zero output bytes.
- **15 unittest tests passed**, zero failures/errors/skips. See `tests.json` and `tests.log` for executed counts and exact tests, including T9–T12 adversarial mutations. Some forged records were re-signed by the test authority to ensure numerical/source verification rejects them independently of signature integrity.
- Python source compilation succeeded. No original research artifacts were modified.
- A clean extraction of the self-contained ZIP passed its public-file checksums, signed replay verification and all 15 unit tests without a model download. It used the existing local Python dependencies; this is not a claim of a clean operating-system installation.
- Public-file inspection found no local signing-key material, matched credential patterns or absolute home paths. The private signing key and replay database remain excluded from Git and the bundle.

## Commands

```sh
python src/verify.py  # inside the original release, Python >=3.11
swiftapi-eos fetch-witness --local-release /path/to/original/release
swiftapi-eos verify-source
swiftapi-eos init-local-authority
swiftapi-eos replay-witness --out receipts/replay-002
swiftapi-eos verify-run --run receipts/replay-002 --trusted-key receipts/replay-002/public.json
python tools/run_tests.py
swiftapi-eos infer-local --content /path/to/original/release/content --out receipts/fresh-attempt-001
```

Qualification used an existing Python 3.12 environment with Torch 2.8.0, NumPy 2.3.3, safetensors 0.6.2, Transformers 4.56.2, and cryptography 46.0.3. New receipts capture dependency versions. A project-local dependency directory supplied cryptography; no upstream environment was modified.

## Preserved limitations

- Fresh inference: **UNAVAILABLE_HARDWARE**. Available memory 2,518,106,112 bytes; conservative required memory 14,214,956,648 bytes; locally present model shards 8,044,982,000 bytes. No Qwen forward pass occurred. CPU/MPS code is provided but full-model execution is not empirically qualified here.
- Production SwiftAPI issuance/integration: **NOT LIVE QUALIFIED**. The optional adapter uses the SDK interface, but the default CLI intentionally exposes only the tested local authority. No production signature, credential or remote revocation response was fabricated.
- GitHub CI execution is separate from local tests. Initial run 38988860809 caught a missing `packaging` dependency after source verification. Version 0.1.1 explicitly pins it. Consult the corresponding commit's workflow for the remote verdict; this report does not predeclare it passed.
- Signature authenticity is not hardware execution attestation. Fresh captured-vector verification would substantiate token selection from captured logits, not independently recompute the content model.
- The authority is local and self-issued. External identity, tamper-resistant enforcement and globally synchronized replay/revocation are not established.

## Supported claim

Cryptographically verified local binding-condition decisions were integrated with first-token EOS selection using PCCG-2's original learned gate and authentic saved logits, with independently verifiable signed receipts. A separately identified authorization veto selected native EOS without modifying non-EOS logits.

This is a **saved-logit integration result**, not a fresh full-model inference result or a production SwiftAPI deployment. Full acceptance for those optional paths remains pending the stated resources and qualification.
