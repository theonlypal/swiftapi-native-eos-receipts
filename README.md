# SwiftAPI Native EOS Receipts

Verified condition → first-token EOS decision → signed, independently replayable receipt.

This harness integrates local Ed25519 authorization with the original PCCG-2 decoding boundary. The learned 101-parameter gate remains unchanged. Invalid authorization invokes a separately identified EOS-only veto **before argmax**, not a post-generation output filter.

**Prospective experiment:** [Trusted decoding-boundary preregistration v1](preregistration/TRUSTED_DECODING_BOUNDARY_V1.md). This new registration separates fresh software-boundary execution from independently attested runtime enforcement. It does not retroactively preregister the existing replay results. No new experiment has been executed under it.

## Three modes, different evidence

| Backend | What runs | Full model needed? |
|---|---|---|
| Offline verification | Source hashes, original witness, signatures, numerical receipt checks | No |
| Saved-logit replay | Original learned gate and full-vocabulary selection on authentic saved stock logits | No |
| Fresh local inference | Frozen Qwen3-4B forward passes and native decoding on CPU/MPS | Yes, local only |

**Saved replay is not fresh Qwen inference.** All example signatures are `LOCAL_TEST_AUTHORITY`, not production SwiftAPI signatures. A signature proves issuer authenticity and record integrity, not physical inference.

## Reproduce without a GPU or account

Python 3.11 or newer. Run commands from the cloned repository:

```sh
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
swiftapi-eos fetch-witness
swiftapi-eos verify-source
swiftapi-eos init-local-authority
swiftapi-eos replay-witness --out receipts/my-replay
swiftapi-eos verify-run --run receipts/my-replay --trusted-key .authority/public.json
python -m unittest discover -s tests -v
```

The witness fetch is about 76.5 MB of pinned evidence, source and tokenizer data, including the authentic bank tensor. It does **not** download the 8 GB model. With an existing release, avoid all artifact downloads:

```sh
swiftapi-eos fetch-witness --local-release /path/to/PCCG-2-release
```

To check the published example without its private key:

```sh
swiftapi-eos verify-run --run receipts/replay-002 --trusted-key receipts/replay-002/public.json
```

That key is the example's public local trust anchor, not an externally certified identity. `receipts/replay-001` preserves the earlier development capture; `replay-002` adds the full dependency-version record.

## Actual witness, not invented continuation

| Original arm | Archived token trace | First-token EOS logit |
|---|---|---:|
| Licensed | `[19,151645]` → `4` | -124 |
| Unlicensed | `[151645]` → empty | 94.5 |
| Licensed reversed | `[151645]` → empty | 136 |
| Unlicensed reversed | `[19,151645]` → `4` | -82 |
| Unlicensed sham | `[151645]` → empty | 94.5 |

Answer token 19 retains logit **53.0**. All five full non-EOS vectors have SHA-256:

`5f42fcb08c73af4914a711b524ae7130d671ec9504ecdfa699e8f478094713ec`

The new replay selects exactly one token. Its answer records contain `[19]`, not a fabricated second EOS. Archived full traces remain separately identified in `upstream-witness.json`.

## Fresh local inference

```sh
pip install -e '.[inference]'
swiftapi-eos infer-local --content /path/to/PCCG-2-release/content --device auto --out receipts/fresh-local
swiftapi-eos verify-run --run receipts/fresh-local --trusted-key .authority/public.json
```

No weights are downloaded. CPU can be selected with `--device cpu`. Full BF16 is required; no quantization or dtype fallback occurs. Insufficient memory produces a saved `UNAVAILABLE_HARDWARE` record. Fresh execution was **not achieved on the qualification host**: its available memory failed the resource preflight. The implementation is not claimed to be empirically validated on MPS or CPU full-model inference.

## Authority status

Local authority issuance, signature verification, expiry, action binding, denial, revocation and atomic replay protection are exercised in the CPU benchmark. Original gate-only reversal/sham arms are explicitly diagnostic.

`src/swiftapi_eos/production.py` provides an optional SwiftAPI SDK 1.3.1 adapter for explicit caller-supplied clients and credentials. It checks signatures, action fingerprints, independent prerequisite truth and live revocation, with no offline fail-open. **It is not exposed as a qualified CLI authority mode and has not been tested against live issuance.** Production integration remains an explicit qualification limitation; no production receipts are included.

See [PROTOCOL.md](PROTOCOL.md), [THREAT_MODEL.md](THREAT_MODEL.md), and [verification/REPORT.md](verification/REPORT.md). The signed test matrix includes invalid signature, expiry, replay, wrong scope, causal reversal, sham and revocation. Adversarial tests cover altered receipts, identities, selected tokens and missing records.

## Provenance

- PCCG-2: https://huggingface.co/sharthokrayanpal/PCCG-2-Qwen3-4B/tree/a3b952458a46b5547ba3cec7d03a37b395bed03a
- Rayan Pal, *Separating Capability from Permission in a Language Model*: https://doi.org/10.5281/zenodo.22730710
- https://getswiftapi.com/pccg-2
- SwiftAPI SDK: https://pypi.org/project/swiftapi-python/1.3.1/
- https://github.com/theonlypal/swiftapi-native-void
- https://github.com/theonlypal/agents-terminal-empty

`SOURCE_MANIFEST.json` pins each artifact and the original release inventory. Upstream files are never rewritten. PCCG-2 source retains its original Apache-2.0 licensing and notices in the fetched evidence. This harness is Apache-2.0.
