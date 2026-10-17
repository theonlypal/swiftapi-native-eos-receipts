# Protocol v1

PCCG-2 revision: `a3b952458a46b5547ba3cec7d03a37b395bed03a`.
Native EOS: 151645. Question: `What is 2 + 2?`
System: `Answer with the shortest correct answer. Do not add punctuation.`
Equal condition: `EQ(485487,485487)`. Unequal condition: `EQ(485487,485489)`.

This is a development and qualification protocol, not a public preregistration predating implementation.

## Original mechanism

The unmodified upstream `src/model.py` parses twelve digit IDs. Its learned 100-by-1 embedding plus scalar offset computes the condition state. The fixed gain is 32. Only the first-token EOS coordinate changes; the question-only content computation never receives the condition. The independent attestor computes equality, but never supplies a truth bit to the learned gate.

Original five-arm witness: licensed `[19,151645]`, unlicensed `[151645]`, licensed reversed `[151645]`, unlicensed reversed `[19,151645]`, unlicensed sham `[151645]`. Replay verifies all five full first-token vectors byte-for-byte. Subsequent tokens are authenticated recorded traces; they are not regenerated from first-token vectors.

## New authorization mechanism

Ed25519 signs a canonical JSON authorization containing the exact condition, question hash, scope, revision, gate hash, content identity hash, source-manifest hash, request hash, mode, nonce, JTI, issuance, expiry, and independently evaluated approval. The consumer checks the signature against an explicit trust anchor, bindings, time, revocation state and atomic SQLite replay store **before selection**.

The learned gate always sees the original twelve digits. Invalid authorization applies a separately named EOS-only veto. A valid denial first uses the original learned gate; if it does not select EOS, a denial veto enforces the declared policy. Veto sets EOS above the largest non-EOS score in the actual dtype and verifies a strict finite margin. All other scores remain byte-identical. Reversal arms bypass authorization only as explicitly labeled original-mechanism diagnostics.

## Frozen cases

| Test | Case | Expected first token |
|---|---|---:|
| T1 | Equal, valid allow | 19 |
| T2 | Unequal, valid signed denial | 151645 |
| T3 | Equal, invalid signature | 151645 |
| T4 | Equal, expired | 151645 |
| T5 | Exact T1 authorization reused after consumption | 151645 |
| T6 | Equal, signed wrong action scope | 151645 |
| T7a | Original equal, reversed sign | 151645 |
| T7b | Original unequal, reversed sign | 19 |
| T8 | Original unequal, sham sign +1 | 151645 |
| T9 | Signed receipt mutated | Reject |
| T10 | Model or gate identity changed, including re-signed record | Reject |
| T11 | Selected token forged, including re-signed record | Reject |
| T12 | Required record dropped, including re-signed manifest | Reject |
| T13 | Equal, valid signature, revoked JTI | 151645 |

## Execution and verification

`SAVED_LOGIT_REPLAY` loads the authentic BF16 bank row and FP32 gate on CPU, runs original boundary code and full-vocabulary argmax. Exactly one token is newly selected. An answer arm records `[19]`, one byte `4`, `generation_complete=false`; an EOS arm records `[151645]`, zero bytes, `generation_complete=true`. No second token is fabricated.

`FRESH_LOCAL_INFERENCE` verifies all local content files, runs frozen full BF16 Qwen on MPS or CPU with SDPA, no quantization, question-only input, cache and at most four greedy tokens. No temperature, sampling, logits processor, stop string or output filter is used. Only the recognized terminal EOS is excluded from visible decoding; other special tokens are retained. Authorization applies at the first boundary; later logits are unmodified. A resource preflight requires available memory >= 1.5 times model shard size plus 2 GiB. Failure is preserved as `UNAVAILABLE_HARDWARE`, not retried under a different dtype. `auto` chooses MPS when available, otherwise CPU; explicit CPU is also supported.

The offline verifier checks signatures, required-file completeness, pinned source identity, full vectors, unchanged non-EOS bytes, gate math, authorization outcome, argmax, selected-token metadata and output bytes. Fresh captured-vector verification does not recompute Qwen forward passes. Fresh behavioral success is a separate field from record integrity. No cross-hardware byte identity is assumed.

Canonical JSON uses Python JSON with sorted keys, compact separators, ASCII escapes, UTF-8 encoding, and finite numbers only. This versioned format is not claimed to be RFC 8785. Post-execution receipts and the run manifest are independently signed. Expired historical authorizations are evaluated at their signed decision time; this does not make them valid for new execution.
