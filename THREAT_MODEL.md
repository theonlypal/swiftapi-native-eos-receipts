# Threat model

Trusted: pinned upstream hashes, reviewed decoder/verifier code, supplied public-key trust anchor, local signing authority, local clock, atomic replay database, and recorded revocation state. Neither a self-supplied key nor a valid signature proves that Qwen physically ran. The public example uses a local test key, not SwiftAPI's production identity.

An attacker without the signing key cannot alter receipts. Even a re-signed false selected token or mutated vector fails independent numerical replay. The verifier requires every frozen test record; dropping a failure invalidates run completeness. An operator who controls the software, clock, signing key and execution host can fabricate self-consistent observations. Remote attestation, a hardware root of trust and tamper-resistant enforcement are outside scope.

Replay protection is atomic for consumers sharing one SQLite authority state. Separate copies of that state are separate security domains. Local revocation is a supplied list and historical recorded snapshot, not a globally synchronized service. The production adapter requires successful online SDK revocation checks and fails closed on errors; it has not been live-qualified.

The veto is new trusted decoder integration, not a discovered internal model circuit. It can be removed by someone who can change the decoder. Exact non-EOS logits are preserved; their unconditional softmax probabilities can change because the normalization includes EOS.

Six-digit equality only. The witness bank does not establish arbitrary-predicate evaluation, long-form answer invariance, AGI, consciousness, hosted-model Void mechanisms, or universal shutdown. Original reversal diagnostics are deliberately not available in the authorized execution path.

No credentials or private keys belong in public artifacts. `.authority/` is ignored. Public key trust must be established out of band; the example key establishes only consistency of this example issuer.
