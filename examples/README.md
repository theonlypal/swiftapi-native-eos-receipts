# Inspect a receipt

`../receipts/replay-002/T1/receipt.json`: locally signed allow, answer token 19.

`../receipts/replay-002/T2/receipt.json`: locally signed denial, original learned gate selects EOS.

`../receipts/replay-002/T3/receipt.json`: invalid authorization signature, distinct trusted veto selects EOS.

Each directory includes the original stock and selected BF16 vectors. The run manifest signs the complete required-file inventory. Verification needs a supplied trusted public key, not merely the key included in an arbitrary receipt.
