## Gas / fee optimization suggestions

### Contract storage costs dominate

- Storing `Array<felt252>` is expensive. Prefer:
  - **store ciphertext off-chain** (IPFS/Arweave) and keep only Poseidon commitments on-chain, or
  - **chunking + compression** (pack bytes tightly; avoid storing AAD if not needed).

### Reduce per-message writes

- Avoid storing `aad` unless you truly need it.
- Consider packing nonce into a single felt (12 bytes fits).
- Use smaller metadata where possible (e.g., store `expires_at` as `u32` if acceptable).

### Event-driven indexing

- Emit events with minimal payload; indexers can reconstruct state.
- Avoid on-chain iteration; always query by `msg_id` and use off-chain indexers for inbox views.

### Deletion strategy

- “Delete” on-chain can only clear storage slots (still costs gas).
- Consider lazy deletion: mark as deleted and let clients ignore payload, optionally clearing payload only for high-value privacy paths.

