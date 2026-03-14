## Security considerations (high signal)

### Client-side crypto

- **Use AES-GCM** for confidentiality + integrity of the plaintext.
- **Key derivation**: do **not** use raw `SHA-256(secret)` in production. Use **Argon2id** (preferred) or PBKDF2 with:
  - a per-chat/per-message salt,
  - high work factor,
  - and memory hardness if possible.
- **Nonce**: must be unique per key. The provided code uses random 96-bit nonces (good).
- **Do not reuse secrets** across recipients/rooms; derive per-conversation keys.

### On-chain data model

- **No plaintext**: only ciphertext + nonce + AAD + commitments are stored.
- **Expiry**: enforced in `get_message` and `unlock_message`; deletion is a state transition (`delete_message`) that clears payload.
- **Indexing**: on-chain enumeration is expensive; rely on events for indexing in your UI (The Graph-style indexer / Apibara).

### ZK unlock

- **Verifier contract is the trust root**: if it’s wrong, anyone can unlock/burn messages.
- **Bind proof to message + recipient**: include `msg_id` and `to` in the commitment/circuit so a proof can’t be replayed.
- **Prevent replay**: contract marks `meta.read = true` and blocks re-unlock.

### Privacy / metadata

- Recipient + timestamps + ciphertext length are public. If you need stronger metadata privacy:
  - use room-based broadcasting (many recipients),
  - pad messages to fixed sizes,
  - consider off-chain storage (IPFS) with on-chain commitments.

