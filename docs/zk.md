## ZK unlock flow (production shape)

StarkCipher’s contract expects an external verifier contract with entrypoint:

- `verify(proof: Array<felt252>, public_inputs: Array<felt252>) -> bool`

### Circuit statement (what the user proves)

User proves knowledge of a secret `s` such that:

- \(C = \text{Poseidon}(s, msg\_id, to, domain\_sep)\)
- Public inputs include: `C`, `msg_id`, `to`, `domain_sep`

The contract stores `secret_commitment = C`. When unlocking:

1. Client generates `proof` for the above statement.
2. Client submits `unlock_message(msg_id, proof, public_inputs)`.
3. Contract calls verifier’s `verify(...)`.
4. If `true`, contract marks message as read, and if `burn_after_read` clears payload.

### Recommended tooling

- **Noir**: write the circuit, compile to a SNARK, generate proof in-browser or server-side.
- **Verifier on Starknet**: deploy a Groth16/Plonk verifier contract (project-specific).

> Practical note: a ready-made, audited Starknet verifier is the hard part. Treat the verifier contract as a separate security-critical dependency. StarkCipher is structured so you can swap verifiers without changing message storage.

### Public input layout (suggestion)

`public_inputs = [secret_commitment, msg_id, to_as_felt, domain_sep]`

Domain separator should be unique per deployment, e.g. Poseidon("STARKCIPHER_V1", chain_id, contract_address).

