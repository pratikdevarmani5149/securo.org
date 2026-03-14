## StarkCipher

Decentralized encrypted messaging on Starknet:

- **On-chain**: only encrypted payloads + metadata (expiry/burn flags + integrity hash).
- **Off-chain (client-side)**: AES-GCM encryption/decryption, Poseidon integrity hashing.
- **ZK unlock**: user proves knowledge of a secret *without revealing it*; proof is verified on-chain to allow one-time read / burn-after-read.

### Repo layout

```text
starkcipher/
  contracts/                # Cairo (Scarb) smart contracts
  apps/
    web/                    # Next.js frontend (starknet-react)
  packages/
    crypto/                 # Shared JS crypto helpers (AES-GCM + Poseidon)
```

### Quick start (dev)

Prereqs:
- Node.js 18+ (or 20+)
- Scarb (Cairo toolchain)

Contracts:
```bash
cd contracts
scarb build
```

Web:
```bash
cd apps/web
npm install
npm run dev
```

> Deployment + verifier setup notes are in `docs/` (created below).

