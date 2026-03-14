import { hash } from "starknet";

export type AesGcmEncrypted = {
  ciphertext: Uint8Array; // includes GCM tag at end (WebCrypto format)
  nonce: Uint8Array; // 12 bytes
  aad: Uint8Array; // can be empty
};

async function deriveAesKeyFromSecret(secret: string): Promise<CryptoKey> {
  // Production: use PBKDF2/Argon2id with per-chat salt and high iteration count.
  // This demo uses SHA-256(secret) as key material.
  const secretBytes = new TextEncoder().encode(secret);
  const digest = await crypto.subtle.digest("SHA-256", secretBytes);
  return crypto.subtle.importKey("raw", digest, { name: "AES-GCM" }, false, [
    "encrypt",
    "decrypt"
  ]);
}

export async function aesGcmEncrypt(args: {
  plaintext: Uint8Array;
  secret: string;
  aad?: Uint8Array;
}): Promise<AesGcmEncrypted> {
  const key = await deriveAesKeyFromSecret(args.secret);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const aad = args.aad ?? new Uint8Array();

  const ct = await (crypto.subtle as any).encrypt(
    {
      name: "AES-GCM",
      iv: nonce,
      additionalData: aad.byteLength ? aad : undefined,
    },
    key,
    args.plaintext
  );

  return {
    ciphertext: new Uint8Array(ct),
    nonce,
    aad
  };
}

export async function aesGcmDecrypt(args: {
  ciphertext: Uint8Array;
  nonce: Uint8Array;
  aad?: Uint8Array;
  secret: string;
}): Promise<Uint8Array> {
  const key = await deriveAesKeyFromSecret(args.secret);
  const aad = args.aad ?? new Uint8Array();
  const pt = await (crypto.subtle as any).decrypt(
    {
      name: "AES-GCM",
      iv: args.nonce,
      additionalData: aad.byteLength ? aad : undefined,
    },
    key,
    args.ciphertext
  );
  return new Uint8Array(pt);
}

// -------- Starknet-friendly packing helpers --------
// We store byte arrays on-chain as `Array<felt252>` by packing up to 31 bytes per felt.
// (31 bytes keeps the value < 2^248, safely under Cairo felt252 modulus constraints.)

export function packBytesToFelts(bytes: Uint8Array): string[] {
  // Format: [byte_length, chunk0, chunk1, ...] where each chunk packs up to 31 bytes.
  const out: string[] = ["0x" + BigInt(bytes.length).toString(16)];
  for (let i = 0; i < bytes.length; i += 31) {
    const chunk = bytes.slice(i, i + 31);
    let v = 0n;
    for (const b of chunk) v = (v << 8n) + BigInt(b);
    out.push("0x" + v.toString(16));
  }
  return out;
}

export function unpackFeltsToBytes(felts: Array<string | bigint>): Uint8Array {
  if (felts.length === 0) return new Uint8Array();
  const declaredLen = Number(typeof felts[0] === "bigint" ? felts[0] : BigInt(felts[0]));
  const parts: number[] = [];
  for (const f of felts.slice(1)) {
    let v = typeof f === "bigint" ? f : BigInt(f);
    const chunk = new Array<number>(31).fill(0);
    for (let i = 30; i >= 0; i--) {
      chunk[i] = Number(v & 0xffn);
      v >>= 8n;
    }
    parts.push(...chunk);
  }
  return new Uint8Array(parts.slice(0, declaredLen));
}

// -------- Poseidon integrity hashing --------
// Uses starknet.js poseidon implementation to hash felts.

export function poseidonHashFelts(felts: Array<string | bigint>): string {
  const inputs = felts.map((f) => (typeof f === "bigint" ? f : BigInt(f)));
  const h = hash.computePoseidonHashOnElements(inputs);
  return h;
}

