"use client";

import { useMemo, useState } from "react";
import { useAccount, useConnect, useDisconnect } from "@starknet-react/core";
import { RpcProvider, Contract } from "starknet";
import {
  aesGcmDecrypt,
  aesGcmEncrypt,
  packBytesToFelts,
  unpackFeltsToBytes,
  poseidonHashFelts
} from "@starkcipher/crypto";
import starkcipherAbi from "../starkcipher.abi.json";

type UiMsg = {
  msgId: bigint;
  from: string;
  to: string;
  roomId: string;
  createdAt: number;
  expiresAt: number;
  burnAfterRead: boolean;
  anonymous: boolean;
  ciphertextFelts: string[];
  nonceFelts: string[];
  aadFelts: string[];
  integrityHash: string;
  secretCommitment: string;
  verifier: string;
};

const DEFAULT_RPC = "https://starknet-sepolia.public.blastapi.io";

export default function HomePage() {
  const { address, account, chain } = useAccount();
  const { connect, connectors } = useConnect();
  const { disconnect } = useDisconnect();

  const [contractAddress, setContractAddress] = useState<string>("");
  const [rpcUrl, setRpcUrl] = useState<string>(DEFAULT_RPC);

  const provider = useMemo(() => new RpcProvider({ nodeUrl: rpcUrl }), [rpcUrl]);

  const contract = useMemo(() => {
    if (!contractAddress) return null;
    return new Contract(starkcipherAbi as any, contractAddress, account ?? provider);
  }, [account, provider, contractAddress]);

  // Compose
  const [to, setTo] = useState<string>("");
  const [roomId, setRoomId] = useState<string>("0");
  const [message, setMessage] = useState<string>("");
  const [secret, setSecret] = useState<string>("");
  const [expiresInSec, setExpiresInSec] = useState<string>("3600");
  const [burnAfterRead, setBurnAfterRead] = useState<boolean>(true);
  const [anonymous, setAnonymous] = useState<boolean>(false);
  const [verifier, setVerifier] = useState<string>("0x0");

  // Read
  const [fetchId, setFetchId] = useState<string>("");
  const [fetched, setFetched] = useState<UiMsg | null>(null);
  const [decrypted, setDecrypted] = useState<string>("");

  async function onSend() {
    if (!account) throw new Error("Connect wallet first");
    if (!contract) throw new Error("Set contract address");
    if (!to) throw new Error("Recipient address required");
    if (!message) throw new Error("Message required");
    if (!secret) throw new Error("Secret required");

    const enc = await aesGcmEncrypt({
      plaintext: new TextEncoder().encode(message),
      secret
    });

    const ciphertextFelts = packBytesToFelts(enc.ciphertext);
    const nonceFelts = packBytesToFelts(enc.nonce);
    const aadFelts = packBytesToFelts(enc.aad);

    // NOTE: this is the "integrity binding" value; it’s not a MAC replacement,
    // it’s an on-chain commitment used to detect tampering / mismatched metadata.
    const integrityHash = poseidonHashFelts([
      ...ciphertextFelts,
      ...nonceFelts,
      ...aadFelts
    ]);

    // Minimal secret commitment for the ZK circuit public input.
    // In production: include domain sep, msg_id, recipient, etc.
    const secretCommitment = poseidonHashFelts([poseidonHashFelts(packBytesToFelts(new TextEncoder().encode(secret)))]);

    const nowSec = Math.floor(Date.now() / 1000);
    const exp = expiresInSec.trim() === "0" ? 0 : nowSec + Number(expiresInSec);

    const calldata = [
      to,
      roomId,
      exp,
      burnAfterRead,
      anonymous,
      integrityHash,
      secretCommitment,
      verifier,
      ciphertextFelts,
      nonceFelts,
      aadFelts
    ];

    const tx = await contract.invoke("send_message", calldata as any);
    await provider.waitForTransaction(tx.transaction_hash);
    alert(`Sent. Tx: ${tx.transaction_hash}`);
  }

  async function onFetch() {
    if (!contract) throw new Error("Set contract address");
    const rec = await contract.call("get_message", [fetchId] as any);

    // `starknet.js` returns nested structs; this mapping is intentionally simple.
    const meta = (rec as any).meta;
    const ui: UiMsg = {
      msgId: BigInt(fetchId),
      from: meta.from,
      to: meta.to,
      roomId: meta.room_id,
      createdAt: Number(meta.created_at),
      expiresAt: Number(meta.expires_at),
      burnAfterRead: Boolean(meta.burn_after_read),
      anonymous: Boolean(meta.anonymous),
      ciphertextFelts: (rec as any).ciphertext,
      nonceFelts: (rec as any).nonce,
      aadFelts: (rec as any).aad,
      integrityHash: (rec as any).integrity_hash,
      secretCommitment: (rec as any).secret_commitment,
      verifier: (rec as any).verifier
    };
    setFetched(ui);
    setDecrypted("");
  }

  async function onDecryptLocal() {
    if (!fetched) throw new Error("Fetch a message first");
    if (!secret) throw new Error("Enter secret (same as sender used)");

    const ciphertext = unpackFeltsToBytes(fetched.ciphertextFelts);
    const nonce = unpackFeltsToBytes(fetched.nonceFelts);
    const aad = unpackFeltsToBytes(fetched.aadFelts);

    const pt = await aesGcmDecrypt({ ciphertext, nonce, aad, secret });
    setDecrypted(new TextDecoder().decode(pt));
  }

  async function onUnlockOnchain() {
    if (!account) throw new Error("Connect wallet first");
    if (!contract) throw new Error("Set contract address");
    if (!fetched) throw new Error("Fetch a message first");

    // Placeholder: this is where you generate a ZK proof client-side (Noir/Circom),
    // then submit (proof, public_inputs) to the contract.
    //
    // For now we send empty arrays; contract will reject unless verifier is 0x0
    // (and we intentionally reject verifier==0 in Cairo to avoid unsafe unlocks).
    const proof: string[] = [];
    const publicInputs: string[] = [];

    const tx = await contract.invoke("unlock_message", [fetchId, proof, publicInputs] as any);
    await provider.waitForTransaction(tx.transaction_hash);
    alert(`Unlocked/burned. Tx: ${tx.transaction_hash}`);
  }

  return (
    <main className="container">
      <div style={{ display: "flex", justifyContent: "space-between", gap: 12, flexWrap: "wrap" }}>
        <div>
          <div style={{ fontSize: 24, fontWeight: 650, letterSpacing: "-0.02em" }}>StarkCipher</div>
          <div style={{ color: "var(--muted)", marginTop: 6 }}>
            Encrypted messaging on Starknet (ciphertext only).
          </div>
        </div>
        <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
          {address ? (
            <>
              <span className="pill mono">{address}</span>
              <button className="btn secondary" onClick={() => disconnect()}>
                Disconnect
              </button>
            </>
          ) : (
            <>
              <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                {connectors.map((c) => (
                  <button key={c.id} className="btn" onClick={() => connect({ connector: c })}>
                    Connect {c.name}
                  </button>
                ))}
              </div>
            </>
          )}
        </div>
      </div>

      <div className="row" style={{ marginTop: 18 }}>
        <section className="panel stack">
          <h2>Network</h2>
          <div className="stack">
            <label>
              <div className="pill" style={{ marginBottom: 8 }}>RPC URL</div>
              <input className="input" value={rpcUrl} onChange={(e) => setRpcUrl(e.target.value)} />
            </label>
            <label>
              <div className="pill" style={{ marginBottom: 8 }}>Contract address</div>
              <input
                className="input mono"
                placeholder="0x..."
                value={contractAddress}
                onChange={(e) => setContractAddress(e.target.value)}
              />
            </label>
            <div className="pill">
              <span>Chain</span>
              <span className="mono">{chain?.name ?? "unknown"}</span>
            </div>
          </div>

          <h2 style={{ marginTop: 14 }}>Compose</h2>
          <label>
            <div className="pill" style={{ marginBottom: 8 }}>To (wallet)</div>
            <input className="input mono" placeholder="0x..." value={to} onChange={(e) => setTo(e.target.value)} />
          </label>
          <label>
            <div className="pill" style={{ marginBottom: 8 }}>Room id (0 = direct)</div>
            <input className="input mono" value={roomId} onChange={(e) => setRoomId(e.target.value)} />
          </label>
          <label>
            <div className="pill" style={{ marginBottom: 8 }}>Message</div>
            <textarea className="input" rows={4} value={message} onChange={(e) => setMessage(e.target.value)} />
          </label>
          <label>
            <div className="pill" style={{ marginBottom: 8 }}>Secret code</div>
            <input className="input" value={secret} onChange={(e) => setSecret(e.target.value)} />
          </label>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
            <label>
              <div className="pill" style={{ marginBottom: 8 }}>Expires in (sec, 0=never)</div>
              <input className="input mono" value={expiresInSec} onChange={(e) => setExpiresInSec(e.target.value)} />
            </label>
            <label>
              <div className="pill" style={{ marginBottom: 8 }}>Verifier (ZK)</div>
              <input className="input mono" value={verifier} onChange={(e) => setVerifier(e.target.value)} />
            </label>
          </div>
          <label className="pill" style={{ gap: 10 }}>
            <input type="checkbox" checked={burnAfterRead} onChange={(e) => setBurnAfterRead(e.target.checked)} />
            Burn after read
          </label>
          <label className="pill" style={{ gap: 10 }}>
            <input type="checkbox" checked={anonymous} onChange={(e) => setAnonymous(e.target.checked)} />
            Anonymous UI hint
          </label>
          <button className="btn" onClick={onSend} disabled={!address}>
            Encrypt locally & send on-chain
          </button>

          <div className="warn" style={{ fontSize: 12, marginTop: 4 }}>
            ZK proof generation is scaffolded but not yet wired: see `docs/zk.md`.
          </div>
        </section>

        <section className="panel stack">
          <h2>Read / Unlock</h2>
          <div className="stack">
            <label>
              <div className="pill" style={{ marginBottom: 8 }}>Message id</div>
              <input className="input mono" value={fetchId} onChange={(e) => setFetchId(e.target.value)} />
            </label>
            <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
              <button className="btn secondary" onClick={onFetch}>
                Fetch ciphertext (on-chain)
              </button>
              <button className="btn secondary" onClick={onDecryptLocal} disabled={!fetched}>
                Decrypt locally (no tx)
              </button>
              <button className="btn" onClick={onUnlockOnchain} disabled={!fetched || !address}>
                Submit ZK unlock (tx)
              </button>
            </div>
          </div>

          {fetched ? (
            <div className="msg">
              <div className="meta">
                <span className="mono">msg_id={String(fetched.msgId)}</span>
                <span className="pill mono">to={fetched.to}</span>
              </div>
              <div className="meta" style={{ marginTop: 8 }}>
                <span>created={new Date(fetched.createdAt * 1000).toLocaleString()}</span>
                <span>expires={fetched.expiresAt === 0 ? "never" : new Date(fetched.expiresAt * 1000).toLocaleString()}</span>
                <span>burn={String(fetched.burnAfterRead)}</span>
              </div>
              <div className="body">
                {decrypted ? (
                  decrypted
                ) : (
                  <span style={{ color: "var(--muted)" }}>
                    Ciphertext fetched. Enter secret and click “Decrypt locally”.
                  </span>
                )}
              </div>
            </div>
          ) : (
            <div style={{ color: "var(--muted)", fontSize: 13 }}>
              Fetch a message id to see ciphertext and decrypt locally.
            </div>
          )}
        </section>
      </div>
    </main>
  );
}

