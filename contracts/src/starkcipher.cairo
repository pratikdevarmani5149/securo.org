use starknet::ContractAddress;
use starknet::get_caller_address;
use starknet::get_block_timestamp;
use starknet::storage::{Map, StorageMapReadAccess, StorageMapWriteAccess};

/// StarkCipher: encrypted messaging + expiry + burn-after-read gating with ZK verifier hook.
///
/// Design goals:
/// - Contract stores only ciphertext and metadata (never plaintext).
/// - Per-message expiry timestamp (enforced in reads + state transitions).
/// - Supports deletion after expiry and optional burn-after-read / one-time read.
/// - Optional ZK verifier contract checks proof of knowledge of secret for unlock.
#[starknet::contract]
mod starkcipher {
    use super::*;
    use starknet::syscalls::call_contract_syscall;
    use starknet::SyscallResultTrait;
    use array::ArrayTrait;

    // -----------------------------
    // Types
    // -----------------------------

    #[derive(Copy, Drop, Serde)]
    struct MsgMeta {
        from: ContractAddress,
        to: ContractAddress,
        room_id: felt252,        // 0 for direct messages; nonzero for temporary rooms
        created_at: u64,
        expires_at: u64,         // 0 => never expires
        burn_after_read: bool,
        anonymous: bool,         // if true, `from` still stored but UI should not show it
        read: bool,              // becomes true when unlocked (for one-time read semantics)
        deleted: bool,           // true when message payload is cleared
    }

    #[derive(Copy, Drop, Serde)]
    struct MsgRecord {
        meta: MsgMeta,
        /// Poseidon hash commitment binding: (ciphertext, nonce, aad, meta fields, secret commitment)
        integrity_hash: felt252,
        /// Commitment to secret (e.g., Poseidon(secret, msg_id, to, domain_sep)).
        secret_commitment: felt252,
        /// Optional verifier contract. If 0 address, unlock uses no verifier (not recommended).
        verifier: ContractAddress,
        /// Encrypted payload split into felts (e.g., packed bytes in UI).
        ciphertext: Array<felt252>,
        /// AES-GCM nonce (12 bytes packed into a felt or multiple felts).
        nonce: Array<felt252>,
        /// Optional additional authenticated data (AAD) packed into felts.
        aad: Array<felt252>,
    }

    // -----------------------------
    // Storage
    // -----------------------------

    #[storage]
    struct Storage {
        next_msg_id: u64,
        // msg_id -> MsgRecord (stored as flattened fields for Cairo storage constraints)
        meta: Map<u64, MsgMeta>,
        integrity_hash: Map<u64, felt252>,
        secret_commitment: Map<u64, felt252>,
        verifier: Map<u64, ContractAddress>,
        ciphertext: Map<(u64, u32), felt252>,
        ciphertext_len: Map<u64, u32>,
        nonce: Map<(u64, u32), felt252>,
        nonce_len: Map<u64, u32>,
        aad: Map<(u64, u32), felt252>,
        aad_len: Map<u64, u32>,
    }

    // -----------------------------
    // Events
    // -----------------------------

    #[event]
    enum Event {
        MessageSent: MessageSent,
        MessageUnlocked: MessageUnlocked,
        MessageDeleted: MessageDeleted,
    }

    #[derive(Drop, starknet::Event)]
    struct MessageSent {
        #[key]
        msg_id: u64,
        #[key]
        to: ContractAddress,
        #[key]
        room_id: felt252,
        from: ContractAddress,
        expires_at: u64,
        burn_after_read: bool,
        anonymous: bool,
        integrity_hash: felt252,
        secret_commitment: felt252,
        verifier: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct MessageUnlocked {
        #[key]
        msg_id: u64,
        #[key]
        to: ContractAddress,
        by: ContractAddress,
        burned: bool,
    }

    #[derive(Drop, starknet::Event)]
    struct MessageDeleted {
        #[key]
        msg_id: u64,
        #[key]
        to: ContractAddress,
        by: ContractAddress,
        reason: felt252, // "expiry" | "burn" | "sender" (use felt strings off-chain)
    }

    // -----------------------------
    // Verifier interface
    // -----------------------------

    // Expected verifier entrypoint:
    // fn verify(proof: Array<felt252>, public_inputs: Array<felt252>) -> bool
    //
    // Public inputs should at minimum include:
    // - secret_commitment
    // - msg_id
    // - to (as felt)
    // - domain separator
    fn verify_with_verifier(
        verifier: ContractAddress,
        proof: Array<felt252>,
        public_inputs: Array<felt252>,
    ) -> bool {
        // If verifier is 0, treat as "no verifier configured"
        if verifier == ContractAddress::from(0) {
            return false;
        }

        let mut calldata: Array<felt252> = ArrayTrait::new();
        // Encode dynamic arrays as: len, ...items (common Starknet ABI).
        calldata.append(proof.len().into());
        let mut i = 0;
        loop {
            if i == proof.len() { break; }
            calldata.append(*proof.at(i));
            i += 1;
        };

        calldata.append(public_inputs.len().into());
        let mut j = 0;
        loop {
            if j == public_inputs.len() { break; }
            calldata.append(*public_inputs.at(j));
            j += 1;
        };

        let (retdata,) = call_contract_syscall(
            verifier,
            selector!("verify"),
            calldata.span(),
        ).unwrap_syscall();

        // Expect single felt result 0/1.
        if retdata.len() != 1 { return false; }
        *retdata.at(0) != 0
    }

    // -----------------------------
    // Helpers
    // -----------------------------

    fn is_expired(expires_at: u64) -> bool {
        if expires_at == 0 { return false; }
        get_block_timestamp() >= expires_at
    }

    fn clear_payload(ref self: ContractState, msg_id: u64) {
        let clen = self.ciphertext_len.read(msg_id);
        let mut i: u32 = 0;
        loop {
            if i == clen { break; }
            self.ciphertext.write((msg_id, i), 0);
            i += 1;
        };
        self.ciphertext_len.write(msg_id, 0);

        let nlen = self.nonce_len.read(msg_id);
        let mut j: u32 = 0;
        loop {
            if j == nlen { break; }
            self.nonce.write((msg_id, j), 0);
            j += 1;
        };
        self.nonce_len.write(msg_id, 0);

        let alen = self.aad_len.read(msg_id);
        let mut k: u32 = 0;
        loop {
            if k == alen { break; }
            self.aad.write((msg_id, k), 0);
            k += 1;
        };
        self.aad_len.write(msg_id, 0);
    }

    // -----------------------------
    // External interface
    // -----------------------------

    #[abi(embed_v0)]
    impl StarkCipher of super::starkcipher::StarkCipherTrait {
        /// Send an encrypted message to a wallet or room.
        ///
        /// `ciphertext`, `nonce`, `aad` must be produced client-side from AES-GCM.
        /// `integrity_hash` is a Poseidon hash binding payload+metadata for tamper detection (client-side).
        /// `secret_commitment` is a Poseidon hash commitment used by ZK unlock.
        fn send_message(
            ref self: ContractState,
            to: ContractAddress,
            room_id: felt252,
            expires_at: u64,
            burn_after_read: bool,
            anonymous: bool,
            integrity_hash: felt252,
            secret_commitment: felt252,
            verifier: ContractAddress,
            ciphertext: Array<felt252>,
            nonce: Array<felt252>,
            aad: Array<felt252>,
        ) -> u64 {
            let from = get_caller_address();
            let created_at = get_block_timestamp();
            if expires_at != 0 {
                assert(expires_at > created_at, 'bad_expiry');
            }
            assert(ciphertext.len() > 0, 'empty_ct');
            assert(nonce.len() > 0, 'empty_nonce');

            let msg_id = self.next_msg_id.read();
            self.next_msg_id.write(msg_id + 1);

            let meta = MsgMeta {
                from,
                to,
                room_id,
                created_at,
                expires_at,
                burn_after_read,
                anonymous,
                read: false,
                deleted: false,
            };
            self.meta.write(msg_id, meta);
            self.integrity_hash.write(msg_id, integrity_hash);
            self.secret_commitment.write(msg_id, secret_commitment);
            self.verifier.write(msg_id, verifier);

            // Persist ciphertext
            self.ciphertext_len.write(msg_id, ciphertext.len());
            let mut i: u32 = 0;
            loop {
                if i == ciphertext.len() { break; }
                self.ciphertext.write((msg_id, i), *ciphertext.at(i));
                i += 1;
            };

            // Persist nonce
            self.nonce_len.write(msg_id, nonce.len());
            let mut j: u32 = 0;
            loop {
                if j == nonce.len() { break; }
                self.nonce.write((msg_id, j), *nonce.at(j));
                j += 1;
            };

            // Persist aad
            self.aad_len.write(msg_id, aad.len());
            let mut k: u32 = 0;
            loop {
                if k == aad.len() { break; }
                self.aad.write((msg_id, k), *aad.at(k));
                k += 1;
            };

            self.emit(Event::MessageSent(MessageSent {
                msg_id,
                to,
                room_id,
                from,
                expires_at,
                burn_after_read,
                anonymous,
                integrity_hash,
                secret_commitment,
                verifier,
            }));
            msg_id
        }

        /// Read metadata and encrypted payload for a message.
        /// The contract NEVER decrypts; frontends decrypt locally.
        fn get_message(ref self: ContractState, msg_id: u64) -> MsgRecord {
            let meta = self.meta.read(msg_id);
            assert(!meta.deleted, 'deleted');
            assert(!is_expired(meta.expires_at), 'expired');

            let clen = self.ciphertext_len.read(msg_id);
            let mut ct: Array<felt252> = ArrayTrait::new();
            let mut i: u32 = 0;
            loop {
                if i == clen { break; }
                ct.append(self.ciphertext.read((msg_id, i)));
                i += 1;
            };

            let nlen = self.nonce_len.read(msg_id);
            let mut nn: Array<felt252> = ArrayTrait::new();
            let mut j: u32 = 0;
            loop {
                if j == nlen { break; }
                nn.append(self.nonce.read((msg_id, j)));
                j += 1;
            };

            let alen = self.aad_len.read(msg_id);
            let mut aa: Array<felt252> = ArrayTrait::new();
            let mut k: u32 = 0;
            loop {
                if k == alen { break; }
                aa.append(self.aad.read((msg_id, k)));
                k += 1;
            };

            MsgRecord {
                meta,
                integrity_hash: self.integrity_hash.read(msg_id),
                secret_commitment: self.secret_commitment.read(msg_id),
                verifier: self.verifier.read(msg_id),
                ciphertext: ct,
                nonce: nn,
                aad: aa,
            }
        }

        /// Unlock a message by presenting a ZK proof of knowledge of the secret.
        ///
        /// If `burn_after_read` is true, the payload is cleared immediately (burn-on-unlock).
        /// Otherwise, `meta.read` is set and the UI can treat it as "one-time read".
        fn unlock_message(
            ref self: ContractState,
            msg_id: u64,
            proof: Array<felt252>,
            public_inputs: Array<felt252>,
        ) {
            let mut meta = self.meta.read(msg_id);
            assert(!meta.deleted, 'deleted');
            assert(!is_expired(meta.expires_at), 'expired');

            let caller = get_caller_address();
            // For direct messages, only recipient can unlock.
            // For rooms, UIs can use `room_id` + off-chain membership proofs;
            // on-chain we still require caller == `to` for simplicity.
            assert(caller == meta.to, 'not_recipient');
            assert(!meta.read, 'already_read');

            let verifier = self.verifier.read(msg_id);
            let ok = verify_with_verifier(verifier, proof, public_inputs);
            assert(ok, 'bad_proof');

            meta.read = true;
            self.meta.write(msg_id, meta);

            let mut burned = false;
            if meta.burn_after_read {
                burned = true;
                clear_payload(self, msg_id);
                meta.deleted = true;
                self.meta.write(msg_id, meta);
                self.emit(Event::MessageDeleted(MessageDeleted {
                    msg_id,
                    to: meta.to,
                    by: caller,
                    reason: 'burn',
                }));
            }

            self.emit(Event::MessageUnlocked(MessageUnlocked {
                msg_id,
                to: meta.to,
                by: caller,
                burned,
            }));
        }

        /// Delete a message after expiry (anyone can trigger), or sender can delete anytime.
        fn delete_message(ref self: ContractState, msg_id: u64) {
            let mut meta = self.meta.read(msg_id);
            assert(!meta.deleted, 'deleted');
            let caller = get_caller_address();

            let expired = is_expired(meta.expires_at);
            let sender = caller == meta.from;
            assert(expired || sender, 'not_allowed');

            clear_payload(self, msg_id);
            meta.deleted = true;
            self.meta.write(msg_id, meta);

            let reason = if expired { 'expiry' } else { 'sender' };
            self.emit(Event::MessageDeleted(MessageDeleted {
                msg_id,
                to: meta.to,
                by: caller,
                reason,
            }));
        }

        fn get_next_msg_id(self: @ContractState) -> u64 {
            self.next_msg_id.read()
        }
    }

    #[generate_trait]
    trait StarkCipherTrait {
        fn send_message(
            ref self: ContractState,
            to: ContractAddress,
            room_id: felt252,
            expires_at: u64,
            burn_after_read: bool,
            anonymous: bool,
            integrity_hash: felt252,
            secret_commitment: felt252,
            verifier: ContractAddress,
            ciphertext: Array<felt252>,
            nonce: Array<felt252>,
            aad: Array<felt252>,
        ) -> u64;
        fn get_message(ref self: ContractState, msg_id: u64) -> MsgRecord;
        fn unlock_message(
            ref self: ContractState,
            msg_id: u64,
            proof: Array<felt252>,
            public_inputs: Array<felt252>,
        );
        fn delete_message(ref self: ContractState, msg_id: u64);
        fn get_next_msg_id(self: @ContractState) -> u64;
    }
}

