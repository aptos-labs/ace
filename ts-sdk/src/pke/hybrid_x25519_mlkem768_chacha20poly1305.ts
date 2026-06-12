// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Hybrid PKE for long-lived on-chain share transport:
 *   inner: HPKE-X25519-HKDF-SHA256-ChaCha20Poly1305
 *   outer: ML-KEM-768 shared secret -> HKDF-SHA256 -> ChaCha20-Poly1305
 *
 * BCS wire format (no leading scheme byte; the abstract `pke` outer enum prepends it):
 *   EncryptionKey = HpkeEncryptionKey || [ULEB128(1184)] [1184B ML-KEM ek]
 *   DecryptionKey = HpkeDecryptionKey || [ULEB128(64)]   [64B ML-KEM seed]
 *   Ciphertext    = [ULEB128(1088)] [1088B ML-KEM ct]
 *                   [ULEB128(12)]   [12B nonce]
 *                   [ULEB128(len)]  [len B outer AEAD ct]
 */
import { Deserializer, Serializer } from "@aptos-labs/ts-sdk";
import { chacha20poly1305 } from "@noble/ciphers/chacha";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex, concatBytes, hexToBytes } from "@noble/hashes/utils";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { randomBytes } from "@noble/post-quantum/utils.js";
import { Result } from "../result";
import * as HpkeX25519ChaCha20Poly1305 from "./hpke_x25519_chacha20poly1305";

const MLKEM768_EK_BYTES = 1184;
const MLKEM768_DK_SEED_BYTES = 64;
const MLKEM768_CT_BYTES = 1088;
const AEAD_KEY_BYTES = 32;
const AEAD_NONCE_BYTES = 12;
const AEAD_TAG_BYTES = 16;
const HKDF_SALT = new TextEncoder().encode(
    "ACE-PKE-HYBRID-X25519-MLKEM768-CHACHA20POLY1305/v0",
);

function assertConsumed(d: Deserializer, label: string): void {
    if (d.remaining() !== 0) throw new Error(`${label}: trailing bytes`);
}

function hexStringToBytes(hex: string): Uint8Array {
    const h = hex.trim();
    return hexToBytes(h.startsWith("0x") || h.startsWith("0X") ? h.slice(2) : h);
}

function le64(n: number): Uint8Array {
    if (!Number.isSafeInteger(n) || n < 0) {
        throw new Error(`le64: invalid length ${n}`);
    }
    const out = new Uint8Array(8);
    let x = BigInt(n);
    for (let i = 0; i < out.length; i++) {
        out[i] = Number(x & 0xffn);
        x >>= 8n;
    }
    return out;
}

function deriveOuterKey(sharedSecret: Uint8Array, mlkemCt: Uint8Array, aad: Uint8Array): Uint8Array {
    const info = concatBytes(HKDF_SALT, le64(mlkemCt.length), mlkemCt, le64(aad.length), aad);
    return hkdf(sha256, sharedSecret, HKDF_SALT, info, AEAD_KEY_BYTES);
}

export class EncryptionKey {
    hpkeX25519: HpkeX25519ChaCha20Poly1305.EncryptionKey;
    mlkem768Ek: Uint8Array;

    constructor(
        hpkeX25519: HpkeX25519ChaCha20Poly1305.EncryptionKey,
        mlkem768Ek: Uint8Array,
    ) {
        if (mlkem768Ek.length !== MLKEM768_EK_BYTES) {
            throw new Error(`EncryptionKey: mlkem768Ek must be ${MLKEM768_EK_BYTES} bytes, got ${mlkem768Ek.length}`);
        }
        this.hpkeX25519 = hpkeX25519;
        this.mlkem768Ek = mlkem768Ek;
    }

    static deserialize(d: Deserializer): Result<EncryptionKey> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const hpkeX25519 = HpkeX25519ChaCha20Poly1305.EncryptionKey.deserialize(d)
                    .unwrapOrThrow("Hybrid EncryptionKey.deserialize: HPKE-X25519");
                return new EncryptionKey(hpkeX25519, d.deserializeBytes());
            },
        });
    }

    serialize(s: Serializer): void {
        this.hpkeX25519.serialize(s);
        s.serializeBytes(this.mlkem768Ek);
    }

    toBytes(): Uint8Array {
        const s = new Serializer();
        this.serialize(s);
        return s.toUint8Array();
    }

    static fromBytes(bytes: Uint8Array): Result<EncryptionKey> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const d = new Deserializer(bytes);
                const ek = EncryptionKey.deserialize(d).unwrapOrThrow("Hybrid EncryptionKey.fromBytes");
                assertConsumed(d, "Hybrid EncryptionKey.fromBytes");
                return ek;
            },
        });
    }

    toHex(): string { return bytesToHex(this.toBytes()); }

    static fromHex(hex: string): Result<EncryptionKey> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => EncryptionKey.fromBytes(hexStringToBytes(hex))
                .unwrapOrThrow("Hybrid EncryptionKey.fromHex"),
        });
    }
}

export class DecryptionKey {
    hpkeX25519: HpkeX25519ChaCha20Poly1305.DecryptionKey;
    mlkem768Seed: Uint8Array;

    constructor(
        hpkeX25519: HpkeX25519ChaCha20Poly1305.DecryptionKey,
        mlkem768Seed: Uint8Array,
    ) {
        if (mlkem768Seed.length !== MLKEM768_DK_SEED_BYTES) {
            throw new Error(`DecryptionKey: mlkem768Seed must be ${MLKEM768_DK_SEED_BYTES} bytes, got ${mlkem768Seed.length}`);
        }
        this.hpkeX25519 = hpkeX25519;
        this.mlkem768Seed = mlkem768Seed;
    }

    static deserialize(d: Deserializer): Result<DecryptionKey> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const hpkeX25519 = HpkeX25519ChaCha20Poly1305.DecryptionKey.deserialize(d)
                    .unwrapOrThrow("Hybrid DecryptionKey.deserialize: HPKE-X25519");
                return new DecryptionKey(hpkeX25519, d.deserializeBytes());
            },
        });
    }

    serialize(s: Serializer): void {
        this.hpkeX25519.serialize(s);
        s.serializeBytes(this.mlkem768Seed);
    }

    toBytes(): Uint8Array {
        const s = new Serializer();
        this.serialize(s);
        return s.toUint8Array();
    }

    static fromBytes(bytes: Uint8Array): Result<DecryptionKey> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const d = new Deserializer(bytes);
                const dk = DecryptionKey.deserialize(d).unwrapOrThrow("Hybrid DecryptionKey.fromBytes");
                assertConsumed(d, "Hybrid DecryptionKey.fromBytes");
                return dk;
            },
        });
    }

    toHex(): string { return bytesToHex(this.toBytes()); }

    static fromHex(hex: string): Result<DecryptionKey> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => DecryptionKey.fromBytes(hexStringToBytes(hex))
                .unwrapOrThrow("Hybrid DecryptionKey.fromHex"),
        });
    }
}

export class Ciphertext {
    mlkem768Ct: Uint8Array;
    aeadNonce: Uint8Array;
    aeadCt: Uint8Array;

    constructor(mlkem768Ct: Uint8Array, aeadNonce: Uint8Array, aeadCt: Uint8Array) {
        if (mlkem768Ct.length !== MLKEM768_CT_BYTES) {
            throw new Error(`Ciphertext: mlkem768Ct must be ${MLKEM768_CT_BYTES} bytes, got ${mlkem768Ct.length}`);
        }
        if (aeadNonce.length !== AEAD_NONCE_BYTES) {
            throw new Error(`Ciphertext: aeadNonce must be ${AEAD_NONCE_BYTES} bytes, got ${aeadNonce.length}`);
        }
        if (aeadCt.length < AEAD_TAG_BYTES) {
            throw new Error(`Ciphertext: aeadCt must be >= ${AEAD_TAG_BYTES} bytes, got ${aeadCt.length}`);
        }
        this.mlkem768Ct = mlkem768Ct;
        this.aeadNonce = aeadNonce;
        this.aeadCt = aeadCt;
    }

    static deserialize(d: Deserializer): Result<Ciphertext> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => new Ciphertext(d.deserializeBytes(), d.deserializeBytes(), d.deserializeBytes()),
        });
    }

    serialize(s: Serializer): void {
        s.serializeBytes(this.mlkem768Ct);
        s.serializeBytes(this.aeadNonce);
        s.serializeBytes(this.aeadCt);
    }

    toBytes(): Uint8Array {
        const s = new Serializer();
        this.serialize(s);
        return s.toUint8Array();
    }

    static fromBytes(bytes: Uint8Array): Result<Ciphertext> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const d = new Deserializer(bytes);
                const ct = Ciphertext.deserialize(d).unwrapOrThrow("Hybrid Ciphertext.fromBytes");
                assertConsumed(d, "Hybrid Ciphertext.fromBytes");
                return ct;
            },
        });
    }

    toHex(): string { return bytesToHex(this.toBytes()); }

    static fromHex(hex: string): Result<Ciphertext> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => Ciphertext.fromBytes(hexStringToBytes(hex))
                .unwrapOrThrow("Hybrid Ciphertext.fromHex"),
        });
    }
}

export async function keygen(): Promise<{ encryptionKey: EncryptionKey; decryptionKey: DecryptionKey }> {
    const { encryptionKey: hpkeEk, decryptionKey: hpkeDk } =
        await HpkeX25519ChaCha20Poly1305.keygen();
    const mlkem768Seed = randomBytes(MLKEM768_DK_SEED_BYTES);
    const mlkemKeys = ml_kem768.keygen(mlkem768Seed);
    return {
        encryptionKey: new EncryptionKey(hpkeEk, mlkemKeys.publicKey),
        decryptionKey: new DecryptionKey(hpkeDk, mlkem768Seed),
    };
}

export function deriveEncryptionKey(dk: DecryptionKey): EncryptionKey {
    const hpkeEk = HpkeX25519ChaCha20Poly1305.deriveEncryptionKey(dk.hpkeX25519);
    const mlkemKeys = ml_kem768.keygen(dk.mlkem768Seed);
    return new EncryptionKey(hpkeEk, mlkemKeys.publicKey);
}

export async function encrypt({
    encryptionKey,
    plaintext,
    aad,
}: {
    encryptionKey: EncryptionKey;
    plaintext: Uint8Array;
    aad?: Uint8Array;
}): Promise<Ciphertext> {
    const innerHpkeCt = await HpkeX25519ChaCha20Poly1305.encrypt({
        encryptionKey: encryptionKey.hpkeX25519,
        plaintext,
        aad,
    });
    const innerHpkeBytes = innerHpkeCt.toBytes();
    const { cipherText: mlkem768Ct, sharedSecret } = ml_kem768.encapsulate(encryptionKey.mlkem768Ek);
    const context = aad ?? new Uint8Array();
    const key = deriveOuterKey(sharedSecret, mlkem768Ct, context);
    const nonce = randomBytes(AEAD_NONCE_BYTES);
    const aeadCt = chacha20poly1305(key, nonce, context).encrypt(innerHpkeBytes);
    return new Ciphertext(mlkem768Ct, nonce, aeadCt);
}

export function decrypt(
    dk: DecryptionKey,
    ciphertext: Ciphertext,
    aad?: Uint8Array,
): Promise<Result<Uint8Array>> {
    return Result.captureAsync({
        recordsExecutionTimeMs: false,
        task: async () => {
            const mlkemKeys = ml_kem768.keygen(dk.mlkem768Seed);
            const sharedSecret = ml_kem768.decapsulate(ciphertext.mlkem768Ct, mlkemKeys.secretKey);
            const context = aad ?? new Uint8Array();
            const key = deriveOuterKey(sharedSecret, ciphertext.mlkem768Ct, context);
            const innerHpkeBytes = chacha20poly1305(key, ciphertext.aeadNonce, context)
                .decrypt(ciphertext.aeadCt);
            const innerHpkeCt = HpkeX25519ChaCha20Poly1305.Ciphertext.fromBytes(innerHpkeBytes)
                .unwrapOrThrow("Hybrid decrypt: parse inner HPKE ciphertext");
            const pt = await HpkeX25519ChaCha20Poly1305.decrypt(dk.hpkeX25519, innerHpkeCt, aad);
            return pt.unwrapOrThrow("Hybrid decrypt: inner HPKE open failed");
        },
    });
}
