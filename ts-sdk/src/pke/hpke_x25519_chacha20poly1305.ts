// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * HPKE base mode, ciphersuite:
 *   KEM:  DHKEM(X25519, HKDF-SHA256)   (KemId 0x0020)
 *   KDF:  HKDF-SHA256                  (KdfId 0x0001)
 *   AEAD: ChaCha20-Poly1305            (AeadId 0x0003)
 *
 * Classical ~128-bit security. RFC 9180.
 *
 * BCS wire format (no leading scheme byte; the abstract `pke` outer enum prepends it):
 *   EncryptionKey   = [ULEB128(32)] [32B X25519 public key]
 *   DecryptionKey   = [ULEB128(32)] [32B X25519 private key]
 *   Ciphertext      = [ULEB128(32)] [32B enc] [ULEB128(len)] [len B aead_ct]
 *
 * `aead_ct` includes the 16-byte Poly1305 tag.
 */
import { Deserializer, Serializer } from "@aptos-labs/ts-sdk";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import {
    CipherSuite,
    DhkemX25519HkdfSha256,
    HkdfSha256,
} from "@hpke/core";
import { Chacha20Poly1305 } from "@hpke/chacha20poly1305";
import { x25519 } from "@noble/curves/ed25519";
import { Result } from "../result";

const X25519_KEY_BYTES = 32;
const ENCAPSULATED_KEY_BYTES = 32;
const AEAD_TAG_BYTES = 16;

function suite(): CipherSuite {
    return new CipherSuite({
        kem: new DhkemX25519HkdfSha256(),
        kdf: new HkdfSha256(),
        aead: new Chacha20Poly1305(),
    });
}

function assertConsumed(d: Deserializer, label: string): void {
    if (d.remaining() !== 0) throw new Error(`${label}: trailing bytes`);
}

function hexStringToBytes(hex: string): Uint8Array {
    const h = hex.trim();
    return hexToBytes(h.startsWith("0x") || h.startsWith("0X") ? h.slice(2) : h);
}

export class EncryptionKey {
    pk: Uint8Array; // 32B raw X25519 public key

    constructor(pk: Uint8Array) {
        if (pk.length !== X25519_KEY_BYTES) {
            throw new Error(`EncryptionKey: pk must be ${X25519_KEY_BYTES} bytes, got ${pk.length}`);
        }
        this.pk = pk;
    }

    static deserialize(d: Deserializer): Result<EncryptionKey> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => new EncryptionKey(d.deserializeBytes()),
        });
    }

    serialize(s: Serializer): void {
        s.serializeBytes(this.pk);
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
                const ek = EncryptionKey.deserialize(d).unwrapOrThrow("EncryptionKey.fromBytes");
                assertConsumed(d, "EncryptionKey.fromBytes");
                return ek;
            },
        });
    }

    toHex(): string { return bytesToHex(this.toBytes()); }

    static fromHex(hex: string): Result<EncryptionKey> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => EncryptionKey.fromBytes(hexStringToBytes(hex))
                            .unwrapOrThrow("EncryptionKey.fromHex"),
        });
    }
}

export class DecryptionKey {
    sk: Uint8Array; // 32B raw X25519 private key

    constructor(sk: Uint8Array) {
        if (sk.length !== X25519_KEY_BYTES) {
            throw new Error(`DecryptionKey: sk must be ${X25519_KEY_BYTES} bytes, got ${sk.length}`);
        }
        this.sk = sk;
    }

    static deserialize(d: Deserializer): Result<DecryptionKey> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => new DecryptionKey(d.deserializeBytes()),
        });
    }

    serialize(s: Serializer): void {
        s.serializeBytes(this.sk);
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
                const dk = DecryptionKey.deserialize(d).unwrapOrThrow("DecryptionKey.fromBytes");
                assertConsumed(d, "DecryptionKey.fromBytes");
                return dk;
            },
        });
    }

    toHex(): string { return bytesToHex(this.toBytes()); }

    static fromHex(hex: string): Result<DecryptionKey> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => DecryptionKey.fromBytes(hexStringToBytes(hex))
                            .unwrapOrThrow("DecryptionKey.fromHex"),
        });
    }
}

export class Ciphertext {
    enc: Uint8Array;     // 32B encapsulated key (X25519 ephemeral pubkey)
    aeadCt: Uint8Array;  // AEAD ciphertext incl 16B Poly1305 tag

    constructor(enc: Uint8Array, aeadCt: Uint8Array) {
        if (enc.length !== ENCAPSULATED_KEY_BYTES) {
            throw new Error(`Ciphertext: enc must be ${ENCAPSULATED_KEY_BYTES} bytes, got ${enc.length}`);
        }
        if (aeadCt.length < AEAD_TAG_BYTES) {
            throw new Error(`Ciphertext: aeadCt must be >= ${AEAD_TAG_BYTES} bytes (Poly1305 tag), got ${aeadCt.length}`);
        }
        this.enc = enc;
        this.aeadCt = aeadCt;
    }

    static deserialize(d: Deserializer): Result<Ciphertext> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => new Ciphertext(d.deserializeBytes(), d.deserializeBytes()),
        });
    }

    serialize(s: Serializer): void {
        s.serializeBytes(this.enc);
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
                const ct = Ciphertext.deserialize(d).unwrapOrThrow("Ciphertext.fromBytes");
                assertConsumed(d, "Ciphertext.fromBytes");
                return ct;
            },
        });
    }

    toHex(): string { return bytesToHex(this.toBytes()); }

    static fromHex(hex: string): Result<Ciphertext> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => Ciphertext.fromBytes(hexStringToBytes(hex))
                            .unwrapOrThrow("Ciphertext.fromHex"),
        });
    }
}

export async function keygen(): Promise<{ encryptionKey: EncryptionKey; decryptionKey: DecryptionKey }> {
    const s = suite();
    const pair = await s.kem.generateKeyPair();
    const pk = new Uint8Array(await s.kem.serializePublicKey(pair.publicKey));
    const sk = new Uint8Array(await s.kem.serializePrivateKey(pair.privateKey));
    return {
        encryptionKey: new EncryptionKey(pk),
        decryptionKey: new DecryptionKey(sk),
    };
}

/** Derive the public key from a private key via X25519 scalar-base-mult.
 *  HPKE's KEM API has no public-from-private helper, so we use noble's x25519 directly. */
export function deriveEncryptionKey(dk: DecryptionKey): EncryptionKey {
    return new EncryptionKey(x25519.getPublicKey(dk.sk));
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
    const s = suite();
    const recipientPublicKey = await s.kem.deserializePublicKey(encryptionKey.pk);
    const { enc, ct } = await s.seal({ recipientPublicKey }, plaintext, aad);
    return new Ciphertext(new Uint8Array(enc), new Uint8Array(ct));
}

export function decrypt(
    dk: DecryptionKey,
    ciphertext: Ciphertext,
    aad?: Uint8Array,
): Promise<Result<Uint8Array>> {
    return Result.captureAsync({
        recordsExecutionTimeMs: false,
        task: async () => {
            const s = suite();
            const recipientKey = await s.kem.deserializePrivateKey(dk.sk);
            const pt = await s.open(
                { recipientKey, enc: ciphertext.enc },
                ciphertext.aeadCt,
                aad,
            );
            return new Uint8Array(pt);
        },
    });
}
