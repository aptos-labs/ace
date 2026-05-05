// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Boneh-Franklin IBE over BLS12-381, "shortsig" variant ("minimal-signature-size"
 * convention from draft-irtf-cfrg-bls-signature):
 *
 * - Master public key in G2.
 * - Identity hashed to G1 (Q_id ∈ G1, 48 bytes compressed).
 * - Identity decryption key share in G1 (s_i · Q_id, 48 bytes compressed).
 * - Ciphertext c0 in G2 (96 bytes compressed).
 *
 * DEM: HKDF-SHA256 → ChaCha20-Poly1305 AEAD (matching the HPKE-X25519 PKE).
 *
 * In threshold mode, IDK shares are combined by Lagrange interpolation in G1 at x=0
 * to recover the full identity decryption key, after which BF-IBE decrypt proceeds.
 *
 * Compared with the existing `bfibe-bls12381-shortpk-otp-hmac`:
 *  - Group flip: master pk + c0 swap from G1 → G2; identity hash + IDK share swap
 *    from G2 → G1. This makes per-decryption shares 48 bytes instead of 96 bytes
 *    and aligns with the BLS-signature convention used by drand/tlock.
 *  - DEM upgrade: hand-rolled OTP + HMAC-SHA3-256 → standard HKDF-SHA256 keying
 *    a ChaCha20-Poly1305 AEAD. Same primitive set as the HPKE-X25519 PKE.
 */

import { Deserializer, Serializer } from "@aptos-labs/ts-sdk";
import { Fp2 } from "@noble/curves/abstract/tower";
import { WeierstrassPoint } from "@noble/curves/abstract/weierstrass";
import { bls12_381 } from "@noble/curves/bls12-381";
import { bytesToNumberBE, bytesToNumberLE, numberToBytesLE } from "@noble/curves/utils";
import { bytesToHex, hexToBytes, randomBytes } from "@noble/hashes/utils";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha2";
import { chacha20poly1305 } from "@noble/ciphers/chacha";
import { frMod, frMul, frInv } from "../group/bls12381fr";
import { Result } from "../result";

const DST_HASH_ID_TO_CURVE = new TextEncoder().encode(
    "BONEH_FRANKLIN_BLS12381_SHORTSIG_AEAD/HASH_ID_TO_CURVE",
);
const DST_KDF = new TextEncoder().encode("BONEH_FRANKLIN_BLS12381_SHORTSIG_AEAD/KDF");

const AEAD_KEY_BYTES = 32;
const AEAD_NONCE_BYTES = 12;
const AEAD_TAG_BYTES = 16;

// ── MasterPublicKey ──────────────────────────────────────────────────────────

export class MasterPublicKey {
    basePoint: WeierstrassPoint<Fp2>; // G2
    pk: WeierstrassPoint<Fp2>;        // G2 (= s · basePoint)

    constructor(basePoint: WeierstrassPoint<Fp2>, pk: WeierstrassPoint<Fp2>) {
        this.basePoint = basePoint;
        this.pk = pk;
    }

    static deserialize(deserializer: Deserializer): Result<MasterPublicKey> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const baseBytes = deserializer.deserializeBytes();
                const base = bls12_381.G2.Point.fromBytes(baseBytes) as unknown as WeierstrassPoint<Fp2>;
                const pkBytes = deserializer.deserializeBytes();
                const pk = bls12_381.G2.Point.fromBytes(pkBytes) as unknown as WeierstrassPoint<Fp2>;
                return new MasterPublicKey(base, pk);
            },
        });
    }

    serialize(serializer: Serializer): void {
        serializer.serializeBytes((this.basePoint as any).toBytes());
        serializer.serializeBytes((this.pk as any).toBytes());
    }

    static fromBytes(bytes: Uint8Array): Result<MasterPublicKey> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const d = new Deserializer(bytes);
                const ek = MasterPublicKey.deserialize(d).unwrapOrThrow("MasterPublicKey.fromBytes");
                if (d.remaining() !== 0) throw "MasterPublicKey.fromBytes: trailing bytes";
                return ek;
            },
        });
    }

    static fromHex(hex: string): Result<MasterPublicKey> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => MasterPublicKey.fromBytes(hexToBytes(hex)).unwrapOrThrow("MasterPublicKey.fromHex"),
        });
    }

    toBytes(): Uint8Array {
        const s = new Serializer();
        this.serialize(s);
        return s.toUint8Array();
    }

    toHex(): string { return bytesToHex(this.toBytes()); }
}

// ── MasterPrivateKey ─────────────────────────────────────────────────────────

export class MasterPrivateKey {
    base: WeierstrassPoint<Fp2>; // G2
    scalar: bigint;

    constructor(base: WeierstrassPoint<Fp2>, scalar: bigint) {
        this.base = base;
        this.scalar = scalar;
    }

    static deserialize(deserializer: Deserializer): Result<MasterPrivateKey> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const baseBytes = deserializer.deserializeBytes();
                const base = bls12_381.G2.Point.fromBytes(baseBytes) as unknown as WeierstrassPoint<Fp2>;
                const scalarBytes = deserializer.deserializeBytes();
                const scalar = bytesToNumberLE(scalarBytes);
                return new MasterPrivateKey(base, scalar);
            },
        });
    }

    serialize(serializer: Serializer): void {
        serializer.serializeBytes((this.base as any).toBytes());
        serializer.serializeBytes(numberToBytesLE(this.scalar, 32));
    }

    static fromBytes(bytes: Uint8Array): Result<MasterPrivateKey> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const d = new Deserializer(bytes);
                const dk = MasterPrivateKey.deserialize(d).unwrapOrThrow("MasterPrivateKey.fromBytes");
                if (d.remaining() !== 0) throw "MasterPrivateKey.fromBytes: trailing bytes";
                return dk;
            },
        });
    }

    static fromHex(hex: string): Result<MasterPrivateKey> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => MasterPrivateKey.fromBytes(hexToBytes(hex)).unwrapOrThrow("MasterPrivateKey.fromHex"),
        });
    }

    toBytes(): Uint8Array {
        const s = new Serializer();
        this.serialize(s);
        return s.toUint8Array();
    }

    toHex(): string { return bytesToHex(this.toBytes()); }
}

// ── IdentityDecryptionKeyShare ───────────────────────────────────────────────

export class IdentityDecryptionKeyShare {
    evalPoint: bigint;
    idkShare: WeierstrassPoint<bigint>; // G1 — this is the "minimal-signature-size" object
    proof: Uint8Array | undefined;

    constructor(evalPoint: bigint, idkShare: WeierstrassPoint<bigint>, proof: Uint8Array | undefined) {
        this.evalPoint = evalPoint;
        this.idkShare = idkShare;
        this.proof = proof;
    }

    serialize(serializer: Serializer): void {
        serializer.serializeBytes(numberToBytesLE(this.evalPoint, 32));
        serializer.serializeBytes((this.idkShare as any).toBytes());
        serializer.serializeU8(this.proof !== undefined ? 1 : 0);
        if (this.proof !== undefined) {
            serializer.serializeBytes(this.proof);
        }
    }

    static deserialize(deserializer: Deserializer): Result<IdentityDecryptionKeyShare> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const evalPointBytes = deserializer.deserializeBytes();
                if (evalPointBytes.length !== 32) throw "IdentityDecryptionKeyShare: expected 32-byte evalPoint";
                const evalPoint = bytesToNumberLE(evalPointBytes);
                const idkShareBytes = deserializer.deserializeBytes();
                const idkShare = bls12_381.G1.Point.fromBytes(idkShareBytes) as unknown as WeierstrassPoint<bigint>;
                const hasProof = deserializer.deserializeU8() !== 0;
                const proof = hasProof ? deserializer.deserializeBytes() : undefined;
                return new IdentityDecryptionKeyShare(evalPoint, idkShare, proof);
            },
        });
    }

    static fromBytes(bytes: Uint8Array): Result<IdentityDecryptionKeyShare> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const d = new Deserializer(bytes);
                const o = IdentityDecryptionKeyShare.deserialize(d).unwrapOrThrow("IdentityDecryptionKeyShare.fromBytes");
                if (d.remaining() !== 0) throw "IdentityDecryptionKeyShare.fromBytes: trailing bytes";
                return o;
            },
        });
    }

    static fromHex(hex: string): Result<IdentityDecryptionKeyShare> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => IdentityDecryptionKeyShare.fromBytes(hexToBytes(hex)).unwrapOrThrow("IdentityDecryptionKeyShare.fromHex"),
        });
    }

    toBytes(): Uint8Array {
        const s = new Serializer();
        this.serialize(s);
        return s.toUint8Array();
    }

    toHex(): string { return bytesToHex(this.toBytes()); }
}

// ── Ciphertext ───────────────────────────────────────────────────────────────

export class Ciphertext {
    c0: WeierstrassPoint<Fp2>; // G2
    aeadCt: Uint8Array;        // ChaCha20-Poly1305 ct || 16-byte tag

    constructor(c0: WeierstrassPoint<Fp2>, aeadCt: Uint8Array) {
        this.c0 = c0;
        if (aeadCt.length < AEAD_TAG_BYTES) {
            throw `Ciphertext: aeadCt must be >= ${AEAD_TAG_BYTES} bytes (Poly1305 tag), got ${aeadCt.length}`;
        }
        this.aeadCt = aeadCt;
    }

    static deserialize(deserializer: Deserializer): Result<Ciphertext> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const c0Bytes = deserializer.deserializeBytes();
                const c0 = bls12_381.G2.Point.fromBytes(c0Bytes) as unknown as WeierstrassPoint<Fp2>;
                const aeadCt = deserializer.deserializeBytes();
                return new Ciphertext(c0, aeadCt);
            },
        });
    }

    serialize(serializer: Serializer): void {
        serializer.serializeBytes((this.c0 as any).toBytes());
        serializer.serializeBytes(this.aeadCt);
    }

    static fromBytes(bytes: Uint8Array): Result<Ciphertext> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const d = new Deserializer(bytes);
                const c = Ciphertext.deserialize(d).unwrapOrThrow("Ciphertext.fromBytes");
                if (d.remaining() !== 0) throw "Ciphertext.fromBytes: trailing bytes";
                return c;
            },
        });
    }

    static fromHex(hex: string): Result<Ciphertext> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => Ciphertext.fromBytes(hexToBytes(hex)).unwrapOrThrow("Ciphertext.fromHex"),
        });
    }

    toBytes(): Uint8Array {
        const s = new Serializer();
        this.serialize(s);
        return s.toUint8Array();
    }

    toHex(): string { return bytesToHex(this.toBytes()); }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/** HKDF-SHA256(IKM=seed, salt=∅, info=DST_KDF, L=44) → (32-byte AEAD key, 12-byte nonce). */
function deriveAeadKeyAndNonce(seed: Uint8Array): { key: Uint8Array; nonce: Uint8Array } {
    const okm = hkdf(sha256, seed, new Uint8Array(0), DST_KDF, AEAD_KEY_BYTES + AEAD_NONCE_BYTES);
    return {
        key: okm.slice(0, AEAD_KEY_BYTES),
        nonce: okm.slice(AEAD_KEY_BYTES, AEAD_KEY_BYTES + AEAD_NONCE_BYTES),
    };
}

/** Canonicalize a Gt (Fp12) element to the byte form fed into HKDF. Same conversion as the
 *  shortpk module uses to translate noble's big-endian-per-Fp limb layout to the on-chain
 *  Aptos layout. The choice doesn't affect correctness (it's just a deterministic encoding)
 *  but matches the existing convention in the repo for cross-language consistency.
 *
 *  Returns 576 bytes (12 × 48-byte Fp limbs, each reversed to LE). */
function gtToSeedBytes(seedElement: any): Uint8Array {
    const noble = bls12_381.fields.Fp12.toBytes(seedElement);
    if (noble.length !== 576) throw `gt seed: expected 576 bytes, got ${noble.length}`;
    const out = new Uint8Array(576);
    for (let i = 0; i < 12; i++) {
        // reverse each 48-byte limb (BE → LE)
        const chunk = noble.slice(i * 48, (i + 1) * 48);
        chunk.reverse();
        out.set(chunk, i * 48);
    }
    return out;
}

// ── Key generation + derivation ──────────────────────────────────────────────

/** Generate a master private key with a hash-derived G2 base point. For tests only —
 *  in production the base point comes from the on-chain DKG session. */
export function keygenForTesting(): MasterPrivateKey {
    const base = bls12_381.G2.hashToCurve(randomBytes(32)) as unknown as WeierstrassPoint<Fp2>;
    const scalar = bytesToNumberBE(bls12_381.utils.randomSecretKey());
    return new MasterPrivateKey(base, scalar);
}

export function derivePublicKey(msk: MasterPrivateKey): MasterPublicKey {
    const pk = msk.base.multiply(msk.scalar);
    return new MasterPublicKey(msk.base, pk);
}

// ── Encrypt / Decrypt ────────────────────────────────────────────────────────

export function encryptWithRandomness(
    mpk: MasterPublicKey,
    id: Uint8Array,
    plaintext: Uint8Array,
    randomness: Uint8Array,
): Ciphertext {
    const r = bytesToNumberLE(randomness);
    // Q_id = H_G1(id)
    const idPoint = bls12_381.G1.hashToCurve(id, { DST: DST_HASH_ID_TO_CURVE }) as unknown as WeierstrassPoint<bigint>;
    // seed = e(H_G1(id), pk^r) ∈ Gt
    const seedElement = bls12_381.pairing(idPoint, mpk.pk.multiply(r));
    const seed = gtToSeedBytes(seedElement);

    const { key, nonce } = deriveAeadKeyAndNonce(seed);
    const aeadCt = chacha20poly1305(key, nonce).encrypt(plaintext);

    // c0 = r · basePoint (in G2)
    const c0 = mpk.basePoint.multiply(r);
    return new Ciphertext(c0, aeadCt);
}

export function encrypt({ mpk, id, plaintext }: { mpk: MasterPublicKey; id: Uint8Array; plaintext: Uint8Array }): Result<Ciphertext> {
    return Result.capture({
        recordsExecutionTimeMs: true,
        task: () => {
            const r = bytesToNumberBE(bls12_381.utils.randomSecretKey());
            return encryptWithRandomness(mpk, id, plaintext, numberToBytesLE(r, 32));
        },
    });
}

/**
 * Verify an IDK share against the on-chain `sharePk` for the same evaluation point.
 *
 * Pairing check: e(idkShare, basePoint) == e(H_G1(id), sharePk).
 * Caller binds `sharePk` to the share's evaluation point (i.e. share_pks[i] for node i).
 */
export function verifyShare({ basePoint, sharePk, id, share }: {
    basePoint: WeierstrassPoint<Fp2>; // G2
    sharePk: WeierstrassPoint<Fp2>;   // G2 (= s_i · basePoint)
    id: Uint8Array;
    share: IdentityDecryptionKeyShare;
}): boolean {
    const idPoint = bls12_381.G1.hashToCurve(id, { DST: DST_HASH_ID_TO_CURVE }) as unknown as WeierstrassPoint<bigint>;
    const lhs = bls12_381.pairing(share.idkShare, basePoint);
    const rhs = bls12_381.pairing(idPoint, sharePk);
    return bls12_381.fields.Fp12.eql(lhs, rhs);
}

export function decrypt({ idkShares, ciphertext }: { idkShares: IdentityDecryptionKeyShare[]; ciphertext: Ciphertext }): Result<Uint8Array> {
    return Result.capture({
        recordsExecutionTimeMs: true,
        task: () => {
            if (idkShares.length === 0) throw "decrypt: no IDK shares provided";

            // Lagrange interpolation in the exponent (G1) to recover the full identity decryption key.
            const xs = idkShares.map(s => frMod(s.evalPoint));
            for (let i = 0; i < xs.length; i++) {
                for (let j = i + 1; j < xs.length; j++) {
                    if (xs[i] === xs[j]) throw "decrypt: duplicate evalPoint";
                }
            }
            const lambdas: bigint[] = xs.map((xi, i) => {
                let lambda = 1n;
                for (let j = 0; j < xs.length; j++) {
                    if (i === j) continue;
                    lambda = frMul(lambda, frMul(frMod(-xs[j]), frInv(frMod(xi - xs[j]))));
                }
                return lambda;
            });

            let idkFull: WeierstrassPoint<bigint> | null = null;
            for (let i = 0; i < idkShares.length; i++) {
                if (lambdas[i] === 0n) continue;
                const scaled = idkShares[i].idkShare.multiply(lambdas[i]);
                idkFull = idkFull === null ? scaled : idkFull.add(scaled);
            }
            if (idkFull === null) throw "decrypt: all Lagrange coefficients were zero";

            // Standard BF-IBE decryption: e(idkFull, c0) = e(s · H_G1(id), r · basePoint)
            //                                            = e(H_G1(id), basePoint)^{rs}
            //                                            = e(H_G1(id), pk^r) = seed
            const seedElement = bls12_381.pairing(idkFull, ciphertext.c0);
            const seed = gtToSeedBytes(seedElement);
            const { key, nonce } = deriveAeadKeyAndNonce(seed);
            // ChaCha20-Poly1305 .decrypt() throws on tag mismatch; we let that propagate.
            return chacha20poly1305(key, nonce).decrypt(ciphertext.aeadCt);
        },
    });
}
