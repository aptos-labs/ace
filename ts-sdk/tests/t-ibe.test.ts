// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest';
import * as TIBE from '../src/t-ibe';
import * as BfibeBls12381 from '../src/t-ibe/bfibe-bls12381-shortpk-otp-hmac';
import { bls12_381 } from '@noble/curves/bls12-381';
import { bytesToNumberLE, numberToBytesLE } from '@noble/curves/utils';
import { WeierstrassPoint } from '@noble/curves/abstract/weierstrass';
import { Fp2 } from '@noble/curves/abstract/tower';
import { split } from '../src/group/bls12381g1';

const DST_ID_HASH = new TextEncoder().encode("BONEH_FRANKLIN_BLS12381_SHORT_PK/HASH_ID_TO_CURVE");

/** Trusted-dealer setup: generates a master key and Shamir-splits it into IDK shares. */
function setupShares(threshold: number, total: number, id: Uint8Array): {
    mskInner: BfibeBls12381.MasterPrivateKey,
    mpkInner: BfibeBls12381.MasterPublicKey,
    shares: BfibeBls12381.IdentityDecryptionKeyShare[],
    /** Per-holder Feldman commitments base^{s_i} — bound to the same `split` as `shares`. */
    sharePks: WeierstrassPoint<bigint>[],
} {
    const mskInner = BfibeBls12381.keygenForTesting();
    const mpkInner = BfibeBls12381.derivePublicKey(mskInner);

    const shareLeBytes = split(numberToBytesLE(mskInner.scalar, 32), threshold, total).unwrapOrThrow('split failed');
    const idPoint = bls12_381.G2.hashToCurve(id, { DST: DST_ID_HASH }) as unknown as WeierstrassPoint<Fp2>;
    const shares: BfibeBls12381.IdentityDecryptionKeyShare[] = [];
    const sharePks: WeierstrassPoint<bigint>[] = [];
    for (let i = 0; i < shareLeBytes.length; i++) {
        const si = bytesToNumberLE(shareLeBytes[i]);
        shares.push(new BfibeBls12381.IdentityDecryptionKeyShare(BigInt(i + 1), idPoint.multiply(si), undefined));
        sharePks.push(mskInner.base.multiply(si) as unknown as WeierstrassPoint<bigint>);
    }
    return { mskInner, mpkInner, shares, sharePks };
}

describe('T-IBE (Threshold Identity-Based Encryption)', () => {
    describe('End-to-end', () => {
        it('should encrypt and decrypt correctly with 3-of-5 shares', () => {
            const id = new TextEncoder().encode('alice@example.com');
            const plaintext = new TextEncoder().encode('Hello threshold IBE!');
            const { mpkInner, shares } = setupShares(3, 5, id);

            const ciphertext = BfibeBls12381.encrypt({ mpk: mpkInner, id, plaintext })
                .unwrapOrThrow('encrypt failed');

            // Use shares at indices 0, 2, 4 (eval points 1, 3, 5)
            const decrypted = BfibeBls12381.decrypt({
                idkShares: [shares[0], shares[2], shares[4]],
                ciphertext,
            }).unwrapOrThrow('decrypt failed');

            expect(decrypted).toEqual(plaintext);
        });

        it('should encrypt and decrypt correctly with minimum 2-of-3 threshold', () => {
            const id = new TextEncoder().encode('bob@example.com');
            const plaintext = new TextEncoder().encode('Threshold minimum test');
            const { mpkInner, shares } = setupShares(2, 3, id);

            const ciphertext = BfibeBls12381.encrypt({ mpk: mpkInner, id, plaintext })
                .unwrapOrThrow('encrypt failed');

            const decrypted = BfibeBls12381.decrypt({
                idkShares: [shares[0], shares[1]],
                ciphertext,
            }).unwrapOrThrow('decrypt failed');

            expect(decrypted).toEqual(plaintext);
        });

        it('should work with any t-subset of shares (different subset)', () => {
            const id = new TextEncoder().encode('carol@example.com');
            const plaintext = new TextEncoder().encode('Any t-subset works');
            const { mpkInner, shares } = setupShares(2, 4, id);

            const ciphertext = BfibeBls12381.encrypt({ mpk: mpkInner, id, plaintext })
                .unwrapOrThrow('encrypt failed');

            // Use shares at indices 1 and 3 (eval points 2, 4) instead of 1, 2
            const decrypted = BfibeBls12381.decrypt({
                idkShares: [shares[1], shares[3]],
                ciphertext,
            }).unwrapOrThrow('decrypt failed');

            expect(decrypted).toEqual(plaintext);
        });
    });

    describe('verifyShare', () => {
        it('accepts a correctly-formed share', () => {
            const id = new TextEncoder().encode('verify@example.com');
            const { mpkInner, shares, sharePks } = setupShares(2, 3, id);
            const ok = BfibeBls12381.verifyShare({
                basePoint: mpkInner.basePoint,
                sharePk: sharePks[0],
                id,
                share: shares[0],
            });
            expect(ok).toBe(true);
        });

        it('rejects a share whose idkShare has been tampered with', () => {
            const id = new TextEncoder().encode('tamper@example.com');
            const { mpkInner, shares, sharePks } = setupShares(2, 3, id);
            // Replace idkShare with a different point (use share[1]'s idkShare under share[0]'s evalPoint).
            const tampered = new BfibeBls12381.IdentityDecryptionKeyShare(
                shares[0].evalPoint, shares[1].idkShare, undefined,
            );
            const ok = BfibeBls12381.verifyShare({
                basePoint: mpkInner.basePoint,
                sharePk: sharePks[0],
                id,
                share: tampered,
            });
            expect(ok).toBe(false);
        });

        it('rejects a valid share against the wrong sharePk', () => {
            const id = new TextEncoder().encode('mismatch@example.com');
            const { mpkInner, shares, sharePks } = setupShares(2, 3, id);
            const ok = BfibeBls12381.verifyShare({
                basePoint: mpkInner.basePoint,
                sharePk: sharePks[1],
                id,
                share: shares[0],
            });
            expect(ok).toBe(false);
        });

        it('rejects a share against a different id', () => {
            const id = new TextEncoder().encode('verify@example.com');
            const otherId = new TextEncoder().encode('different@example.com');
            const { mpkInner, shares, sharePks } = setupShares(2, 3, id);
            const ok = BfibeBls12381.verifyShare({
                basePoint: mpkInner.basePoint,
                sharePk: sharePks[0],
                id: otherId,
                share: shares[0],
            });
            expect(ok).toBe(false);
        });
    });

    describe('Decryption failure', () => {
        it('should fail with MAC error when using wrong-identity IDK shares', () => {
            const id1 = new TextEncoder().encode('alice@example.com');
            const id2 = new TextEncoder().encode('eve@example.com');
            const plaintext = new TextEncoder().encode('Secret message');

            const { mpkInner, mskInner } = setupShares(2, 3, id1);

            // Encrypt for id1
            const ciphertext = BfibeBls12381.encrypt({ mpk: mpkInner, id: id1, plaintext })
                .unwrapOrThrow('encrypt failed');

            // Build IDK shares for id2 using the same master key
            const shareLeBytes = split(numberToBytesLE(mskInner.scalar, 32), 2, 3).unwrapOrThrow('split');
            const idPoint2 = bls12_381.G2.hashToCurve(id2, { DST: DST_ID_HASH }) as unknown as WeierstrassPoint<Fp2>;
            const wrongShares = shareLeBytes.slice(0, 2).map((leBytes, i) => {
                const si = bytesToNumberLE(leBytes);
                return new BfibeBls12381.IdentityDecryptionKeyShare(BigInt(i + 1), idPoint2.multiply(si), undefined);
            });

            const result = BfibeBls12381.decrypt({ idkShares: wrongShares, ciphertext });
            expect(result.isOk).toBe(false);
        });
    });

    describe('Serialization round-trips (inner variant classes)', () => {
        it('MasterPrivateKey', () => {
            const msk = BfibeBls12381.keygenForTesting();
            const restored = BfibeBls12381.MasterPrivateKey.fromBytes(msk.toBytes())
                .unwrapOrThrow('MasterPrivateKey round-trip failed');
            expect(restored.toBytes()).toEqual(msk.toBytes());
        });

        it('MasterPublicKey', () => {
            const mpk = BfibeBls12381.derivePublicKey(BfibeBls12381.keygenForTesting());
            const restored = BfibeBls12381.MasterPublicKey.fromBytes(mpk.toBytes())
                .unwrapOrThrow('MasterPublicKey round-trip failed');
            expect(restored.toBytes()).toEqual(mpk.toBytes());
        });

        it('Ciphertext', () => {
            const id = new TextEncoder().encode('serde@test.com');
            const { mpkInner } = setupShares(2, 3, id);
            const ciph = BfibeBls12381.encrypt({ mpk: mpkInner, id, plaintext: new TextEncoder().encode('serde test') })
                .unwrapOrThrow('encrypt');
            const restored = BfibeBls12381.Ciphertext.fromBytes(ciph.toBytes())
                .unwrapOrThrow('Ciphertext round-trip failed');
            expect(restored.toBytes()).toEqual(ciph.toBytes());
        });

        it('IdentityDecryptionKeyShare (without proof)', () => {
            const id = new TextEncoder().encode('serde@test.com');
            const { shares } = setupShares(2, 3, id);
            const share = shares[0];
            const restored = BfibeBls12381.IdentityDecryptionKeyShare.fromBytes(share.toBytes())
                .unwrapOrThrow('IdentityDecryptionKeyShare round-trip failed');
            expect(restored.toBytes()).toEqual(share.toBytes());
        });

        it('IdentityDecryptionKeyShare (with proof bytes)', () => {
            const id = new TextEncoder().encode('serde-proof@test.com');
            const { shares } = setupShares(2, 3, id);
            const proof = new Uint8Array(32).fill(0xab);
            const shareWithProof = new BfibeBls12381.IdentityDecryptionKeyShare(
                shares[0].evalPoint, shares[0].idkShare, proof
            );
            const restored = BfibeBls12381.IdentityDecryptionKeyShare.fromBytes(shareWithProof.toBytes())
                .unwrapOrThrow('IdentityDecryptionKeyShare (with proof) round-trip failed');
            expect(restored.toBytes()).toEqual(shareWithProof.toBytes());
        });
    });

    describe('Serialization round-trips (abstract wrapper classes)', () => {
        it('MasterPrivateKey wrapper', () => {
            const msk = TIBE.keygenForTesting().unwrapOrThrow('keygenForTesting failed');
            const restored = TIBE.MasterPrivateKey.fromBytes(msk.toBytes())
                .unwrapOrThrow('MasterPrivateKey wrapper round-trip failed');
            expect(restored.toBytes()).toEqual(msk.toBytes());
        });

        it('MasterPublicKey wrapper', () => {
            const msk = TIBE.keygenForTesting().unwrapOrThrow('keygenForTesting failed');
            const mpk = TIBE.derivePublicKey(msk).unwrapOrThrow('derivePublicKey failed');
            const restored = TIBE.MasterPublicKey.fromBytes(mpk.toBytes())
                .unwrapOrThrow('MasterPublicKey wrapper round-trip failed');
            expect(restored.toBytes()).toEqual(mpk.toBytes());
        });

        it('Ciphertext wrapper', () => {
            const id = new TextEncoder().encode('wrapper-serde@test.com');
            const msk = TIBE.keygenForTesting().unwrapOrThrow('keygenForTesting');
            const mpk = TIBE.derivePublicKey(msk).unwrapOrThrow('derivePublicKey');
            const ciph = TIBE.encrypt({ mpk, id, plaintext: new TextEncoder().encode('wrapper serde') })
                .unwrapOrThrow('encrypt');
            const restored = TIBE.Ciphertext.fromBytes(ciph.toBytes())
                .unwrapOrThrow('Ciphertext wrapper round-trip failed');
            expect(restored.toBytes()).toEqual(ciph.toBytes());
        });

        it('IdentityDecryptionKeyShare wrapper', () => {
            const id = new TextEncoder().encode('idk-wrapper@test.com');
            const { shares } = setupShares(2, 3, id);
            const share = shares[0];
            const wrapped = TIBE.IdentityDecryptionKeyShare.newBonehFranklinBls12381ShortPkOtpHmac(
                share.evalPoint, share.idkShare, undefined
            ).unwrapOrThrow('newBonehFranklin');
            const restored = TIBE.IdentityDecryptionKeyShare.fromBytes(wrapped.toBytes())
                .unwrapOrThrow('IdentityDecryptionKeyShare wrapper round-trip failed');
            expect(restored.toBytes()).toEqual(wrapped.toBytes());
        });
    });

    describe('Hex serialization', () => {
        it('MasterPrivateKey hex round-trip', () => {
            const msk = TIBE.keygenForTesting().unwrapOrThrow('keygenForTesting');
            const hex = msk.toHex();
            const restored = TIBE.MasterPrivateKey.fromHex(hex).unwrapOrThrow('fromHex failed');
            expect(restored.toBytes()).toEqual(msk.toBytes());
        });

        it('MasterPublicKey hex round-trip', () => {
            const msk = TIBE.keygenForTesting().unwrapOrThrow('keygenForTesting');
            const mpk = TIBE.derivePublicKey(msk).unwrapOrThrow('derivePublicKey');
            const hex = mpk.toHex();
            const restored = TIBE.MasterPublicKey.fromHex(hex).unwrapOrThrow('fromHex failed');
            expect(restored.toBytes()).toEqual(mpk.toBytes());
        });
    });

    describe('encryptWithRandomness', () => {
        it('is deterministic with the same randomness', () => {
            const id = new TextEncoder().encode('deterministic@test.com');
            const plaintext = new TextEncoder().encode('deterministic test');
            const randomness = new Uint8Array(32).fill(0x42);
            const { mpkInner } = setupShares(2, 3, id);

            const ciph1 = BfibeBls12381.encryptWithRandomness(mpkInner, id, plaintext, randomness);
            const ciph2 = BfibeBls12381.encryptWithRandomness(mpkInner, id, plaintext, randomness);

            expect(ciph1.toBytes()).toEqual(ciph2.toBytes());
        });
    });

    describe('keygenForTesting + derivePublicKey', () => {
        it('derivePublicKey is consistent after msk serde round-trip', () => {
            const msk = TIBE.keygenForTesting().unwrapOrThrow('keygenForTesting');
            const mpk = TIBE.derivePublicKey(msk).unwrapOrThrow('derivePublicKey');

            const mskRestored = TIBE.MasterPrivateKey.fromBytes(msk.toBytes()).unwrapOrThrow('msk serde');
            const mpkFromRestored = TIBE.derivePublicKey(mskRestored).unwrapOrThrow('derivePublicKey from restored');

            expect(mpkFromRestored.toBytes()).toEqual(mpk.toBytes());
        });
    });
});
