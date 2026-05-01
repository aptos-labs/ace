import { Deserializer, Serializer } from "@aptos-labs/ts-sdk";
import { Fp2 } from "@noble/curves/abstract/tower";
import { WeierstrassPoint } from "@noble/curves/abstract/weierstrass";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import { group } from "..";
import { Result } from "../result";
import * as BfibeBls12381ShortPkOtpHmac from "./bfibe-bls12381-shortpk-otp-hmac";

export const SCHEME_BFIBE_BLS12381_SHORTPK_OTP_HMAC = 0;

export class MasterPublicKey {
    scheme: number;
    inner: any;
    constructor(scheme: number, inner: any) {
        this.scheme = scheme;
        this.inner = inner;
    }

    static newBonehFranklinBls12381ShortPkOtpHmac(basePoint: group.Element, pk: group.Element): Result<MasterPublicKey> {
        return Result.capture({
            task: (_extra: Record<string, any>) => {
                const basePointInner = (basePoint.inner as group.bls12381G1.PublicPoint).pt;
                const pkInner = (pk.inner as group.bls12381G1.PublicPoint).pt;
                const inner = new BfibeBls12381ShortPkOtpHmac.MasterPublicKey(basePointInner, pkInner);
                return new MasterPublicKey(SCHEME_BFIBE_BLS12381_SHORTPK_OTP_HMAC, inner);
            },
            recordsExecutionTimeMs: false,
        });
    }

    /** @internal */
    static _create(scheme: number, inner: BfibeBls12381ShortPkOtpHmac.MasterPublicKey): MasterPublicKey {
        return new MasterPublicKey(scheme, inner);
    }

    static deserialize(deserializer: Deserializer): Result<MasterPublicKey> {
        const task = (_extra: Record<string, any>) => {
            const scheme = deserializer.deserializeU8();
            if (scheme === SCHEME_BFIBE_BLS12381_SHORTPK_OTP_HMAC) {
                const inner = BfibeBls12381ShortPkOtpHmac.MasterPublicKey.deserialize(deserializer).unwrapOrThrow('MasterPublicKey inner deserialization failed');
                return new MasterPublicKey(scheme, inner);
            }
            throw `MasterPublicKey deserialization failed with unknown scheme: ${scheme}`;
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    static fromBytes(bytes: Uint8Array): Result<MasterPublicKey> {
        const task = (_extra: Record<string, any>) => {
            const des = new Deserializer(bytes);
            const ret = MasterPublicKey.deserialize(des).unwrapOrThrow('MasterPublicKey.fromBytes failed');
            if (des.remaining() !== 0) throw 'MasterPublicKey.fromBytes: trailing bytes';
            return ret;
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    static fromHex(hex: string): Result<MasterPublicKey> {
        const task = (_extra: Record<string, any>) =>
            MasterPublicKey.fromBytes(hexToBytes(hex)).unwrapOrThrow('MasterPublicKey.fromHex failed');
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    serialize(serializer: Serializer): void {
        serializer.serializeU8(this.scheme);
        (this.inner as BfibeBls12381ShortPkOtpHmac.MasterPublicKey).serialize(serializer);
    }

    toBytes(): Uint8Array {
        const serializer = new Serializer();
        this.serialize(serializer);
        return serializer.toUint8Array();
    }

    toHex(): string {
        return bytesToHex(this.toBytes());
    }
}

export class MasterPrivateKey {
    scheme: number;
    inner: any;
    constructor(scheme: number, inner: any) {
        this.scheme = scheme;
        this.inner = inner;
    }

    /** @internal */
    static _create(scheme: number, inner: BfibeBls12381ShortPkOtpHmac.MasterPrivateKey): MasterPrivateKey {
        return new MasterPrivateKey(scheme, inner);
    }

    static deserialize(deserializer: Deserializer): Result<MasterPrivateKey> {
        const task = (_extra: Record<string, any>) => {
            const scheme = deserializer.deserializeU8();
            if (scheme === SCHEME_BFIBE_BLS12381_SHORTPK_OTP_HMAC) {
                const inner = BfibeBls12381ShortPkOtpHmac.MasterPrivateKey.deserialize(deserializer).unwrapOrThrow('MasterPrivateKey inner deserialization failed');
                return new MasterPrivateKey(scheme, inner);
            }
            throw `MasterPrivateKey deserialization failed with unknown scheme: ${scheme}`;
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    static fromBytes(bytes: Uint8Array): Result<MasterPrivateKey> {
        const task = (_extra: Record<string, any>) => {
            const des = new Deserializer(bytes);
            const ret = MasterPrivateKey.deserialize(des).unwrapOrThrow('MasterPrivateKey.fromBytes failed');
            if (des.remaining() !== 0) throw 'MasterPrivateKey.fromBytes: trailing bytes';
            return ret;
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    static fromHex(hex: string): Result<MasterPrivateKey> {
        const task = (_extra: Record<string, any>) =>
            MasterPrivateKey.fromBytes(hexToBytes(hex)).unwrapOrThrow('MasterPrivateKey.fromHex failed');
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    serialize(serializer: Serializer): void {
        serializer.serializeU8(this.scheme);
        (this.inner as BfibeBls12381ShortPkOtpHmac.MasterPrivateKey).serialize(serializer);
    }

    toBytes(): Uint8Array {
        const serializer = new Serializer();
        this.serialize(serializer);
        return serializer.toUint8Array();
    }

    toHex(): string {
        return bytesToHex(this.toBytes());
    }
}

export class Ciphertext {
    scheme: number;
    inner: any;
    constructor(scheme: number, inner: any) {
        this.scheme = scheme;
        this.inner = inner;
    }

    /** @internal */
    static _create(scheme: number, inner: BfibeBls12381ShortPkOtpHmac.Ciphertext): Ciphertext {
        return new Ciphertext(scheme, inner);
    }

    static deserialize(deserializer: Deserializer): Result<Ciphertext> {
        const task = (_extra: Record<string, any>) => {
            const scheme = deserializer.deserializeU8();
            if (scheme === SCHEME_BFIBE_BLS12381_SHORTPK_OTP_HMAC) {
                const inner = BfibeBls12381ShortPkOtpHmac.Ciphertext.deserialize(deserializer).unwrapOrThrow('Ciphertext inner deserialization failed');
                return new Ciphertext(scheme, inner);
            }
            throw `Ciphertext deserialization failed with unknown scheme: ${scheme}`;
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    static fromBytes(bytes: Uint8Array): Result<Ciphertext> {
        const task = (_extra: Record<string, any>) => {
            const des = new Deserializer(bytes);
            const ret = Ciphertext.deserialize(des).unwrapOrThrow('Ciphertext.fromBytes failed');
            if (des.remaining() !== 0) throw 'Ciphertext.fromBytes: trailing bytes';
            return ret;
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    static fromHex(hex: string): Result<Ciphertext> {
        const task = (_extra: Record<string, any>) =>
            Ciphertext.fromBytes(hexToBytes(hex)).unwrapOrThrow('Ciphertext.fromHex failed');
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    serialize(serializer: Serializer): void {
        serializer.serializeU8(this.scheme);
        (this.inner as BfibeBls12381ShortPkOtpHmac.Ciphertext).serialize(serializer);
    }

    toBytes(): Uint8Array {
        const serializer = new Serializer();
        this.serialize(serializer);
        return serializer.toUint8Array();
    }

    toHex(): string {
        return bytesToHex(this.toBytes());
    }
}

export class IdentityDecryptionKeyShare {
    scheme: number;
    inner: any;
    constructor(scheme: number, inner: any) {
        this.scheme = scheme;
        this.inner = inner;
    }

    static newBonehFranklinBls12381ShortPkOtpHmac(evalPoint: bigint, idkShare: WeierstrassPoint<Fp2>, proof?: Uint8Array): Result<IdentityDecryptionKeyShare> {
        return Result.capture({
            task: (_extra: Record<string, any>) => {
                const inner = new BfibeBls12381ShortPkOtpHmac.IdentityDecryptionKeyShare(evalPoint, idkShare, proof);
                return new IdentityDecryptionKeyShare(SCHEME_BFIBE_BLS12381_SHORTPK_OTP_HMAC, inner);
            },
            recordsExecutionTimeMs: false,
        });
    }

    static deserialize(deserializer: Deserializer): Result<IdentityDecryptionKeyShare> {
        const task = (_extra: Record<string, any>) => {
            const scheme = deserializer.deserializeU8();
            if (scheme === SCHEME_BFIBE_BLS12381_SHORTPK_OTP_HMAC) {
                const inner = BfibeBls12381ShortPkOtpHmac.IdentityDecryptionKeyShare.deserialize(deserializer).unwrapOrThrow('IdentityDecryptionKeyShare inner deserialization failed');
                return new IdentityDecryptionKeyShare(scheme, inner);
            }
            throw `IdentityDecryptionKeyShare deserialization failed with unknown scheme: ${scheme}`;
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    static fromBytes(bytes: Uint8Array): Result<IdentityDecryptionKeyShare> {
        const task = (_extra: Record<string, any>) => {
            const des = new Deserializer(bytes);
            const ret = IdentityDecryptionKeyShare.deserialize(des).unwrapOrThrow('IdentityDecryptionKeyShare.fromBytes failed');
            if (des.remaining() !== 0) throw 'IdentityDecryptionKeyShare.fromBytes: trailing bytes';
            return ret;
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    static fromHex(hex: string): Result<IdentityDecryptionKeyShare> {
        const task = (_extra: Record<string, any>) =>
            IdentityDecryptionKeyShare.fromBytes(hexToBytes(hex)).unwrapOrThrow('IdentityDecryptionKeyShare.fromHex failed');
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    serialize(serializer: Serializer): void {
        serializer.serializeU8(this.scheme);
        (this.inner as BfibeBls12381ShortPkOtpHmac.IdentityDecryptionKeyShare).serialize(serializer);
    }

    toBytes(): Uint8Array {
        const serializer = new Serializer();
        this.serialize(serializer);
        return serializer.toUint8Array();
    }

    toHex(): string {
        return bytesToHex(this.toBytes());
    }
}

export function keygenForTesting(scheme?: number): Result<MasterPrivateKey> {
    const task = (_extra: Record<string, any>) => {
        if (scheme === undefined) scheme = SCHEME_BFIBE_BLS12381_SHORTPK_OTP_HMAC;
        if (scheme === SCHEME_BFIBE_BLS12381_SHORTPK_OTP_HMAC) {
            const msk = BfibeBls12381ShortPkOtpHmac.keygenForTesting();
            return MasterPrivateKey._create(scheme, msk);
        }
        throw 'keygenForTesting failed with unknown scheme';
    };
    return Result.capture({task, recordsExecutionTimeMs: true});
}

export function derivePublicKey(msk: MasterPrivateKey): Result<MasterPublicKey> {
    const task = (_extra: Record<string, any>) => {
        if (msk.scheme === SCHEME_BFIBE_BLS12381_SHORTPK_OTP_HMAC) {
            const mpk = BfibeBls12381ShortPkOtpHmac.derivePublicKey(msk.inner as BfibeBls12381ShortPkOtpHmac.MasterPrivateKey);
            return MasterPublicKey._create(SCHEME_BFIBE_BLS12381_SHORTPK_OTP_HMAC, mpk);
        }
        throw 'derivePublicKey failed with unknown scheme';
    };
    return Result.capture({task, recordsExecutionTimeMs: true});
}

export function encrypt({mpk, id, plaintext}: {mpk: MasterPublicKey, id: Uint8Array, plaintext: Uint8Array}): Result<Ciphertext> {
    const task = (_extra: Record<string, any>) => {
        if (mpk.scheme === SCHEME_BFIBE_BLS12381_SHORTPK_OTP_HMAC) {
            const innerCiph = BfibeBls12381ShortPkOtpHmac.encrypt({
                mpk: mpk.inner as BfibeBls12381ShortPkOtpHmac.MasterPublicKey,
                id,
                plaintext,
            }).unwrapOrThrow('encrypt failed');
            return Ciphertext._create(SCHEME_BFIBE_BLS12381_SHORTPK_OTP_HMAC, innerCiph);
        }
        throw 'unknown scheme';
    };
    return Result.capture({task, recordsExecutionTimeMs: true});
}

/** Do NOT use this, unless you are a maintainer. Use `encrypt` instead. */
export function encryptWithRandomness({mpk, id, plaintext, randomness}: {mpk: MasterPublicKey, id: Uint8Array, plaintext: Uint8Array, randomness: Uint8Array}): Result<Ciphertext> {
    const task = (_extra: Record<string, any>) => {
        if (mpk.scheme === SCHEME_BFIBE_BLS12381_SHORTPK_OTP_HMAC) {
            const innerCiph = BfibeBls12381ShortPkOtpHmac.encryptWithRandomness(
                mpk.inner as BfibeBls12381ShortPkOtpHmac.MasterPublicKey,
                id,
                plaintext,
                randomness,
            );
            return Ciphertext._create(SCHEME_BFIBE_BLS12381_SHORTPK_OTP_HMAC, innerCiph);
        }
        throw 'unknown scheme';
    };
    return Result.capture({task, recordsExecutionTimeMs: true});
}

/**
 * Verify that an IDK share is correct against the on-chain `sharePk` for the same evaluation point.
 *
 * Returns `true` if the share is well-formed for the given `(basePoint, sharePk, id)`.
 * Caller binds `sharePk` to the share's evaluation point (i.e. `share_pks[i]` for node i).
 */
export function verifyShare({basePoint, sharePk, id, share}: {
    basePoint: group.Element,
    sharePk: group.Element,
    id: Uint8Array,
    share: IdentityDecryptionKeyShare,
}): Result<boolean> {
    const task = (_extra: Record<string, any>) => {
        if (share.scheme !== SCHEME_BFIBE_BLS12381_SHORTPK_OTP_HMAC) {
            throw `verifyShare: unknown share scheme ${share.scheme}`;
        }
        const basePointInner = (basePoint.inner as group.bls12381G1.PublicPoint).pt;
        const sharePkInner = (sharePk.inner as group.bls12381G1.PublicPoint).pt;
        return BfibeBls12381ShortPkOtpHmac.verifyShare({
            basePoint: basePointInner,
            sharePk: sharePkInner,
            id,
            share: share.inner as BfibeBls12381ShortPkOtpHmac.IdentityDecryptionKeyShare,
        });
    };
    return Result.capture({task, recordsExecutionTimeMs: true});
}

export function decrypt({idkShares, ciphertext}: {idkShares: IdentityDecryptionKeyShare[], ciphertext: Ciphertext}): Result<Uint8Array> {
    const task = (_extra: Record<string, any>) => {
        const scheme = ciphertext.scheme;
        for (const idkShare of idkShares) if (idkShare.scheme !== scheme) throw 'scheme mismatch';
        if (ciphertext.scheme === SCHEME_BFIBE_BLS12381_SHORTPK_OTP_HMAC) {
            return BfibeBls12381ShortPkOtpHmac.decrypt({
                idkShares: idkShares.map(idkShare => idkShare.inner as BfibeBls12381ShortPkOtpHmac.IdentityDecryptionKeyShare),
                ciphertext: ciphertext.inner as BfibeBls12381ShortPkOtpHmac.Ciphertext,
            }).unwrapOrThrow('decrypt failed');
        }
        throw 'unknown scheme';
    };
    return Result.capture({task, recordsExecutionTimeMs: true});
}
