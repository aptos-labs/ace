// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { Deserializer, Serializer } from "@aptos-labs/ts-sdk";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import * as OtpHmacBonehFranklinBls12381ShortPK from "./otp_hmac_boneh_franklin_bls12381_short_pk";
import { Result } from "../result";

/**
 * Boneh-Franklin IBE scheme using BLS12-381 with short public keys (G1).
 * Uses OTP (one-time pad) encryption with HMAC for authentication.
 * - Master public key: G1 point (48 bytes compressed)
 * - Master private key: scalar + G1 base point
 * - Identity private key: G2 point (96 bytes compressed)
 * - Ciphertext: G1 point + symmetric ciphertext + MAC
 */
export const SCHEME_OTP_HAMC_BONEH_FRANKLIN_BLS12381_SHORT_PK = 0;

export class MasterPublicKey {
    readonly scheme: number;
    /** @internal */
    readonly inner: any;

    private constructor(scheme: number, inner: any) {
        this.scheme = scheme;
        this.inner = inner;
    }

    /** @internal */
    static _create(scheme: number, inner: any): MasterPublicKey {
        return new MasterPublicKey(scheme, inner);
    }

    static deserialize(deserializer: Deserializer): Result<MasterPublicKey> {
        const task = (_extra: Record<string, any>) => {
            const scheme = deserializer.deserializeU8();
            if (scheme === SCHEME_OTP_HAMC_BONEH_FRANKLIN_BLS12381_SHORT_PK) {
                const inner = OtpHmacBonehFranklinBls12381ShortPK.MasterPublicKey.deserialize(deserializer).unwrapOrThrow('MasterPublicKey inner deserialization failed');
                return new MasterPublicKey(scheme, inner);
            }
            throw `MasterPublicKey deserialization failed with unknown scheme: ${scheme}`;
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    static fromBytes(bytes: Uint8Array): Result<MasterPublicKey> {
        const task = (_extra: Record<string, any>) => {
            const deserializer = new Deserializer(bytes);
            const ret = MasterPublicKey.deserialize(deserializer).unwrapOrThrow('MasterPublicKey deserialization failed');
            if (deserializer.remaining() !== 0) {
                throw `MasterPublicKey deserialization failed with trailing bytes`;
            }
            return ret;
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    static fromHex(hex: string): Result<MasterPublicKey> {
        const task = (_extra: Record<string, any>) => {
            return MasterPublicKey.fromBytes(hexToBytes(hex)).unwrapOrThrow('MasterPublicKey hex deserialization failed');
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    serialize(serializer: Serializer): void {
        serializer.serializeU8(this.scheme);
        (this.inner as OtpHmacBonehFranklinBls12381ShortPK.MasterPublicKey).serialize(serializer);
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
    readonly scheme: number;
    /** @internal */
    readonly inner: any;

    private constructor(scheme: number, inner: any) {
        this.scheme = scheme;
        this.inner = inner;
    }

    /** @internal */
    static _create(scheme: number, inner: any): MasterPrivateKey {
        return new MasterPrivateKey(scheme, inner);
    }

    static deserialize(deserializer: Deserializer): Result<MasterPrivateKey> {
        const task = (_extra: Record<string, any>) => {
            const scheme = deserializer.deserializeU8();
            if (scheme === SCHEME_OTP_HAMC_BONEH_FRANKLIN_BLS12381_SHORT_PK) {
                const inner = OtpHmacBonehFranklinBls12381ShortPK.MasterPrivateKey.deserialize(deserializer).unwrapOrThrow('MasterPrivateKey inner deserialization failed');
                return new MasterPrivateKey(scheme, inner);
            }
            throw `MasterPrivateKey deserialization failed with unknown scheme: ${scheme}`;
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    static fromBytes(bytes: Uint8Array): Result<MasterPrivateKey> {
        const task = (_extra: Record<string, any>) => {
            const deserializer = new Deserializer(bytes);
            const ret = MasterPrivateKey.deserialize(deserializer).unwrapOrThrow('MasterPrivateKey deserialization failed');
            if (deserializer.remaining() !== 0) {
                throw `MasterPrivateKey deserialization failed with trailing bytes`;
            }
            return ret;
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    static fromHex(hex: string): Result<MasterPrivateKey> {
        const task = (_extra: Record<string, any>) => {
            return MasterPrivateKey.fromBytes(hexToBytes(hex)).unwrapOrThrow('MasterPrivateKey hex deserialization failed');
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    serialize(serializer: Serializer): void {
        serializer.serializeU8(this.scheme);
        (this.inner as OtpHmacBonehFranklinBls12381ShortPK.MasterPrivateKey).serialize(serializer);
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

export class IdentityPrivateKey {
    readonly scheme: number;
    /** @internal */
    readonly inner: any;

    private constructor(scheme: number, inner: any) {
        this.scheme = scheme;
        this.inner = inner;
    }

    /** @internal */
    static _create(scheme: number, inner: any): IdentityPrivateKey {
        return new IdentityPrivateKey(scheme, inner);
    }

    static deserialize(deserializer: Deserializer): Result<IdentityPrivateKey> {
        const task = (_extra: Record<string, any>) => {
            const scheme = deserializer.deserializeU8();
            if (scheme === SCHEME_OTP_HAMC_BONEH_FRANKLIN_BLS12381_SHORT_PK) {
                const inner = OtpHmacBonehFranklinBls12381ShortPK.IdentityPrivateKey.deserialize(deserializer).unwrapOrThrow('IdentityPrivateKey inner deserialization failed');
                return new IdentityPrivateKey(scheme, inner);
            }
            throw `IdentityPrivateKey deserialization failed with unknown scheme: ${scheme}`;
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    static fromBytes(bytes: Uint8Array): Result<IdentityPrivateKey> {
        const task = (_extra: Record<string, any>) => {
            const deserializer = new Deserializer(bytes);
            const ret = IdentityPrivateKey.deserialize(deserializer).unwrapOrThrow('IdentityPrivateKey deserialization failed');
            if (deserializer.remaining() !== 0) {
                throw `IdentityPrivateKey deserialization failed with trailing bytes`;
            }
            return ret;
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    static fromHex(hex: string): Result<IdentityPrivateKey> {
        const task = (_extra: Record<string, any>) => {
            return IdentityPrivateKey.fromBytes(hexToBytes(hex)).unwrapOrThrow('IdentityPrivateKey hex deserialization failed');
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    serialize(serializer: Serializer): void {
        serializer.serializeU8(this.scheme);
        (this.inner as OtpHmacBonehFranklinBls12381ShortPK.IdentityPrivateKey).serialize(serializer);
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
    readonly scheme: number;
    /** @internal */
    readonly inner: any;

    private constructor(scheme: number, inner: any) {
        this.scheme = scheme;
        this.inner = inner;
    }

    /** @internal */
    static _create(scheme: number, inner: any): Ciphertext {
        return new Ciphertext(scheme, inner);
    }

    static deserialize(deserializer: Deserializer): Result<Ciphertext> {
        const task = (_extra: Record<string, any>) => {
            const scheme = deserializer.deserializeU8();
            if (scheme === SCHEME_OTP_HAMC_BONEH_FRANKLIN_BLS12381_SHORT_PK) {
                const inner = OtpHmacBonehFranklinBls12381ShortPK.Ciphertext.deserialize(deserializer).unwrapOrThrow('Ciphertext inner deserialization failed');
                return new Ciphertext(scheme, inner);
            }
            throw `Ciphertext deserialization failed with unknown scheme: ${scheme}`;
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    static fromBytes(bytes: Uint8Array): Result<Ciphertext> {
        const task = (_extra: Record<string, any>) => {
            const deserializer = new Deserializer(bytes);
            const ret = Ciphertext.deserialize(deserializer).unwrapOrThrow('Ciphertext deserialization failed');
            if (deserializer.remaining() !== 0) {
                throw `Ciphertext deserialization failed with trailing bytes`;
            }
            return ret;
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    static fromHex(hex: string): Result<Ciphertext> {
        const task = (_extra: Record<string, any>) => {
            return Ciphertext.fromBytes(hexToBytes(hex)).unwrapOrThrow('Ciphertext hex deserialization failed');
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    serialize(serializer: Serializer): void {
        serializer.serializeU8(this.scheme);
        (this.inner as OtpHmacBonehFranklinBls12381ShortPK.Ciphertext).serialize(serializer);
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

export function keygen(scheme?: number): Result<MasterPrivateKey> {
    const task = (_extra: Record<string, any>) => {
        if (scheme === undefined) {
            scheme = SCHEME_OTP_HAMC_BONEH_FRANKLIN_BLS12381_SHORT_PK;
        }
        if (scheme === SCHEME_OTP_HAMC_BONEH_FRANKLIN_BLS12381_SHORT_PK) {
            let msk = OtpHmacBonehFranklinBls12381ShortPK.keygen();
            return MasterPrivateKey._create(scheme, msk);
        }
        throw 'keygen failed with unknown scheme';
    };
    return Result.capture({task, recordsExecutionTimeMs: true});
}

export function derivePublicKey(privateKey: MasterPrivateKey): Result<MasterPublicKey> {
    const task = (_extra: Record<string, any>) => {
        if (privateKey.scheme == SCHEME_OTP_HAMC_BONEH_FRANKLIN_BLS12381_SHORT_PK) {
            return MasterPublicKey._create(SCHEME_OTP_HAMC_BONEH_FRANKLIN_BLS12381_SHORT_PK, OtpHmacBonehFranklinBls12381ShortPK.derivePublicKey(privateKey.inner));
        }
        throw 'derivePublicKey failed with unknown scheme';
    };
    return Result.capture({task, recordsExecutionTimeMs: true});
}

export function encrypt(publicKey: MasterPublicKey, id: Uint8Array, plaintext: Uint8Array): Result<Ciphertext> {
    const task = (_extra: Record<string, any>) => {
        if (publicKey.scheme == SCHEME_OTP_HAMC_BONEH_FRANKLIN_BLS12381_SHORT_PK) {
            return Ciphertext._create(
                SCHEME_OTP_HAMC_BONEH_FRANKLIN_BLS12381_SHORT_PK,
                OtpHmacBonehFranklinBls12381ShortPK.encrypt(publicKey.inner, id, plaintext)
            );
        }
        throw 'encryption failed with unknown scheme';
    };
    return Result.capture({task, recordsExecutionTimeMs: true});
}

/** Do NOT use this, unless you are a maintainer. Use `encrypt` instead. */
export function encryptWithRandomness(publicKey: MasterPublicKey, id: Uint8Array, plaintext: Uint8Array, randomness: Uint8Array): Result<Ciphertext> {
    const task = (_extra: Record<string, any>) => {
        if (publicKey.scheme == SCHEME_OTP_HAMC_BONEH_FRANKLIN_BLS12381_SHORT_PK) {
            return Ciphertext._create(
                SCHEME_OTP_HAMC_BONEH_FRANKLIN_BLS12381_SHORT_PK,
                OtpHmacBonehFranklinBls12381ShortPK.encryptWithRandomness(publicKey.inner, id, plaintext, randomness)
            );
        }
        throw 'encryptWithRandomness failed with unknown scheme';
    };
    return Result.capture({task, recordsExecutionTimeMs: true});
}

export function extract(privateKey: MasterPrivateKey, id: Uint8Array): Result<IdentityPrivateKey> {
    const task = (extra: Record<string, any>) => {
        extra['scheme'] = privateKey.scheme;
        if (privateKey.scheme == SCHEME_OTP_HAMC_BONEH_FRANKLIN_BLS12381_SHORT_PK) {
            return IdentityPrivateKey._create(
                SCHEME_OTP_HAMC_BONEH_FRANKLIN_BLS12381_SHORT_PK,
                OtpHmacBonehFranklinBls12381ShortPK.extract(privateKey.inner, id)
            );
        }
        throw 'extract failed with unknown scheme';
    };
    return Result.capture({task, recordsExecutionTimeMs: true});
}

export function decrypt(identityKey: IdentityPrivateKey, ciphertext: Ciphertext): Result<Uint8Array> {
    const task = (extra: Record<string, any>) => {
        extra['scheme'] = identityKey.scheme;
        if (identityKey.scheme == SCHEME_OTP_HAMC_BONEH_FRANKLIN_BLS12381_SHORT_PK) {
            const innerResult = OtpHmacBonehFranklinBls12381ShortPK.decrypt(identityKey.inner, ciphertext.inner);
            return innerResult.unwrapOrThrow('OtpHmacBonehFranklinBls12381ShortPK.tryDecrypt failed');
        }
        throw `decrypt failed with unknown scheme`;
    };
    return Result.capture({task, recordsExecutionTimeMs: true});
}

