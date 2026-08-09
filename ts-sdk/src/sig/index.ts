// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Generic, scheme-tagged signature library.
//!
//! Modeled on the `pke` module: a scheme byte selects the concrete algorithm so
//! new schemes (1, 2, …) can be added without changing the wire shape. Scheme
//! `0` = Ed25519 is the only one implemented today.
//!
//! `PublicKey`, `Signature`, and `SigningKey` all serialize as
//! `uleb128(scheme) || serializeBytes(raw)`, which is BCS-identical to the Rust
//! `sig::{PublicKey, Signature}` enums (variant index == scheme, single
//! `Vec<u8>` field). See `worker-components/vss-common/src/sig.rs`.

import { Deserializer, Serializer } from "@aptos-labs/ts-sdk";
import { ed25519 } from "@noble/curves/ed25519";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import { Result } from "../result";

export const SCHEME_ED25519 = 0;

function fromHexBytes(hex: string): Uint8Array {
    return hexToBytes(hex.replace(/^0x/i, ""));
}

function assertConsumed(deserializer: Deserializer, label: string): void {
    if (deserializer.remaining() !== 0) {
        throw new Error(`${label}: trailing bytes after deserialization`);
    }
}

function assertByteLength(bytes: Uint8Array, expected: number, label: string): void {
    if (bytes.length !== expected) {
        throw new Error(`${label} must be ${expected} bytes, got ${bytes.length}`);
    }
}

export class PublicKey {
    constructor(
        readonly scheme: number,
        readonly bytes: Uint8Array,
    ) {
        if (scheme !== SCHEME_ED25519) throw new Error(`unsupported sig public key scheme ${scheme}`);
        assertByteLength(bytes, 32, "Ed25519 public key");
    }

    serialize(serializer: Serializer): void {
        serializer.serializeU32AsUleb128(this.scheme);
        serializer.serializeBytes(this.bytes);
    }

    toBytes(): Uint8Array {
        const serializer = new Serializer();
        this.serialize(serializer);
        return serializer.toUint8Array();
    }

    toHex(): string {
        return bytesToHex(this.toBytes());
    }

    verify(message: Uint8Array, signature: Signature): boolean {
        if (signature.scheme !== this.scheme) return false;
        return ed25519.verify(signature.bytes, message, this.bytes);
    }

    static deserialize(deserializer: Deserializer): Result<PublicKey> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const scheme = deserializer.deserializeUleb128AsU32();
                if (scheme !== SCHEME_ED25519) throw new Error(`unsupported sig public key scheme ${scheme}`);
                return new PublicKey(scheme, deserializer.deserializeBytes());
            },
        });
    }

    static fromBytes(bytes: Uint8Array): Result<PublicKey> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const deserializer = new Deserializer(bytes);
                const publicKey = PublicKey.deserialize(deserializer).unwrapOrThrow("PublicKey.fromBytes");
                assertConsumed(deserializer, "PublicKey.fromBytes");
                return publicKey;
            },
        });
    }

    static fromHex(hex: string): Result<PublicKey> {
        return PublicKey.fromBytes(fromHexBytes(hex));
    }
}

export class Signature {
    constructor(
        readonly scheme: number,
        readonly bytes: Uint8Array,
    ) {
        if (scheme !== SCHEME_ED25519) throw new Error(`unsupported sig signature scheme ${scheme}`);
        assertByteLength(bytes, 64, "Ed25519 signature");
    }

    serialize(serializer: Serializer): void {
        serializer.serializeU32AsUleb128(this.scheme);
        serializer.serializeBytes(this.bytes);
    }

    toBytes(): Uint8Array {
        const serializer = new Serializer();
        this.serialize(serializer);
        return serializer.toUint8Array();
    }

    toHex(): string {
        return bytesToHex(this.toBytes());
    }

    static deserialize(deserializer: Deserializer): Result<Signature> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const scheme = deserializer.deserializeUleb128AsU32();
                if (scheme !== SCHEME_ED25519) throw new Error(`unsupported sig signature scheme ${scheme}`);
                return new Signature(scheme, deserializer.deserializeBytes());
            },
        });
    }

    static fromBytes(bytes: Uint8Array): Result<Signature> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const deserializer = new Deserializer(bytes);
                const signature = Signature.deserialize(deserializer).unwrapOrThrow("Signature.fromBytes");
                assertConsumed(deserializer, "Signature.fromBytes");
                return signature;
            },
        });
    }

    static fromHex(hex: string): Result<Signature> {
        return Signature.fromBytes(fromHexBytes(hex));
    }
}

/**
 * Scheme-tagged signing key. Serializes as `uleb128(scheme) || serializeBytes(raw)`
 * so it can be persisted as a single generic-key BCS hex blob (e.g. a deployment
 * profile's `reconstructorKey`) and evolve to new schemes without a migration.
 */
export class SigningKey {
    constructor(
        readonly scheme: number,
        readonly bytes: Uint8Array,
    ) {
        if (scheme !== SCHEME_ED25519) throw new Error(`unsupported sig signing key scheme ${scheme}`);
        assertByteLength(bytes, 32, "Ed25519 signing key");
    }

    publicKey(): PublicKey {
        return new PublicKey(this.scheme, ed25519.getPublicKey(this.bytes));
    }

    sign(message: Uint8Array): Signature {
        return new Signature(this.scheme, ed25519.sign(message, this.bytes));
    }

    serialize(serializer: Serializer): void {
        serializer.serializeU32AsUleb128(this.scheme);
        serializer.serializeBytes(this.bytes);
    }

    toBytes(): Uint8Array {
        const serializer = new Serializer();
        this.serialize(serializer);
        return serializer.toUint8Array();
    }

    /** Hex of the BCS-serialized (scheme-tagged) signing key. */
    toHex(): string {
        return bytesToHex(this.toBytes());
    }

    static deserialize(deserializer: Deserializer): Result<SigningKey> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const scheme = deserializer.deserializeUleb128AsU32();
                if (scheme !== SCHEME_ED25519) throw new Error(`unsupported sig signing key scheme ${scheme}`);
                return new SigningKey(scheme, deserializer.deserializeBytes());
            },
        });
    }

    static fromBytes(bytes: Uint8Array): Result<SigningKey> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const deserializer = new Deserializer(bytes);
                const signingKey = SigningKey.deserialize(deserializer).unwrapOrThrow("SigningKey.fromBytes");
                assertConsumed(deserializer, "SigningKey.fromBytes");
                return signingKey;
            },
        });
    }

    static fromHex(hex: string): Result<SigningKey> {
        return SigningKey.fromBytes(fromHexBytes(hex));
    }

    static random(scheme: number = SCHEME_ED25519): SigningKey {
        if (scheme !== SCHEME_ED25519) throw new Error(`unsupported sig signing key scheme ${scheme}`);
        return new SigningKey(scheme, ed25519.utils.randomSecretKey());
    }
}

export async function keygen(
    scheme: number = SCHEME_ED25519,
): Promise<{ publicKey: PublicKey; signingKey: SigningKey }> {
    if (scheme === SCHEME_ED25519) {
        const signingKey = SigningKey.random(scheme);
        return {
            publicKey: signingKey.publicKey(),
            signingKey,
        };
    }
    throw new Error(`keygen: unknown signature scheme ${scheme}`);
}

export function verify(message: Uint8Array, signature: Signature, publicKey: PublicKey): boolean {
    return publicKey.verify(message, signature);
}
