// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { Deserializer, Serializer } from "@aptos-labs/ts-sdk";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import { Result } from "../result";

const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const BASE58_VALUES = new Map([...BASE58_ALPHABET].map((char, index) => [char, index]));

function base58Encode(bytes: Uint8Array): string {
    let value = 0n;
    for (const byte of bytes) {
        value = (value * 256n) + BigInt(byte);
    }

    let encoded = "";
    while (value > 0n) {
        const rem = Number(value % 58n);
        value /= 58n;
        encoded = BASE58_ALPHABET[rem] + encoded;
    }

    let leadingZeroes = 0;
    for (const byte of bytes) {
        if (byte !== 0) break;
        leadingZeroes += 1;
    }

    return "1".repeat(leadingZeroes) + (encoded || "");
}

function base58Decode(value: string): Uint8Array {
    let decoded = 0n;
    for (const char of value) {
        const digit = BASE58_VALUES.get(char);
        if (digit === undefined) {
            throw `SolanaPublicKey: invalid base58 character '${char}'`;
        }
        decoded = (decoded * 58n) + BigInt(digit);
    }

    const bytes: number[] = [];
    while (decoded > 0n) {
        bytes.unshift(Number(decoded % 256n));
        decoded /= 256n;
    }

    let leadingZeroes = 0;
    for (const char of value) {
        if (char !== "1") break;
        leadingZeroes += 1;
    }

    return new Uint8Array([...new Array(leadingZeroes).fill(0), ...bytes]);
}

export class PublicKey {
    private readonly bytes: Uint8Array;

    constructor(value: string | Uint8Array) {
        const bytes = typeof value === "string" ? base58Decode(value) : value;
        if (bytes.length !== 32) {
            throw `SolanaPublicKey: expected 32 bytes, got ${bytes.length}`;
        }
        this.bytes = new Uint8Array(bytes);
    }

    toBytes(): Uint8Array {
        return new Uint8Array(this.bytes);
    }

    toBase58(): string {
        return base58Encode(this.bytes);
    }

    toString(): string {
        return this.toBase58();
    }

    toJSON(): string {
        return this.toBase58();
    }
}

function readShortVecLength(bytes: Uint8Array): { length: number, size: number } {
    let length = 0;
    let size = 0;
    let shift = 0;

    while (true) {
        if (size >= bytes.length) {
            throw "SolanaProofOfPermission: transaction bytes ended while reading signature count";
        }
        const byte = bytes[size];
        length += (byte & 0x7f) << shift;
        size += 1;
        if ((byte & 0x80) === 0) break;
        shift += 7;
        if (shift > 28) {
            throw "SolanaProofOfPermission: signature count shortvec is too large";
        }
    }

    return { length, size };
}

export function inferTransactionScheme(txn: Uint8Array): number {
    const signatureCount = readShortVecLength(txn);
    const messageOffset = signatureCount.size + (signatureCount.length * 64);
    if (messageOffset >= txn.length) {
        throw "SolanaProofOfPermission: transaction bytes ended before message";
    }
    return (txn[messageOffset] & 0x80) !== 0
        ? ProofOfPermission.SCHEME_VERSIONED
        : ProofOfPermission.SCHEME_UNVERSIONED;
}

export class ContractID {
    knownChainName: string; // mainnet-beta/testnet/devnet
    programId: PublicKey;

    constructor({knownChainName, programId}: {knownChainName: string, programId: string}) {
        this.knownChainName = knownChainName;
        this.programId = new PublicKey(programId);
    }

    static deserialize(deserializer: Deserializer): Result<ContractID> {
        const task = (_extra: Record<string, any>) => {
            const knownChainName = deserializer.deserializeStr();
            const programId = new PublicKey(deserializer.deserializeBytes());
            return new ContractID({knownChainName, programId: programId.toBase58()});
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    static fromBytes(bytes: Uint8Array): Result<ContractID> {
        const task = (_extra: Record<string, any>) => {
            const deserializer = new Deserializer(bytes);
            return ContractID.deserialize(deserializer).unwrapOrThrow('SolanaContractID.fromBytes failed with deserialization error');
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    static fromHex(hex: string): Result<ContractID> {
        const task = (_extra: Record<string, any>) => {
            return ContractID.fromBytes(hexToBytes(hex)).unwrapOrThrow('SolanaContractID.fromHex failed with fromBytes error');
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    serialize(serializer: Serializer): void {
        serializer.serializeStr(this.knownChainName);
        serializer.serializeBytes(this.programId.toBytes());
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

export class ProofOfPermission {
    static readonly SCHEME_UNVERSIONED = 0;
    static readonly SCHEME_VERSIONED = 1;

    scheme: number;
    txnBytes: Uint8Array;

    private constructor(scheme: number, txnBytes: Uint8Array) {
        this.scheme = scheme;
        this.txnBytes = new Uint8Array(txnBytes);
    }

    static newVersioned(txn: Uint8Array): ProofOfPermission {
        return new ProofOfPermission(ProofOfPermission.SCHEME_VERSIONED, txn);
    }

    static newUnversioned(txn: Uint8Array): ProofOfPermission {
        return new ProofOfPermission(ProofOfPermission.SCHEME_UNVERSIONED, txn);
    }

    static deserialize(deserializer: Deserializer): Result<ProofOfPermission> {
        const task = (extra: Record<string, any>) => {
            const scheme = deserializer.deserializeU8();
            extra['scheme'] = scheme;
            const bytes = deserializer.deserializeBytes();
            if (scheme == ProofOfPermission.SCHEME_VERSIONED) {
                return new ProofOfPermission(ProofOfPermission.SCHEME_VERSIONED, bytes);
            } else if (scheme == ProofOfPermission.SCHEME_UNVERSIONED) {
                return new ProofOfPermission(ProofOfPermission.SCHEME_UNVERSIONED, bytes);
            } else {
                throw 'SolanaProofOfPermission.deserialize failed with unknown scheme';
            }
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    static fromBytes(bytes: Uint8Array): Result<ProofOfPermission> {
        const task = (_extra: Record<string, any>) => {
            const deserializer = new Deserializer(bytes);
            return ProofOfPermission.deserialize(deserializer).unwrapOrThrow('SolanaProofOfPermission.fromBytes failed with deserialization error');
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    static fromHex(hex: string): Result<ProofOfPermission> {
        const task = (_extra: Record<string, any>) => {
            return ProofOfPermission.fromBytes(hexToBytes(hex)).unwrapOrThrow('SolanaProofOfPermission.fromHex failed with fromBytes error');
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    serialize(serializer: Serializer): void {
        serializer.serializeU8(this.scheme);
        if (this.scheme == ProofOfPermission.SCHEME_VERSIONED) {
            serializer.serializeBytes(this.txnBytes);
        } else if (this.scheme == ProofOfPermission.SCHEME_UNVERSIONED) {
            serializer.serializeBytes(this.txnBytes);
        }
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
