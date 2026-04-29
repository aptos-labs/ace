// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { Deserializer, Serializer } from "@aptos-labs/ts-sdk";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import { PublicKey, Transaction, VersionedTransaction } from "@solana/web3.js";
import { Result } from "../result";

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

    toPrettyMessage(indent: number = 0): string {
        const pad = '  '.repeat(indent);
        return `\n${pad}knownChainName: ${this.knownChainName}\n${pad}programId: ${this.programId.toBase58()}`;
    }
}

export class ProofOfPermission {
    static readonly SCHEME_UNVERSIONED = 0;
    static readonly SCHEME_VERSIONED = 1;

    scheme: number;
    inner: Transaction | VersionedTransaction;

    private constructor(scheme: number, inner: Transaction | VersionedTransaction) {
        this.scheme = scheme;
        this.inner = inner;
    }

    static newVersioned(txn: VersionedTransaction): ProofOfPermission {
        return new ProofOfPermission(ProofOfPermission.SCHEME_VERSIONED, txn);
    }

    static newUnversioned(txn: Transaction): ProofOfPermission {
        return new ProofOfPermission(ProofOfPermission.SCHEME_UNVERSIONED, txn);
    }

    static deserialize(deserializer: Deserializer): Result<ProofOfPermission> {
        const task = (extra: Record<string, any>) => {
            const scheme = deserializer.deserializeU8();
            extra['scheme'] = scheme;
            const bytes = deserializer.deserializeBytes();
            if (scheme == ProofOfPermission.SCHEME_VERSIONED) {
                const inner = VersionedTransaction.deserialize(bytes);
                return new ProofOfPermission(ProofOfPermission.SCHEME_VERSIONED, inner);
            } else if (scheme == ProofOfPermission.SCHEME_UNVERSIONED) {
                const inner = Transaction.from(Buffer.from(bytes));
                return new ProofOfPermission(ProofOfPermission.SCHEME_UNVERSIONED, inner);
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
            serializer.serializeBytes((this.inner as VersionedTransaction).serialize());
        } else if (this.scheme == ProofOfPermission.SCHEME_UNVERSIONED) {
            serializer.serializeBytes((this.inner as Transaction).serialize());
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
