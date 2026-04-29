// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import {
    AccountAddress,
    AccountPublicKey,
    AnyPublicKey,
    AnySignature,
    Aptos,
    AptosConfig,
    Deserializer,
    Ed25519PublicKey,
    Ed25519Signature,
    EntryFunctionArgumentTypes,
    FederatedKeylessPublicKey,
    KeylessPublicKey,
    KeylessSignature,
    MoveValue,
    MultiEd25519PublicKey,
    MultiEd25519Signature,
    MultiKey,
    MultiKeySignature,
    Network,
    PublicKey,
    Serializer,
    Signature,
    SimpleEntryFunctionArgumentTypes
} from "@aptos-labs/ts-sdk";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import { Result } from "../result";
import type { FullDecryptionDomain } from "./index";

export class ContractID {
    chainId: number;
    moduleAddr: AccountAddress;
    moduleName: string;
    functionName: string;

    constructor(chainId: number, moduleAddr: AccountAddress, moduleName: string, functionName: string) {
        this.chainId = chainId;
        this.moduleAddr = moduleAddr;
        this.moduleName = moduleName;
        this.functionName = functionName;
    }
    
    static dummy(): ContractID {
        return new ContractID(0, AccountAddress.fromString("0x1"), "module3", "function3");
    }
    
    static deserialize(deserializer: Deserializer): Result<ContractID> {
        const task = (_extra: Record<string, any>) => {
            const chainId = deserializer.deserializeU8();
            const moduleAddr = deserializer.deserialize(AccountAddress);
            const moduleName = deserializer.deserializeStr();
            const functionName = deserializer.deserializeStr();
            return new ContractID(chainId, moduleAddr, moduleName, functionName);
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }
    
    static fromBytes(bytes: Uint8Array): Result<ContractID> {
        const task = (_extra: Record<string, any>) => {
            const deserializer = new Deserializer(bytes);
            const ret = ContractID.deserialize(deserializer).unwrapOrThrow('AptosContractID.fromBytes failed with deserialization error');
            if (deserializer.remaining() !== 0) {
                throw 'AptosContractID.fromBytes failed with trailing bytes';
            }
            return ret;
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }
    
    static fromHex(hex: string): Result<ContractID> {
        const task = (_extra: Record<string, any>) => {
            return ContractID.fromBytes(hexToBytes(hex)).unwrapOrThrow('AptosContractID.fromHex failed with fromBytes error');
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }
    
    serialize(serializer: Serializer): void {
        serializer.serializeU8(this.chainId);
        serializer.serialize(this.moduleAddr);
        serializer.serializeStr(this.moduleName);
        serializer.serializeStr(this.functionName);
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
        return `\n${pad}chainId: ${this.chainId}\n${pad}moduleAddr: ${this.moduleAddr.toStringLong()}\n${pad}moduleName: ${this.moduleName}\n${pad}functionName: ${this.functionName}`;
    }
}

const PK_SCHEME_ED25519 = 0;
const PK_SCHEME_ANY = 1;
const PK_SCHEME_MULTI_ED25519 = 2;
const PK_SCHEME_MULTI_KEY = 3;
const PK_SCHEME_KEYLESS = 4;
const PK_SCHEME_FEDERATED_KEYLESS = 5;

function getPublicKeyScheme(publicKey: PublicKey): number {
    if (publicKey instanceof Ed25519PublicKey) {
        return PK_SCHEME_ED25519;
    } else if (publicKey instanceof AnyPublicKey) {
        return PK_SCHEME_ANY;
    } else if (publicKey instanceof MultiEd25519PublicKey) {
        return PK_SCHEME_MULTI_ED25519;
    } else if (publicKey instanceof MultiKey) {
        return PK_SCHEME_MULTI_KEY;
    } else if (publicKey instanceof KeylessPublicKey) {
        return PK_SCHEME_KEYLESS;
    } else if (publicKey instanceof FederatedKeylessPublicKey) {
        return PK_SCHEME_FEDERATED_KEYLESS;
    } else {
        throw 'ACE.Aptos.getPublicKeyScheme failed with unsupported public key type';
    }
}

function deserializePublicKey(scheme: number, deserializer: Deserializer): PublicKey {
    if (scheme === PK_SCHEME_ED25519) {
        return deserializer.deserialize(Ed25519PublicKey);
    } else if (scheme === PK_SCHEME_ANY) {
        return deserializer.deserialize(AnyPublicKey);
    } else if (scheme === PK_SCHEME_MULTI_ED25519) {
        return deserializer.deserialize(MultiEd25519PublicKey);
    } else if (scheme === PK_SCHEME_MULTI_KEY) {
        return deserializer.deserialize(MultiKey);
    } else if (scheme === PK_SCHEME_KEYLESS) {
        return deserializer.deserialize(KeylessPublicKey);
    } else if (scheme === PK_SCHEME_FEDERATED_KEYLESS) {
        return deserializer.deserialize(FederatedKeylessPublicKey);
    } else {
        throw 'ACE.Aptos.deserializePublicKey failed with unsupported public key scheme';
    }
}

const SIG_SCHEME_ED25519 = 0;
const SIG_SCHEME_ANY = 1;
const SIG_SCHEME_MULTI_ED25519 = 2;
const SIG_SCHEME_MULTI_KEY = 3;
const SIG_SCHEME_KEYLESS = 4;

function getSignatureScheme(signature: Signature): number {
    if (signature instanceof Ed25519Signature) {
        return SIG_SCHEME_ED25519;
    } else if (signature instanceof AnySignature) {
        return SIG_SCHEME_ANY;
    } else if (signature instanceof MultiEd25519Signature) {
        return SIG_SCHEME_MULTI_ED25519;
    } else if (signature instanceof MultiKeySignature) {
        return SIG_SCHEME_MULTI_KEY;
    } else if (signature instanceof KeylessSignature) {
        return SIG_SCHEME_KEYLESS;
    } else {
        throw 'ACE.Aptos.getSignatureScheme failed with unsupported signature type';
    }
}

function deserializeSignature(scheme: number, deserializer: Deserializer): Signature {
    if (scheme === SIG_SCHEME_ED25519) {
        return deserializer.deserialize(Ed25519Signature);
    } else if (scheme === SIG_SCHEME_ANY) {
        return deserializer.deserialize(AnySignature);
    } else if (scheme === SIG_SCHEME_MULTI_ED25519) {
        return deserializer.deserialize(MultiEd25519Signature);
    } else if (scheme === SIG_SCHEME_MULTI_KEY) {
        return deserializer.deserialize(MultiKeySignature);
    } else if (scheme === SIG_SCHEME_KEYLESS) {
        return deserializer.deserialize(KeylessSignature);
    } else {
        throw 'ACE.Aptos.deserializeSignature failed with unsupported signature scheme';
    }
}

export class ProofOfPermission {
    userAddr: AccountAddress;
    publicKeyScheme: number;
    publicKey: AccountPublicKey;
    signatureScheme: number;
    signature: Signature;
    fullMessage: string;

    constructor({userAddr, publicKey, signature, fullMessage}: {userAddr: AccountAddress, publicKey: PublicKey, signature: Signature, fullMessage: string}) {
        this.userAddr = userAddr;
        this.publicKey = publicKey as AccountPublicKey;
        this.signature = signature;
        this.fullMessage = fullMessage;
        this.publicKeyScheme = getPublicKeyScheme(publicKey);
        this.signatureScheme = getSignatureScheme(signature);
    }

    static deserialize(deserializer: Deserializer): Result<ProofOfPermission> {
        const task = (_extra: Record<string, any>) => {
            const userAddr = deserializer.deserialize(AccountAddress);
            const authenticationScheme = deserializer.deserializeU8();
            const publicKey = deserializePublicKey(authenticationScheme, deserializer);
            const signatureScheme = deserializer.deserializeU8();
            const signature = deserializeSignature(signatureScheme, deserializer);
            const fullMessage = deserializer.deserializeStr();
            return new ProofOfPermission({userAddr, publicKey, signature, fullMessage});
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    static fromBytes(bytes: Uint8Array): Result<ProofOfPermission> {
        const task = (_extra: Record<string, any>) => {
            const deserializer = new Deserializer(bytes);
            return ProofOfPermission.deserialize(deserializer).unwrapOrThrow('AptosProofOfPermission.fromBytes failed with deserialization error');
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    static fromHex(hex: string): Result<ProofOfPermission> {
        const task = (_extra: Record<string, any>) => {
            return ProofOfPermission.fromBytes(hexToBytes(hex)).unwrapOrThrow('AptosProofOfPermission.fromHex failed with fromBytes error');
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    serialize(serializer: Serializer): void {
        serializer.serialize(this.userAddr);
        serializer.serializeU8(this.publicKeyScheme);
        serializer.serialize(this.publicKey);
        serializer.serializeU8(this.signatureScheme);
        serializer.serialize(this.signature);
        serializer.serializeStr(this.fullMessage);
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
