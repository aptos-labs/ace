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

export async function verifyPermission({fullDecryptionDomain, proof, rpcEndpoint, apiKey}: {fullDecryptionDomain: FullDecryptionDomain, proof: ProofOfPermission, rpcEndpoint?: string, apiKey?: string}): Promise<Result<void>> {
    const task = async (extra: Record<string, any>) => {
        const networkName = getChainNameFromChainId(fullDecryptionDomain.getAptosContractID().chainId);
        const aptos = createAptos(networkName, rpcEndpoint, apiKey);
    
        // Run all 3 tasks in parallel
        const [verifySigResult, checkAuthKeyResult, checkPermissionResult] = await Promise.all([
            verifySig({aptos, fullDecryptionDomain, proof}),
            checkAuthKey({aptos, userAddr: proof.userAddr, publicKey: proof.publicKey}),
            checkPermission({aptos, fullDecryptionDomain, proof})
        ]);
    
        extra['verifySigResult'] = verifySigResult;
        extra['checkAuthKeyResult'] = checkAuthKeyResult;
        extra['checkPermissionResult'] = checkPermissionResult;

        if (!verifySigResult.isOk || !checkAuthKeyResult.isOk || !checkPermissionResult.isOk) {
            throw 'ACE.Aptos.verifyPermission failed with sub-check failures';
        }
    };
    return await Result.captureAsync({task, recordsExecutionTimeMs: true});
}

async function verifySig({aptos, fullDecryptionDomain, proof}: {aptos: Aptos, fullDecryptionDomain: FullDecryptionDomain, proof: ProofOfPermission}): Promise<Result<void>> {
    const task = async (extra: Record<string, any>) => {
        const msgToSign = fullDecryptionDomain.toPrettyMessage();
        const msgToSignHex = bytesToHex(new TextEncoder().encode(msgToSign));
        const fullMessageSeemsFromPetra = proof.fullMessage.includes(msgToSign);
        const fullMessageSeemsFromAptosConnect = proof.fullMessage.includes(msgToSignHex);
        extra['msgToSign'] = msgToSign;
        extra['msgToSignHex'] = msgToSignHex;
        extra['fullMessageSeemsFromPetra'] = fullMessageSeemsFromPetra;
        extra['fullMessageSeemsFromAptosConnect'] = fullMessageSeemsFromAptosConnect;
        if (!fullMessageSeemsFromPetra && !fullMessageSeemsFromAptosConnect) throw 'ACE.Aptos.verifySig failed with fullMessage content mismatch';
        const sigValid = await proof.publicKey.verifySignatureAsync({
            aptosConfig: aptos.config,
            message: proof.fullMessage,
            signature: proof.signature
        });
        if (!sigValid) throw 'ACE.Aptos.verifySig failed with signature verification error';
    };
    return await Result.captureAsync({task, recordsExecutionTimeMs: true});
}

async function checkAuthKey({aptos, userAddr, publicKey}: {aptos: Aptos, userAddr: AccountAddress, publicKey: PublicKey}): Promise<Result<void>> {
    const task = async (extra: Record<string, any>) => {
        if (!(publicKey instanceof AccountPublicKey)) {
            throw 'ACE.Aptos.checkAuthKey failed with invalid public key type';
        }
        const onChainAuthKeyBytes = await getAccountAuthKeyBytes(aptos, userAddr);
        const userAuthKeyBytes = publicKey.authKey().bcsToBytes();
        const onChainHex = bytesToHex(onChainAuthKeyBytes);
        const userHex = bytesToHex(userAuthKeyBytes);
        extra['onChainHex'] = onChainHex;
        extra['userHex'] = userHex;
        if (onChainHex !== userHex) throw 'ACE.Aptos.checkAuthKey failed with auth key mismatch';
    };
    return await Result.captureAsync({task, recordsExecutionTimeMs: true});
}

async function checkPermission({aptos, fullDecryptionDomain, proof}: {aptos: Aptos, fullDecryptionDomain: FullDecryptionDomain, proof: ProofOfPermission}): Promise<Result<void>> {
    const task = async (extra: Record<string, any>) => {
        const contractId = fullDecryptionDomain.getAptosContractID();
        const viewFunctionInvocationResult = await view({
            aptos,
            func: `${contractId.moduleAddr.toStringLong()}::${contractId.moduleName}::${contractId.functionName}`,
            typeArguments: [],
            functionArguments: [proof.userAddr, fullDecryptionDomain.domain]
        });
        extra['viewFunctionInvocationResult'] = viewFunctionInvocationResult;
        if (!viewFunctionInvocationResult.isOk) {
            throw 'ACE.Aptos.checkPermission failed with view function invocation error';
        }
        const returnedMoveValue = viewFunctionInvocationResult.okValue;
        if (returnedMoveValue?.toString() !== 'true') {
            throw 'ACE.Aptos.checkPermission failed with access denied';
        }
    };
    return await Result.captureAsync({task, recordsExecutionTimeMs: true});
}

function getChainNameFromChainId(chainId: number): string {
    if (chainId === 1) {
        return "mainnet";
    } else if (chainId === 2) {
        return "testnet";
    } else if (chainId === 4) {
        return "localnet";
    } else if (chainId === 14) {
        return "devnet";
    } else if (chainId >= 104) {
        return "shelbynet";
    } else {
        throw 'ACE.Aptos.getChainNameFromChainId failed with unknown chain id';
    }
}

function createAptos(networkName: string, customEndpoint?: string, apiKey?: string): Aptos {
    const clientConfig = apiKey ? { API_KEY: apiKey } : undefined;
    
    let config: AptosConfig;
    if (customEndpoint) {
        // Use custom endpoint if provided
        config = new AptosConfig({
            network: Network.CUSTOM,
            fullnode: customEndpoint,
            clientConfig
        });
    } else if (networkName === "mainnet") {
        config = new AptosConfig({ network: Network.MAINNET, clientConfig });
    } else if (networkName === "testnet") {
        config = new AptosConfig({ network: Network.TESTNET, clientConfig });
    } else if (networkName === "devnet") {
        config = new AptosConfig({ network: Network.DEVNET, clientConfig });
    } else if (networkName === "localnet") {
        config = new AptosConfig({
            network: Network.LOCAL,
            fullnode: "http://localhost:8080/v1",
            faucet: "http://localhost:8081",
            clientConfig
        });
    } else {
        throw 'ACE.Aptos.createAptos failed with unsupported network name';
    }
    return new Aptos(config);
}

async function getAccountAuthKeyBytes(aptos: Aptos, address: AccountAddress): Promise<Uint8Array> {
    const accountInfo = await aptos.getAccountInfo({ accountAddress: address });
    return hexToBytes(accountInfo.authentication_key.replace('0x', ''));
}

async function view({aptos, func, typeArguments, functionArguments}: {aptos: Aptos, func: `${string}::${string}::${string}`, typeArguments: Array<string>, functionArguments: Array<EntryFunctionArgumentTypes | SimpleEntryFunctionArgumentTypes>}): Promise<Result<MoveValue>> {
    const task = async (extra: Record<string, any>) => {
        extra['func'] = func;
        const returnedMoveValues = await aptos.view({
            payload: {
                function: func,
                typeArguments: typeArguments,
                functionArguments: functionArguments
            }
        });
        extra['returnedMoveValues'] = returnedMoveValues;
        if (returnedMoveValues.length === 0) {
            throw 'ACE.Aptos.view failed with empty response';
        }
        return returnedMoveValues[0]!;
    }
    return await Result.captureAsync({task, recordsExecutionTimeMs: true});
}

