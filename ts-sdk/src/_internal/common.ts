// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { AccountAddress, Aptos, AptosConfig, Deserializer, Network, Serializer } from "@aptos-labs/ts-sdk";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import { Transaction, VersionedTransaction } from "@solana/web3.js";
import { Result } from "../result";
import * as pke from "../pke";
import * as tibe from "../t-ibe";
import { State as NetworkState } from "../network";
import { ContractID as AptosContractID, ProofOfPermission as AptosProofOfPermission } from "./aptos";
import { ContractID as SolanaContractID, ProofOfPermission as SolanaProofOfPermission } from "./solana";

export class AceDeployment {
    apiEndpoint: string;
    contractAddr: AccountAddress;
    apiKey?: string;

    constructor({apiEndpoint, contractAddr, apiKey}: {apiEndpoint: string, contractAddr: AccountAddress, apiKey?: string}) {
        this.apiEndpoint = apiEndpoint;
        this.contractAddr = contractAddr;
        this.apiKey = apiKey;
    }
}

export class ContractID {
    static readonly SCHEME_APTOS = 0;
    static readonly SCHEME_SOLANA = 1;

    scheme: number;
    inner: AptosContractID | SolanaContractID;

    private constructor(scheme: number, inner: AptosContractID | SolanaContractID) {
        this.scheme = scheme;
        this.inner = inner;
    }

    static newAptos({ chainId, moduleAddr, moduleName, functionName }: { chainId: number, moduleAddr: AccountAddress, moduleName: string, functionName: string }) {
        return new ContractID(ContractID.SCHEME_APTOS, new AptosContractID(chainId, moduleAddr, moduleName, functionName));
    }

    static newSolana({ knownChainName, programId }: { knownChainName: string, programId: string }) {
        return new ContractID(ContractID.SCHEME_SOLANA, new SolanaContractID({knownChainName, programId}));
    }

    static dummy(): ContractID {
        return new ContractID(ContractID.SCHEME_APTOS, AptosContractID.dummy());
    }

    static deserialize(deserializer: Deserializer): Result<ContractID> {
        const task = (extra: Record<string, any>) => {
            const scheme = deserializer.deserializeU8();
            extra['scheme'] = scheme;
            if (scheme == ContractID.SCHEME_APTOS) {
                return new ContractID(ContractID.SCHEME_APTOS, AptosContractID.deserialize(deserializer).unwrapOrThrow('ACE.ContractID.deserialize failed in aptos case'));
            } else if (scheme == ContractID.SCHEME_SOLANA) {
                return new ContractID(ContractID.SCHEME_SOLANA, SolanaContractID.deserialize(deserializer).unwrapOrThrow('ACE.ContractID.deserialize failed in solana case'));
            } else {
                throw 'ACE.ContractID.deserialize failed with unknown scheme';
            }
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    static fromBytes(bytes: Uint8Array): Result<ContractID> {
        const task = (_extra: Record<string, any>) => {
            const deserializer = new Deserializer(bytes);
            const result = ContractID.deserialize(deserializer).unwrapOrThrow('ACE.ContractID.fromBytes failed with deserialization error');
            if (deserializer.remaining() !== 0) {
                throw 'ACE.ContractID.fromBytes failed with trailing bytes';
            }
            return result;
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    static fromHex(hex: string): Result<ContractID> {
        const task = (_extra: Record<string, any>) => {
            return ContractID.fromBytes(hexToBytes(hex)).unwrapOrThrow('ACE.ContractID.fromHex failed with fromBytes error');
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    serialize(serializer: Serializer): void {
        serializer.serializeU8(this.scheme);
        if (this.scheme == ContractID.SCHEME_APTOS) {
            (this.inner as AptosContractID).serialize(serializer);
        } else if (this.scheme == ContractID.SCHEME_SOLANA) {
            (this.inner as SolanaContractID).serialize(serializer);
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

    toPrettyMessage(indent: number = 0): string {
        const pad = '  '.repeat(indent);
        const schemeName = this.scheme === ContractID.SCHEME_APTOS ? 'aptos' : 'solana';
        const innerMsg = (this.inner as AptosContractID | SolanaContractID).toPrettyMessage(indent + 2);
        return `\n${pad}scheme: ${schemeName}\n${pad}inner:${innerMsg}`;
    }
}

export class FullDecryptionDomain {
    keypairId: AccountAddress;
    contractId: ContractID;
    domain: Uint8Array;

    constructor({keypairId, contractId, domain}: {keypairId: AccountAddress, contractId: ContractID, domain: Uint8Array}) {
        this.keypairId = keypairId;
        this.contractId = contractId;
        this.domain = domain;
    }

    static dummy(): FullDecryptionDomain {
        return new FullDecryptionDomain({
            keypairId: AccountAddress.ZERO,
            contractId: ContractID.dummy(),
            domain: new Uint8Array(0),
        });
    }

    static deserialize(deserializer: Deserializer): Result<FullDecryptionDomain> {
        const task = (_extra: Record<string, any>) => {
            const keypairId = AccountAddress.deserialize(deserializer);
            const contractId = ContractID.deserialize(deserializer).unwrapOrThrow('ACE.FullDecryptionDomain.deserialize failed with ContractID deserialization error');
            const domain = deserializer.deserializeBytes();
            return new FullDecryptionDomain({keypairId, contractId, domain});
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    static fromBytes(bytes: Uint8Array): Result<FullDecryptionDomain> {
        const task = (_extra: Record<string, any>) => {
            const deserializer = new Deserializer(bytes);
            const ret = FullDecryptionDomain.deserialize(deserializer).unwrapOrThrow('ACE.FullDecryptionDomain.fromBytes failed with deserialization error');
            if (deserializer.remaining() !== 0) {
                throw 'ACE.FullDecryptionDomain.fromBytes failed with trailing bytes';
            }
            return ret;
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    static fromHex(hex: string): Result<FullDecryptionDomain> {
        const task = (_extra: Record<string, any>) => {
            return FullDecryptionDomain.fromBytes(hexToBytes(hex)).unwrapOrThrow('ACE.FullDecryptionDomain.fromHex failed with fromBytes error');
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    serialize(serializer: Serializer): void {
        this.keypairId.serialize(serializer);
        this.contractId.serialize(serializer);
        serializer.serializeBytes(this.domain);
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
        return `\n${pad}keypairId: ${this.keypairId.toStringLong()}\n${pad}contractId:${this.contractId.toPrettyMessage(indent + 1)}\n${pad}domain: 0x${bytesToHex(this.domain)}`;
    }

    getSolanaContractID(): SolanaContractID {
        if (this.contractId.scheme != ContractID.SCHEME_SOLANA) {
            throw 'ACE.FullDecryptionDomain.getSolanaContractID failed with wrong scheme';
        }
        return this.contractId.inner as SolanaContractID;
    }

    getAptosContractID(): AptosContractID {
        if (this.contractId.scheme != ContractID.SCHEME_APTOS) {
            throw 'ACE.FullDecryptionDomain.getAptosContractID failed with wrong scheme';
        }
        return this.contractId.inner as AptosContractID;
    }
}

export class ProofOfPermission {
    static readonly SCHEME_APTOS = 0;
    static readonly SCHEME_SOLANA = 1;

    scheme: number;
    inner: AptosProofOfPermission | SolanaProofOfPermission;

    private constructor(scheme: number, inner: AptosProofOfPermission | SolanaProofOfPermission) {
        this.scheme = scheme;
        this.inner = inner;
    }

    static createAptos({ userAddr, publicKey, signature, fullMessage }: { userAddr: AccountAddress, publicKey: any, signature: any, fullMessage: string }) {
        return new ProofOfPermission(ProofOfPermission.SCHEME_APTOS, new AptosProofOfPermission({userAddr, publicKey, signature, fullMessage}));
    }

    static createSolana({ txn }: { txn: Uint8Array }) {
        try {
            const versioned = VersionedTransaction.deserialize(txn);
            if (versioned.version !== 'legacy') {
                return new ProofOfPermission(ProofOfPermission.SCHEME_SOLANA, SolanaProofOfPermission.newVersioned(versioned));
            }
        } catch {}
        const legacy = Transaction.from(Buffer.from(txn));
        return new ProofOfPermission(ProofOfPermission.SCHEME_SOLANA, SolanaProofOfPermission.newUnversioned(legacy));
    }

    static deserialize(deserializer: Deserializer): Result<ProofOfPermission> {
        const task = (extra: Record<string, any>) => {
            const scheme = deserializer.deserializeU8();
            extra['scheme'] = scheme;
            if (scheme == ProofOfPermission.SCHEME_APTOS) {
                return new ProofOfPermission(ProofOfPermission.SCHEME_APTOS, AptosProofOfPermission.deserialize(deserializer).unwrapOrThrow('ACE.ProofOfPermission.deserialize failed in aptos case'));
            } else if (scheme == ProofOfPermission.SCHEME_SOLANA) {
                return new ProofOfPermission(ProofOfPermission.SCHEME_SOLANA, SolanaProofOfPermission.deserialize(deserializer).unwrapOrThrow('ACE.ProofOfPermission.deserialize failed in solana case'));
            } else {
                throw 'ACE.ProofOfPermission.deserialize failed with unknown scheme';
            }
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    static fromBytes(bytes: Uint8Array): Result<ProofOfPermission> {
        const task = (_extra: Record<string, any>) => {
            const deserializer = new Deserializer(bytes);
            return ProofOfPermission.deserialize(deserializer).unwrapOrThrow('ACE.ProofOfPermission.fromBytes failed with deserialization error');
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    static fromHex(hex: string): Result<ProofOfPermission> {
        const task = (_extra: Record<string, any>) => {
            return ProofOfPermission.fromBytes(hexToBytes(hex)).unwrapOrThrow('ACE.ProofOfPermission.fromHex failed with fromBytes error');
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    serialize(serializer: Serializer): void {
        serializer.serializeU8(this.scheme);
        if (this.scheme == ProofOfPermission.SCHEME_APTOS) {
            (this.inner as AptosProofOfPermission).serialize(serializer);
        } else if (this.scheme == ProofOfPermission.SCHEME_SOLANA) {
            (this.inner as SolanaProofOfPermission).serialize(serializer);
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

export class DecryptionRequestPayload {
    keypairId: AccountAddress;
    epoch: number;
    contractId: ContractID;
    domain: Uint8Array;
    ephemeralEncKey: pke.EncryptionKey;

    constructor({keypairId, epoch, contractId, domain, ephemeralEncKey}: {keypairId: AccountAddress, epoch: number, contractId: ContractID, domain: Uint8Array, ephemeralEncKey: pke.EncryptionKey}) {
        this.keypairId = keypairId;
        this.epoch = epoch;
        this.contractId = contractId;
        this.domain = domain;
        this.ephemeralEncKey = ephemeralEncKey;
    }

    static deserialize(deserializer: Deserializer): Result<DecryptionRequestPayload> {
        const task = (_extra: Record<string, any>) => {
            const keypairId = AccountAddress.deserialize(deserializer);
            const epoch = Number(deserializer.deserializeU64());
            const contractId = ContractID.deserialize(deserializer).unwrapOrThrow('ACE.DecryptionRequestPayload.deserialize failed with ContractID deserialization error');
            const domain = deserializer.deserializeBytes();
            const ephemeralEncKey = pke.EncryptionKey.deserialize(deserializer).unwrapOrThrow('ACE.DecryptionRequestPayload.deserialize failed with ephemeralEncKey deserialization error');
            return new DecryptionRequestPayload({keypairId, epoch, contractId, domain, ephemeralEncKey});
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    static fromBytes(bytes: Uint8Array): Result<DecryptionRequestPayload> {
        const task = (_extra: Record<string, any>) => {
            const deserializer = new Deserializer(bytes);
            const ret = DecryptionRequestPayload.deserialize(deserializer).unwrapOrThrow('ACE.DecryptionRequestPayload.fromBytes failed with deserialization error');
            if (deserializer.remaining() !== 0) {
                throw 'ACE.DecryptionRequestPayload.fromBytes failed with trailing bytes';
            }
            return ret;
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    static fromHex(hex: string): Result<DecryptionRequestPayload> {
        const task = (_extra: Record<string, any>) => {
            return DecryptionRequestPayload.fromBytes(hexToBytes(hex)).unwrapOrThrow('ACE.DecryptionRequestPayload.fromHex failed with fromBytes error');
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    serialize(serializer: Serializer): void {
        this.keypairId.serialize(serializer);
        serializer.serializeU64(BigInt(this.epoch));
        this.contractId.serialize(serializer);
        serializer.serializeBytes(this.domain);
        this.ephemeralEncKey.serialize(serializer);
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
        return `${pad}ACE Decryption Request\n${pad}keypairId: ${this.keypairId.toStringLong()}\n${pad}epoch: ${this.epoch}\n${pad}contractId:${this.contractId.toPrettyMessage(indent + 1)}\n${pad}domain: 0x${bytesToHex(this.domain)}\n${pad}ephemeralEncKey: ${this.ephemeralEncKey.toHex()}`;
    }
}

export class RequestForDecryptionKey {
    requestPayload: DecryptionRequestPayload;
    proof: ProofOfPermission;

    constructor({requestPayload, proof}: {requestPayload: DecryptionRequestPayload, proof: ProofOfPermission}) {
        this.requestPayload = requestPayload;
        this.proof = proof;
    }

    static deserialize(deserializer: Deserializer): Result<RequestForDecryptionKey> {
        const task = (_extra: Record<string, any>) => {
            const requestPayload = DecryptionRequestPayload.deserialize(deserializer).unwrapOrThrow('ACE.RequestForDecryptionKey.deserialize failed with DecryptionRequestPayload deserialization error');
            const proof = ProofOfPermission.deserialize(deserializer).unwrapOrThrow('ACE.RequestForDecryptionKey.deserialize failed with ProofOfPermission deserialization error');
            return new RequestForDecryptionKey({requestPayload, proof});
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    static fromBytes(bytes: Uint8Array): Result<RequestForDecryptionKey> {
        const task = (_extra: Record<string, any>) => {
            const deserializer = new Deserializer(bytes);
            return RequestForDecryptionKey.deserialize(deserializer).unwrapOrThrow('ACE.RequestForDecryptionKey.fromBytes failed with deserialization error');
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    static fromHex(hex: string): Result<RequestForDecryptionKey> {
        const task = (_extra: Record<string, any>) => {
            return RequestForDecryptionKey.fromBytes(hexToBytes(hex)).unwrapOrThrow('ACE.RequestForDecryptionKey.fromHex failed with fromBytes error');
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    serialize(serializer: Serializer): void {
        this.requestPayload.serialize(serializer);
        this.proof.serialize(serializer);
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

export async function fetchNetworkStateAndBuildRequest(
    aceDeployment: AceDeployment,
    fullDecryptionDomain: FullDecryptionDomain,
    ephemeralEncryptionKey: pke.EncryptionKey,
): Promise<{networkState: NetworkState, request: DecryptionRequestPayload}> {
    const aptos = createAptos(aceDeployment.apiEndpoint);
    const aceContractAddr = aceDeployment.contractAddr.toStringLong();

    const [stateHex] = await aptos.view({
        payload: {
            function: `${aceContractAddr}::network::state_view_v0_bcs` as `${string}::${string}::${string}`,
            typeArguments: [],
            functionArguments: [],
        },
    });
    const stateBytes = hexToBytes((stateHex as string).replace(/^0x/, ''));
    const networkState = NetworkState.fromBytes(stateBytes).unwrapOrThrow('ACE: parse network state');

    const request = new DecryptionRequestPayload({
        keypairId: fullDecryptionDomain.keypairId,
        epoch: networkState.epoch,
        contractId: fullDecryptionDomain.contractId,
        domain: fullDecryptionDomain.domain,
        ephemeralEncKey: ephemeralEncryptionKey,
    });

    return {networkState, request};
}

export async function decryptCore({aceDeployment, networkState, request, proof, ephemeralDecryptionKey, ciphertext}: {
    aceDeployment: AceDeployment,
    networkState: NetworkState,
    request: DecryptionRequestPayload,
    proof: ProofOfPermission,
    ephemeralDecryptionKey: pke.DecryptionKey,
    ciphertext: Uint8Array,
}): Promise<Result<Uint8Array>> {
    return Result.captureAsync({
        task: async (_extra) => {
            const aptos = createAptos(aceDeployment.apiEndpoint);
            const aceContractAddr = aceDeployment.contractAddr.toStringLong();

            const nodeInfos = await Promise.all(networkState.curNodes.map(async (nodeAddr) => {
                const addrStr = nodeAddr.toStringLong();
                const [[endpoint], [ekHex]] = await Promise.all([
                    aptos.view({
                        payload: {
                            function: `${aceContractAddr}::worker_config::get_endpoint` as `${string}::${string}::${string}`,
                            typeArguments: [],
                            functionArguments: [addrStr],
                        },
                    }),
                    aptos.view({
                        payload: {
                            function: `${aceContractAddr}::worker_config::get_pke_enc_key_bcs` as `${string}::${string}::${string}`,
                            typeArguments: [],
                            functionArguments: [addrStr],
                        },
                    }),
                ]);
                const nodeEncKey = pke.EncryptionKey.fromBytes(hexToBytes((ekHex as string).replace(/^0x/, '')))
                    .unwrapOrThrow(`ACE.decryptCore: parse pke enc key for ${addrStr}`);
                return { endpoint: endpoint as string, nodeEncKey };
            }));

            const reqBytes = new RequestForDecryptionKey({requestPayload: request, proof}).toBytes();

            const idkShares = (await Promise.all(nodeInfos.map(async ({endpoint, nodeEncKey}, i) => {
                const nodeAddr = networkState.curNodes[i].toStringLong();
                try {
                    const encReqHex = pke.encrypt({encryptionKey: nodeEncKey, plaintext: reqBytes}).toHex();
                    const ctrl = new AbortController();
                    const tid = setTimeout(() => ctrl.abort(), 8000);
                    const resp = await fetch(endpoint, {method: 'POST', body: encReqHex, signal: ctrl.signal});
                    clearTimeout(tid);
                    if (!resp.ok) {
                        const body = await resp.text().catch(() => '');
                        console.log(`  [decrypt] worker ${nodeAddr} (${endpoint}): HTTP ${resp.status} — ${body.trim().slice(0, 120)}`);
                        return null;
                    }
                    const hexText = (await resp.text()).trim();
                    const respCt = pke.Ciphertext.fromHex(hexText).okValue ?? null;
                    if (respCt === null) {
                        console.log(`  [decrypt] worker ${nodeAddr} (${endpoint}): response ciphertext parse failed`);
                        return null;
                    }
                    const shareBytes = pke.decrypt({decryptionKey: ephemeralDecryptionKey, ciphertext: respCt}).okValue ?? null;
                    if (shareBytes === null) {
                        console.log(`  [decrypt] worker ${nodeAddr} (${endpoint}): response decryption failed`);
                        return null;
                    }
                    const share = tibe.IdentityDecryptionKeyShare.fromBytes(shareBytes).okValue ?? null;
                    if (share === null) {
                        console.log(`  [decrypt] worker ${nodeAddr} (${endpoint}): share parse failed`);
                    } else {
                        console.log(`  [decrypt] worker ${nodeAddr} (${endpoint}): OK`);
                    }
                    return share;
                } catch (e) {
                    console.log(`  [decrypt] worker ${nodeAddr} (${endpoint}): fetch error — ${e}`);
                    return null;
                }
            }))).filter((s): s is tibe.IdentityDecryptionKeyShare => s !== null);

            if (idkShares.length < networkState.curThreshold) {
                throw `ACE.decryptCore: need ${networkState.curThreshold} shares, got ${idkShares.length}`;
            }

            return tibe.decrypt({
                idkShares,
                ciphertext: tibe.Ciphertext.fromBytes(ciphertext).unwrapOrThrow('ACE.decryptCore: parse ciphertext'),
            }).unwrapOrThrow('ACE.decryptCore: tibe.decrypt failed');
        },
        recordsExecutionTimeMs: true,
    });
}

export function createAptos(rpcUrl?: string): Aptos {
    return new Aptos(new AptosConfig({
        network: Network.CUSTOM,
        fullnode: rpcUrl ?? 'http://localhost:8080/v1',
    }));
}
