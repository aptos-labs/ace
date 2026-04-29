// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * @module ace
 * 
 * ACE with multi-chain support.
 */

import * as AptosSDK from "@aptos-labs/ts-sdk";
import { AccountAddress, Aptos, AptosConfig, Deserializer, Network, PublicKey, Serializer, Signature } from "@aptos-labs/ts-sdk";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import { Transaction, VersionedTransaction } from "@solana/web3.js";
import { Result } from "../result";
import * as dkg from "../dkg";
import * as pke from "../pke";
import * as tibe from "../t-ibe";
import { State as NetworkState } from "../network";
import { ContractID as AptosContractID, ProofOfPermission as AptosProofOfPermission } from "./aptos";
import { ContractID as SolanaContractID, ProofOfPermission as SolanaProofOfPermission } from "./solana";

export { ContractID as AptosContractID, ProofOfPermission as AptosProofOfPermission } from "./aptos";
export { ContractID as SolanaContractID, ProofOfPermission as SolanaProofOfPermission } from "./solana";

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

// I think this no longer needs to be exported.
class ContractID {
    static readonly SCHEME_APTOS = 0;
    static readonly SCHEME_SOLANA = 1;
    
    scheme: number;
    inner: AptosContractID | SolanaContractID;

    private constructor(scheme: number, inner: AptosContractID | SolanaContractID) {
        this.scheme = scheme;
        this.inner = inner;
    }
    
    static newAptos({ chainId, moduleAddr, moduleName, functionName }: { chainId: number, moduleAddr: AptosSDK.AccountAddress, moduleName: string, functionName: string }) {
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

// I think this no longer needs to be exported.
class FullDecryptionDomain {
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

// I think this no longer needs to be exported.
class ProofOfPermission {
    static readonly SCHEME_APTOS = 0;
    static readonly SCHEME_SOLANA = 1;

    scheme: number;
    inner: AptosProofOfPermission | SolanaProofOfPermission;

    private constructor(scheme: number, inner: AptosProofOfPermission | SolanaProofOfPermission) {
        this.scheme = scheme;
        this.inner = inner;
    }

    static createAptos({ userAddr, publicKey, signature, fullMessage }: { userAddr: AptosSDK.AccountAddress, publicKey: AptosSDK.PublicKey, signature: AptosSDK.Signature, fullMessage: string }) {
        return new ProofOfPermission(ProofOfPermission.SCHEME_APTOS, new AptosProofOfPermission({userAddr, publicKey, signature, fullMessage}));
    }

    static createSolana({ txn }: { txn: Uint8Array }) {
        // VersionedTransaction.deserialize() succeeds for BOTH legacy and v0 transactions
        // without throwing — it wraps a legacy message as version='legacy'.  We must
        // check .version explicitly; catching exceptions is not sufficient.
        try {
            const versioned = VersionedTransaction.deserialize(txn);
            if (versioned.version !== 'legacy') {
                // Actual versioned (v0+) transaction
                return new ProofOfPermission(ProofOfPermission.SCHEME_SOLANA, SolanaProofOfPermission.newVersioned(versioned));
            }
        } catch {}
        // Legacy transaction (or VersionedTransaction wrapping a legacy message)
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

/**
 * How to use:
 * 1. construct a DecryptionSession with the necessary parameters;
 * 2. call getRequestToSign() to get the request to sign;
 * 3. sign the request;
 * 4. call decryptWithProof() to decrypt the ciphertext.
 */
export class AptosDecryptionSession {
    aceDeployment: AceDeployment;
    fullDecryptionDomain: FullDecryptionDomain;
    ciphertext: Uint8Array;
    ephemeralDecryptionKey: pke.DecryptionKey;
    ephemeralEncryptionKey: pke.EncryptionKey;
    request: DecryptionRequestPayload | undefined;
    networkState: NetworkState | undefined;

    constructor({aceDeployment, keypairId, chainId, moduleAddr, moduleName, functionName, domain, ciphertext}: {
        aceDeployment?: AceDeployment,
        keypairId: AccountAddress,
        chainId: number,
        moduleAddr: AccountAddress,
        moduleName: string,
        functionName?: string,
        domain: Uint8Array,
        ciphertext: Uint8Array,
    }) {
        if (aceDeployment === undefined) throw 'default aceDeployment is not supported yet';
        this.aceDeployment = aceDeployment;
        if (functionName === undefined) functionName = 'check_permission';
        const contractId = ContractID.newAptos({chainId, moduleAddr, moduleName, functionName});
        this.fullDecryptionDomain = new FullDecryptionDomain({keypairId, contractId, domain});
        this.ciphertext = ciphertext;
        const {encryptionKey, decryptionKey} = pke.keygen();
        this.ephemeralDecryptionKey = decryptionKey;
        this.ephemeralEncryptionKey = encryptionKey;
    }

    async getRequestToSign(): Promise<string> {
        const {networkState, request} = await fetchNetworkStateAndBuildRequest(
            this.aceDeployment, this.fullDecryptionDomain, this.ephemeralEncryptionKey);
        this.networkState = networkState;
        this.request = request;
        return request.toPrettyMessage();
    }

    async decryptWithProof({userAddr, publicKey, signature, fullMessage}: {
        userAddr: AccountAddress,
        publicKey: PublicKey,
        signature: Signature,
        fullMessage?: string,
    }): Promise<Result<Uint8Array>> {
        if (fullMessage === undefined) fullMessage = this.request!.toPrettyMessage();
        const proof = ProofOfPermission.createAptos({userAddr, publicKey, signature, fullMessage});
        return decryptCore({
            aceDeployment: this.aceDeployment,
            networkState: this.networkState!,
            request: this.request!,
            proof,
            ephemeralDecryptionKey: this.ephemeralDecryptionKey,
            ciphertext: this.ciphertext,
        });
    }
}

/**
 * How to use:
 * 1. construct a SolanaDecryptionSession with the necessary parameters;
 * 2. call getRequestToSign() to get the bytes to embed in the transaction;
 * 3. build and sign a Solana transaction calling assert_access(fullRequestBytes);
 * 4. call decryptWithProof() with the signed transaction bytes.
 */
export class SolanaDecryptionSession {
    aceDeployment: AceDeployment;
    fullDecryptionDomain: FullDecryptionDomain;
    ciphertext: Uint8Array;
    ephemeralDecryptionKey: pke.DecryptionKey;
    ephemeralEncryptionKey: pke.EncryptionKey;
    request: DecryptionRequestPayload | undefined;
    networkState: NetworkState | undefined;

    constructor({aceDeployment, keypairId, knownChainName, programId, domain, ciphertext}: {
        aceDeployment?: AceDeployment,
        keypairId: AccountAddress,
        knownChainName: string,
        programId: string,
        domain: Uint8Array,
        ciphertext: Uint8Array,
    }) {
        if (aceDeployment === undefined) throw 'default aceDeployment is not supported yet';
        this.aceDeployment = aceDeployment;
        const contractId = ContractID.newSolana({knownChainName, programId});
        this.fullDecryptionDomain = new FullDecryptionDomain({keypairId, contractId, domain});
        this.ciphertext = ciphertext;
        const {encryptionKey, decryptionKey} = pke.keygen();
        this.ephemeralDecryptionKey = decryptionKey;
        this.ephemeralEncryptionKey = encryptionKey;
    }

    /**
     * Fetch network state and return the opaque bytes to embed as the
     * `full_request_bytes` argument when building the assert_access transaction.
     *
     * Layout: keypairId(32) | epoch(8 LE) | BCS(ephemeralEncKey) | BCS(domain)
     *
     * Must be called before decryptWithProof().
     */
    async getRequestToSign(): Promise<Uint8Array> {
        const {networkState, request} = await fetchNetworkStateAndBuildRequest(
            this.aceDeployment, this.fullDecryptionDomain, this.ephemeralEncryptionKey);
        this.networkState = networkState;
        this.request = request;
        const s = new Serializer();
        request.keypairId.serialize(s);
        s.serializeU64(BigInt(request.epoch));
        s.serializeBytes(request.ephemeralEncKey.toBytes());
        s.serializeBytes(request.domain);
        return s.toUint8Array();
    }

    async decryptWithProof({txn}: {txn: Uint8Array}): Promise<Result<Uint8Array>> {
        const proof = ProofOfPermission.createSolana({txn});
        return decryptCore({
            aceDeployment: this.aceDeployment,
            networkState: this.networkState!,
            request: this.request!,
            proof,
            ephemeralDecryptionKey: this.ephemeralDecryptionKey,
            ciphertext: this.ciphertext,
        });
    }
}

class DecryptionRequestPayload {
    keypairId: AptosSDK.AccountAddress;
    epoch: number;
    contractId: ContractID;
    domain: Uint8Array;
    ephemeralEncKey: pke.EncryptionKey;

    constructor({keypairId, epoch, contractId, domain, ephemeralEncKey}: {keypairId: AptosSDK.AccountAddress, epoch: number, contractId: ContractID, domain: Uint8Array, ephemeralEncKey: pke.EncryptionKey}) {
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

class RequestForDecryptionKey {
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

export async function aptosEncrypt({aceDeployment, keypairId, chainId, moduleAddr, moduleName, functionName, domain, plaintext}: {
    aceDeployment?: AceDeployment,
    keypairId: AccountAddress,
    chainId: number,
    moduleAddr: AccountAddress,
    moduleName: string,
    functionName?: string,
    domain: Uint8Array,
    plaintext: Uint8Array,
}): Promise<Result<Uint8Array>> {
    if (aceDeployment === undefined) throw 'default aceDeployment is not supported yet';
    if (functionName === undefined) functionName = 'check_permission';
    return Result.captureAsync({
        task: async (_extra) => {
            const aptos = createAptos(aceDeployment.apiEndpoint);
            const contractId = ContractID.newAptos({chainId, moduleAddr, moduleName, functionName: functionName!});
            const fdd = new FullDecryptionDomain({keypairId, contractId, domain});
            const aceContractAddr = aceDeployment.contractAddr.toStringLong();

            // Fetch DKG session to get master public key (basePoint + resultPk).
            const [hexBytes] = await aptos.view({
                payload: {
                    function: `${aceContractAddr}::dkg::get_session_bcs` as `${string}::${string}::${string}`,
                    typeArguments: [],
                    functionArguments: [keypairId.toStringLong()],
                },
            });
            const sessionBytes = hexToBytes((hexBytes as string).replace(/^0x/, ''));
            const session = dkg.Session.fromBytes(sessionBytes).unwrapOrThrow('ace_ex.aptosEncrypt: parse DKG session');
            if (!session.resultPk) throw 'ace_ex.aptosEncrypt: DKG session has no resultPk (not yet finalized)';

            const mpk = tibe.MasterPublicKey.newBonehFranklinBls12381ShortPkOtpHmac(session.basePoint, session.resultPk)
                .unwrapOrThrow('ace_ex.aptosEncrypt: construct MPK');

            return tibe.encrypt({mpk, id: fdd.toBytes(), plaintext})
                .unwrapOrThrow('ace_ex.aptosEncrypt: tibe.encrypt failed')
                .toBytes();
        },
        recordsExecutionTimeMs: true,
    });
}

export async function solanaEncrypt({aceDeployment, keypairId, knownChainName, programId, domain, plaintext}: {
    aceDeployment?: AceDeployment,
    keypairId: AccountAddress,
    knownChainName: string,
    programId: string,
    domain: Uint8Array,
    plaintext: Uint8Array,
}): Promise<Result<Uint8Array>> {
    if (aceDeployment === undefined) throw 'default aceDeployment is not supported yet';
    return Result.captureAsync({
        task: async (_extra) => {
            const aptos = createAptos(aceDeployment.apiEndpoint);
            const contractId = ContractID.newSolana({knownChainName, programId});
            const fdd = new FullDecryptionDomain({keypairId, contractId, domain});
            const aceContractAddr = aceDeployment.contractAddr.toStringLong();

            const [hexBytes] = await aptos.view({
                payload: {
                    function: `${aceContractAddr}::dkg::get_session_bcs` as `${string}::${string}::${string}`,
                    typeArguments: [],
                    functionArguments: [keypairId.toStringLong()],
                },
            });
            const sessionBytes = hexToBytes((hexBytes as string).replace(/^0x/, ''));
            const session = dkg.Session.fromBytes(sessionBytes).unwrapOrThrow('ace_ex.solanaEncrypt: parse DKG session');
            if (!session.resultPk) throw 'ace_ex.solanaEncrypt: DKG session has no resultPk (not yet finalized)';

            const mpk = tibe.MasterPublicKey.newBonehFranklinBls12381ShortPkOtpHmac(session.basePoint, session.resultPk)
                .unwrapOrThrow('ace_ex.solanaEncrypt: construct MPK');

            return tibe.encrypt({mpk, id: fdd.toBytes(), plaintext})
                .unwrapOrThrow('ace_ex.solanaEncrypt: tibe.encrypt failed')
                .toBytes();
        },
        recordsExecutionTimeMs: true,
    });
}

async function fetchNetworkStateAndBuildRequest(
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
    const networkState = NetworkState.fromBytes(stateBytes).unwrapOrThrow('ace_ex: parse network state');

    const request = new DecryptionRequestPayload({
        keypairId: fullDecryptionDomain.keypairId,
        epoch: networkState.epoch,
        contractId: fullDecryptionDomain.contractId,
        domain: fullDecryptionDomain.domain,
        ephemeralEncKey: ephemeralEncryptionKey,
    });

    return {networkState, request};
}

async function decryptCore({aceDeployment, networkState, request, proof, ephemeralDecryptionKey, ciphertext}: {
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
                    .unwrapOrThrow(`ace_ex.decryptCore: parse pke enc key for ${addrStr}`);
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
                throw `ace_ex.decryptCore: need ${networkState.curThreshold} shares, got ${idkShares.length}`;
            }

            return tibe.decrypt({
                idkShares,
                ciphertext: tibe.Ciphertext.fromBytes(ciphertext).unwrapOrThrow('ace_ex.decryptCore: parse ciphertext'),
            }).unwrapOrThrow('ace_ex.decryptCore: tibe.decrypt failed');
        },
        recordsExecutionTimeMs: true,
    });
}

function createAptos(rpcUrl?: string): Aptos {
    return new Aptos(new AptosConfig({
        network: Network.CUSTOM,
        fullnode: rpcUrl ?? 'http://localhost:8080/v1',
    }));
}
