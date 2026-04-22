// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * @module ace
 * 
 * ACE with multi-chain support.
 */

import * as AptosSDK from "@aptos-labs/ts-sdk";
import { AccountAddress, Aptos, AptosConfig, Deserializer, Network, Serializer } from "@aptos-labs/ts-sdk";
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

/**
 * RPC endpoint configuration for verification.
 * Workers can provide custom endpoints for their own fullnodes.
 */
export interface AptosChainConfig {
    endpoint?: string;
    apiKey?: string;
}

export interface RpcConfig {
    aptos?: {
        mainnet?: AptosChainConfig;
        testnet?: AptosChainConfig;
        localnet?: AptosChainConfig;
    };
    solana?: {
        "mainnet-beta"?: string;
        testnet?: string;
        devnet?: string;
        localnet?: string;
    };
}

// export class Committee {
//     workerEndpoints: string[];
//     threshold: number;

//     constructor({workerEndpoints, threshold}: {workerEndpoints: string[], threshold: number}) {
//         if (workerEndpoints.length === 0) throw new Error("workerEndpoints must be non-empty");
//         if (threshold === 0) throw new Error("threshold must be greater than 0");
//         if (threshold > workerEndpoints.length) throw new Error("threshold must be less than or equal to the number of workerEndpoints");
//         this.workerEndpoints = workerEndpoints;
//         this.threshold = threshold;
//     }

//     static dummy(): Committee {
//         return new Committee({workerEndpoints: ['http://localhost:3000'], threshold: 1});
//     }

//     static deserialize(deserializer: Deserializer): Result<Committee> {
//         const task = (_extra: Record<string, any>) => {
//             const numWorkerEndpoints = deserializer.deserializeUleb128AsU32();
//             const workerEndpoints = Array.from({length: numWorkerEndpoints}, () => deserializer.deserializeStr());
//             const threshold = Number(deserializer.deserializeU64());
//             return new Committee({workerEndpoints, threshold});
//         };
//         return Result.capture({task, recordsExecutionTimeMs: false});
//     }

//     serialize(serializer: Serializer): void {
//         serializer.serializeU32AsUleb128(this.workerEndpoints.length);
//         this.workerEndpoints.forEach(workerEndpoint => serializer.serializeStr(workerEndpoint));
//         serializer.serializeU64(this.threshold);
//     }

//     toPrettyMessage(indent: number = 0): string {
//         const pad = '  '.repeat(indent);
//         const endpoints = this.workerEndpoints.map(e => `\n${pad}  - ${e}`).join('');
//         return `\n${pad}workerEndpoints:${endpoints}\n${pad}threshold: ${this.threshold}`;
//     }
// }

export class ContractID {
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

// export class EncryptionKey {
//     ibeMpks: ibe.MasterPublicKey[];
//     threshold: number;

//     constructor({ibeMpks, threshold}: {ibeMpks: ibe.MasterPublicKey[], threshold: number}) {
//         this.ibeMpks = ibeMpks;
//         this.threshold = threshold;
//     }

//     static async fetch({committee}: {committee: Committee}): Promise<Result<EncryptionKey>> {
//         const task = async (extra: Record<string, any>) => {
//             const mpkFetchResults = await Promise.all(committee.workerEndpoints.map(async endpoint => {
//                 return await EncryptionKey.fetchMpkFromEndpoint(endpoint);
//             }));
//             extra['mpkFetchResults'] = mpkFetchResults;
//             if (mpkFetchResults.some(result => !result.isOk)) {
//                 throw 'ACE.EncryptionKey.fetchFromEndpoints failed with 1+ individual fetch errors';
//             }
//             const ibeMpks = mpkFetchResults.map(result => result.okValue!);
//             return new EncryptionKey({ibeMpks, threshold: committee.threshold});    
//         };
//         return await Result.captureAsync({task, recordsExecutionTimeMs: true});
//     }

//     private static async fetchMpkFromEndpoint(endpoint: string): Promise<Result<ibe.MasterPublicKey>> {
//         const task = async (extra: Record<string, any>) => {
//             const url = `${endpoint}/ibe_mpk`;
//             extra['url'] = url;
//             const controller = new AbortController();
//             const timeoutId = setTimeout(() => controller.abort(), 5000);
//             let response: globalThis.Response | null = null;
//             try {
//                 response = await fetch(url, {
//                     method: "GET",
//                     signal: controller.signal
//                 });
//             } catch (error) {
//                 clearTimeout(timeoutId);
//             }
//             if (response == null) throw 'ACE.EncryptionKey.fetchMpkFromEndpoint failed with unresponsive worker';
    
//             const responseBody = await response.text();
//             extra['responseStatus'] = response.status;
//             extra['responseBody'] = responseBody;
//             if (response.status !== 200) throw `ACE.EncryptionKey.fetchMpkFromEndpoint failed with worker rejection`;
//             return ibe.MasterPublicKey.fromHex(responseBody).unwrapOrThrow('ACE.EncryptionKey.fetchMpkFromEndpoint failed with MPK parse error');
//         };
//         return Result.captureAsync({task, recordsExecutionTimeMs: true});
//     }    
// }

// export class DecryptionKey {
//     ibeDecryptionKeys: (ibe.IdentityPrivateKey | null)[];

//     private constructor(ibeDecryptionKeys: (ibe.IdentityPrivateKey | null)[]) {
//         this.ibeDecryptionKeys = ibeDecryptionKeys;
//     }

//     static async fetch({committee, contractId, domain, proof}: {committee: Committee, contractId: ContractID, domain: Uint8Array, proof: ProofOfPermission}): Promise<Result<DecryptionKey>> {
//         const task = async (extra: Record<string, any>) => {
//             extra['committee'] = committee;
//             const decKeyLoadResults = await Promise.all(committee.workerEndpoints.map(async (_workerEndpoint, index) => {
//                 return DecryptionKey.fetchDecKeyShare({committee, contractId, domain, proof, index});
//             }));
            
//             extra['decKeyLoadResults'] = decKeyLoadResults;
//             const numSharesCollected = decKeyLoadResults.filter((loadResult) => loadResult.isOk).length;
//             if (numSharesCollected < committee.threshold) {
//                 throw `ACE.DecryptionKey.fetch failed with insufficient shares collected`;
//             }
//             const decKeyShares = decKeyLoadResults.map((loadResult) => loadResult.okValue ?? null);
//             return new DecryptionKey(decKeyShares);
//         };
//         return Result.captureAsync({task, recordsExecutionTimeMs: true});
//     }

//     private static async fetchDecKeyShare({committee, contractId, domain, proof, index}: {committee: Committee, contractId: ContractID, domain: Uint8Array, proof: ProofOfPermission, index: number}): Promise<Result<ibe.IdentityPrivateKey>> {
//         const task = async (extra: Record<string, any>) => {
//             const targetWorkerEndpoint = committee.workerEndpoints[index];
//             const request = new RequestForDecryptionKey({contractId, domain, proof});
//             const controller = new AbortController();
//             const timeoutId = setTimeout(() => controller.abort(), 5000);
//             var response: globalThis.Response | null = null;
//             try {
//                 response = await fetch(targetWorkerEndpoint, {
//                     method: "POST",
//                     body: request.toHex(),
//                     signal: controller.signal
//                 });
//             } catch (error) {
//                 clearTimeout(timeoutId);
//             }
//             if (response == null) throw 'ACE.DecryptionKey.fetchDecKeyShare failed with unresponsive worker';

//             const responseBody = await response.text();
//             extra['workerResponseStatus'] = response.status;
//             extra['workerResponseBody'] = responseBody;
//             if (response.status !== 200) throw 'ACE.DecryptionKey.fetchDecKeyShare failed with worker rejection';
//             return ibe.IdentityPrivateKey.fromHex(responseBody).unwrapOrThrow('ACE.DecryptionKey.fetchDecKeyShare failed with identity private key parse error');
//         };
//         return Result.captureAsync({task, recordsExecutionTimeMs: true});
//     }
// }

// export class Ciphertext {
//     symCiph: sym.Ciphertext;
//     ibeCiphs: ibe.Ciphertext[];

//     constructor(symCiph: sym.Ciphertext, ibeCiphs: ibe.Ciphertext[]) {
//         this.symCiph = symCiph;
//         this.ibeCiphs = ibeCiphs;
//     }

//     static dummy(): Ciphertext {
//         return new Ciphertext(sym.Ciphertext.dummy(), []);
//     }

//     static deserialize(deserializer: Deserializer): Result<Ciphertext> {
//         const task = (_extra: Record<string, any>) => {
//             const symCiph = sym.Ciphertext.deserialize(deserializer).unwrapOrThrow('ACE.Ciphertext.deserialize failed with sym ciphertext deserialization error');
//             const numIbeCiphs = deserializer.deserializeUleb128AsU32();
//             const ibeCiphs = Array.from({length: numIbeCiphs}, () => ibe.Ciphertext.deserialize(deserializer).unwrapOrThrow('ACE.Ciphertext.deserialize failed with ibe ciphertext deserialization error'));
//             return new Ciphertext(symCiph, ibeCiphs);
//         };
//         return Result.capture({task, recordsExecutionTimeMs: false});
//     }

//     static fromBytes(bytes: Uint8Array): Result<Ciphertext> {
//         const task = (_extra: Record<string, any>) => {
//             const deserializer = new Deserializer(bytes);
//             const ret = Ciphertext.deserialize(deserializer).unwrapOrThrow('ACE.Ciphertext.fromBytes failed with deserialization error');
//             if (deserializer.remaining() !== 0) {
//                 throw 'ACE.Ciphertext.fromBytes failed with trailing bytes';
//             }
//             return ret;
//         };
//         return Result.capture({task, recordsExecutionTimeMs: false});
//     }

//     static fromHex(hex: string): Result<Ciphertext> {
//         return Ciphertext.fromBytes(hexToBytes(hex));
//     }

//     serialize(serializer: Serializer): void {
//         this.symCiph.serialize(serializer);
//         serializer.serializeU32AsUleb128(this.ibeCiphs.length);
//         this.ibeCiphs.forEach(ibeCiph => ibeCiph.serialize(serializer));
//     }

//     toBytes(): Uint8Array {
//         const serializer = new Serializer();
//         this.serialize(serializer);
//         return serializer.toUint8Array();
//     }

//     toHex(): string {
//         return bytesToHex(this.toBytes());
//     }
// }

export class FullDecryptionDomain {
    contractId: ContractID;
    domain: Uint8Array;

    constructor({contractId, domain}: {contractId: ContractID, domain: Uint8Array}) {
        this.contractId = contractId;
        this.domain = domain;
    }

    static dummy(): FullDecryptionDomain {
        return new FullDecryptionDomain({
            contractId: ContractID.dummy(),
            domain: new Uint8Array(0),
        });
    }

    static deserialize(deserializer: Deserializer): Result<FullDecryptionDomain> {
        const task = (_extra: Record<string, any>) => {
            const contractId = ContractID.deserialize(deserializer).unwrapOrThrow('ACE.FullDecryptionDomain.deserialize failed with ContractID deserialization error');
            const domain = deserializer.deserializeBytes();
            return new FullDecryptionDomain({contractId, domain});
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
        return `\n${pad}contractId:${this.contractId.toPrettyMessage(indent + 1)}\n${pad}domain: 0x${bytesToHex(this.domain)}`;
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

export class RequestForDecryptionKey {
    keypairId: AptosSDK.AccountAddress;
    epoch: number;
    contractId: ContractID;
    domain: Uint8Array;
    proof: ProofOfPermission;
    ephemeralEncKey: pke.EncryptionKey;

    constructor({keypairId, epoch, contractId, domain, proof, ephemeralEncKey}: {keypairId: AptosSDK.AccountAddress, epoch: number, contractId: ContractID, domain: Uint8Array, proof: ProofOfPermission, ephemeralEncKey: pke.EncryptionKey}) {
        this.keypairId = keypairId;
        this.epoch = epoch;
        this.contractId = contractId;
        this.domain = domain;
        this.proof = proof;
        this.ephemeralEncKey = ephemeralEncKey;
    }

    static deserialize(deserializer: Deserializer): Result<RequestForDecryptionKey> {
        const task = (_extra: Record<string, any>) => {
            const keypairId = AccountAddress.deserialize(deserializer);
            const epoch = Number(deserializer.deserializeU64());
            const contractId = ContractID.deserialize(deserializer).unwrapOrThrow('ACE.RequestForDecryptionKey.deserialize failed with ContractID deserialization error');
            const domain = deserializer.deserializeBytes();
            const proof = ProofOfPermission.deserialize(deserializer).unwrapOrThrow('ACE.RequestForDecryptionKey.deserialize failed with ProofOfPermission deserialization error');
            const ephemeralEncKey = pke.EncryptionKey.deserialize(deserializer).unwrapOrThrow('ACE.RequestForDecryptionKey.deserialize failed with ephemeralEncKey deserialization error');
            return new RequestForDecryptionKey({keypairId, epoch, contractId, domain, proof, ephemeralEncKey});
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
        this.keypairId.serialize(serializer);
        serializer.serializeU64(BigInt(this.epoch));
        this.contractId.serialize(serializer);
        serializer.serializeBytes(this.domain);
        this.proof.serialize(serializer);
        // Ephemeral enc key appended last (always 67 bytes for scheme 0).
        // The node slices the last 67 bytes to extract it without needing a length prefix.
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
}

export async function encrypt({keypairId, contractId, domain, plaintext, aceContract, rpcUrl}: {
    keypairId: AccountAddress,
    contractId: ContractID,
    domain: Uint8Array,
    plaintext: Uint8Array,
    aceContract: string,
    rpcUrl?: string,
}): Promise<Result<{fullDecryptionDomain: FullDecryptionDomain, ciphertext: Uint8Array}>> {
    return Result.captureAsync({
        task: async (_extra) => {
            const aptos = createAptos(rpcUrl);
            const fdd = new FullDecryptionDomain({contractId, domain});

            // Fetch DKG session to get master public key (basePoint + resultPk).
            const [hexBytes] = await aptos.view({
                payload: {
                    function: `${aceContract}::dkg::get_session_bcs` as `${string}::${string}::${string}`,
                    typeArguments: [],
                    functionArguments: [keypairId.toStringLong()],
                },
            });
            const sessionBytes = hexToBytes((hexBytes as string).replace(/^0x/, ''));
            const session = dkg.Session.fromBytes(sessionBytes).unwrapOrThrow('ace_ex.encrypt: parse DKG session');
            if (!session.resultPk) throw 'ace_ex.encrypt: DKG session has no resultPk (not yet finalized)';

            const mpk = tibe.MasterPublicKey.newBonehFranklinBls12381ShortPkOtpHmac(session.basePoint, session.resultPk)
                .unwrapOrThrow('ace_ex.encrypt: construct MPK');

            const ciph = tibe.encrypt({mpk, id: fdd.toBytes(), plaintext})
                .unwrapOrThrow('ace_ex.encrypt: tibe.encrypt failed');

            return {fullDecryptionDomain: fdd, ciphertext: ciph.toBytes()};
        },
        recordsExecutionTimeMs: true,
    });
}

export async function decrypt({keypairId, contractId, domain, proof, ciphertext, aceContract, rpcUrl}: {
    keypairId: AccountAddress,
    contractId: ContractID,
    domain: Uint8Array,
    proof: ProofOfPermission,
    ciphertext: Uint8Array,
    aceContract: string,
    rpcUrl?: string,
}): Promise<Result<Uint8Array>> {
    return Result.captureAsync({
        task: async (_extra) => {
            const aptos = createAptos(rpcUrl);

            // Fetch current committee from network state.
            const [stateHex] = await aptos.view({
                payload: {
                    function: `${aceContract}::network::state_bcs` as `${string}::${string}::${string}`,
                    typeArguments: [],
                    functionArguments: [],
                },
            });
            const stateBytes = hexToBytes((stateHex as string).replace(/^0x/, ''));
            const state = NetworkState.fromBytes(stateBytes).unwrapOrThrow('ace_ex.decrypt: parse network state');

            // Fetch HTTP endpoint and PKE enc key for each node in curNodes.
            const nodeInfos = await Promise.all(state.curNodes.map(async (nodeAddr) => {
                const addrStr = nodeAddr.toStringLong();
                const [[endpoint], [ekHex]] = await Promise.all([
                    aptos.view({
                        payload: {
                            function: `${aceContract}::worker_config::get_endpoint` as `${string}::${string}::${string}`,
                            typeArguments: [],
                            functionArguments: [addrStr],
                        },
                    }),
                    aptos.view({
                        payload: {
                            function: `${aceContract}::worker_config::get_pke_enc_key_bcs` as `${string}::${string}::${string}`,
                            typeArguments: [],
                            functionArguments: [addrStr],
                        },
                    }),
                ]);
                const nodeEncKey = pke.EncryptionKey.fromBytes(hexToBytes((ekHex as string).replace(/^0x/, '')))
                    .unwrapOrThrow(`ace_ex.decrypt: parse pke enc key for ${addrStr}`);
                return { endpoint: endpoint as string, nodeEncKey };
            }));

            // Generate a per-call ephemeral keypair; the enc key is included in the request so
            // each node can encrypt its share response back to us.
            const { encryptionKey: ephemeralEk, decryptionKey: ephemeralDk } = pke.keygen();
            const reqBytes = new RequestForDecryptionKey({keypairId, epoch: state.epoch, contractId, domain, proof, ephemeralEncKey: ephemeralEk}).toBytes();

            // POST to all workers concurrently; each request is encrypted to that node's PKE key.
            const idkShares = (await Promise.all(nodeInfos.map(async ({endpoint, nodeEncKey}, i) => {
                const nodeAddr = state.curNodes[i].toStringLong();
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
                        console.log(`  [decrypt] worker ${nodeAddr} (${endpoint}): response ciphertext parse failed, hex=${hexText.slice(0, 40)}...`);
                        return null;
                    }
                    const shareBytes = pke.decrypt({decryptionKey: ephemeralDk, ciphertext: respCt}).okValue ?? null;
                    if (shareBytes === null) {
                        console.log(`  [decrypt] worker ${nodeAddr} (${endpoint}): response decryption failed`);
                        return null;
                    }
                    const share = tibe.IdentityDecryptionKeyShare.fromBytes(shareBytes).okValue ?? null;
                    if (share === null) {
                        console.log(`  [decrypt] worker ${nodeAddr} (${endpoint}): share parse failed`);
                    } else {
                        console.log(`  [decrypt] worker ${nodeAddr} (${endpoint}): OK (evalPoint=${share.inner?.evalPoint ?? (share as any).evalPoint})`);
                    }
                    return share;
                } catch (e) {
                    console.log(`  [decrypt] worker ${nodeAddr} (${endpoint}): fetch error — ${e}`);
                    return null;
                }
            }))).filter((s): s is tibe.IdentityDecryptionKeyShare => s !== null);

            if (idkShares.length < state.curThreshold) {
                throw `ace_ex.decrypt: need ${state.curThreshold} shares, got ${idkShares.length}`;
            }

            return tibe.decrypt({
                idkShares,
                ciphertext: tibe.Ciphertext.fromBytes(ciphertext).unwrapOrThrow('ace_ex.decrypt: parse ciphertext'),
            }).unwrapOrThrow('ace_ex.decrypt: tibe.decrypt failed');
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

// function getAptosChainName(chainId: number): string {
//     if (chainId === 1) return "mainnet";
//     if (chainId === 2) return "testnet";
//     if (chainId === 4) return "localnet";
//     return "unknown";
// }

// export async function verifyAndExtract({ibeMsk, contractId, domain, proof, rpcConfig}: {ibeMsk: ibe.MasterPrivateKey, contractId: ContractID, domain: Uint8Array, proof: ProofOfPermission, rpcConfig?: RpcConfig}): Promise<Result<ibe.IdentityPrivateKey>> {
//     const task = async (extra: Record<string, any>) => {
//         extra['contractIdScheme'] = contractId.scheme;
//         extra['proofScheme'] = proof.scheme;
//         const decryptionContext = new FullDecryptionDomain({ contractId, domain });
//         if (contractId.scheme == ContractID.SCHEME_APTOS && proof.scheme == ProofOfPermission.SCHEME_APTOS) {
//             const aptosContractId = contractId.inner as AptosContractID;
//             const chainName = getAptosChainName(aptosContractId.chainId);
//             const chainConfig = rpcConfig?.aptos?.[chainName as keyof NonNullable<RpcConfig['aptos']>];
//             const aptosResult = await verifyAptos({
//                 fullDecryptionDomain: decryptionContext,
//                 proof: proof.inner as AptosProofOfPermission,
//                 rpcEndpoint: chainConfig?.endpoint,
//                 apiKey: chainConfig?.apiKey
//             });
//             extra['verifyAptosResult'] = aptosResult;
//             if (!aptosResult.isOk) throw 'ACE.verifyAndExtract failed with aptos verification error';
//         } else if (contractId.scheme == ContractID.SCHEME_SOLANA && proof.scheme == ProofOfPermission.SCHEME_SOLANA) {
//             const solanaContractId = contractId.inner as SolanaContractID;
//             const rpcEndpoint = rpcConfig?.solana?.[solanaContractId.knownChainName as keyof NonNullable<RpcConfig['solana']>];
//             const solanaResult = await verifySolana({fullDecryptionDomain: decryptionContext, proof: proof.inner as SolanaProofOfPermission, rpcEndpoint});
//             extra['verifySolanaResult'] = solanaResult;
//             if (!solanaResult.isOk) throw 'ACE.verifyAndExtract failed with solana verification error';
//         } else {
//             throw 'ACE.verifyAndExtract failed with unsupported scheme combination';
//         }
//         return ibe.extract(ibeMsk, decryptionContext.toBytes()).unwrapOrThrow('ACE.verifyAndExtract failed with IBE extract error');
//     };
//     return Result.captureAsync({task, recordsExecutionTimeMs: true});
// }

