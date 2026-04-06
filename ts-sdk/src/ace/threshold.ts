// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * @module ace/threshold
 *
 * Threshold ACE protocol APIs.
 * Uses a single shared IBE ciphertext (no GF256 Shamir) with G2 Lagrange combination.
 * Existing ace/index.ts and all v1 classes are untouched.
 */

import { Aptos, AptosConfig, Network } from "@aptos-labs/ts-sdk";
import { Deserializer, Serializer } from "@aptos-labs/ts-sdk";
import { bls12_381 } from "@noble/curves/bls12-381";
import { WeierstrassPoint } from "@noble/curves/abstract/weierstrass";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import * as ibe from "../ibe";
import * as OtpHmac from "../ibe/otp_hmac_boneh_franklin_bls12381_short_pk";
import * as sym from "../sym";
import { Result } from "../result";
import {
    ContractID,
    FullDecryptionDomain,
    ProofOfPermission,
    RequestForDecryptionKey,
    RpcConfig,
} from "./index";
import { ThresholdMasterPublicKey, PartialIdentityKey } from "../threshold-ibe/types";
import { combinePartialKeys } from "../threshold-ibe/combine";

// ============================================================================
// AceNetwork — describes the on-chain ACE network contract
// ============================================================================

export interface AceNetwork {
    /** ACE network contract address (hex, e.g. "0xabc...") */
    contractAddress: string;
    /** Aptos chain ID (1=mainnet, 2=testnet, 4=localnet) */
    chainId: number;
    rpcConfig?: RpcConfig;
}

// ============================================================================
// ThresholdEncryptionKey
// ============================================================================

/**
 * Single shared IBE public key for the current committee, fetched from on-chain.
 */
export class ThresholdEncryptionKey {
    mpk: ThresholdMasterPublicKey;
    ibeCompatMpk: ibe.MasterPublicKey;  // ready for ibe.encrypt

    private constructor(mpk: ThresholdMasterPublicKey, ibeCompatMpk: ibe.MasterPublicKey) {
        this.mpk = mpk;
        this.ibeCompatMpk = ibeCompatMpk;
    }

    /**
     * Fetch the committee MPK from the ACE network contract (secret_id=0).
     */
    static async fetch(network: AceNetwork): Promise<Result<ThresholdEncryptionKey>> {
        return Result.captureAsync({
            task: async (extra) => {
                const aptos = createAptos(network);
                const contractAddress = normalizeAddress(network.contractAddress);
                const result = await aptos.view({
                    payload: {
                        function: `${contractAddress}::ace_network::get_secret`,
                        typeArguments: [],
                        functionArguments: [contractAddress, '0'],
                    },
                });
                extra['viewResult'] = result;
                // Returns [mpk_hex, base_hex, created_epoch, dummy_secret_hex]
                const [mpkHex, baseHex] = result as [string, string, unknown, unknown];
                const mpkBytes = hexToBytes(mpkHex.replace('0x', ''));
                const baseBytes = hexToBytes(baseHex.replace('0x', ''));
                const publicPointG1 = bls12_381.G1.Point.fromBytes(mpkBytes) as unknown as WeierstrassPoint<bigint>;
                const base = bls12_381.G1.Point.fromBytes(baseBytes) as unknown as WeierstrassPoint<bigint>;
                const threshMpk = new ThresholdMasterPublicKey(base, publicPointG1);
                const innerMpk = new OtpHmac.MasterPublicKey(base, publicPointG1);
                const ibeCompatMpk = ibe.MasterPublicKey._create(
                    ibe.SCHEME_OTP_HAMC_BONEH_FRANKLIN_BLS12381_SHORT_PK,
                    innerMpk,
                );
                return new ThresholdEncryptionKey(threshMpk, ibeCompatMpk);
            },
            recordsExecutionTimeMs: true,
        });
    }
}

// ============================================================================
// ThresholdDecryptionKey
// ============================================================================

/**
 * Combined identity private key assembled from ≥threshold partial keys.
 */
export class ThresholdDecryptionKey {
    combinedIdKey: ibe.IdentityPrivateKey;

    private constructor(combinedIdKey: ibe.IdentityPrivateKey) {
        this.combinedIdKey = combinedIdKey;
    }

    /**
     * Fetch partial keys from ≥threshold workers and Lagrange-combine them.
     *
     * @param network    - ACE network contract info
     * @param contractId - Access-control contract (passed to workers for permission check)
     * @param domain     - Blob identifier bytes
     * @param proof      - Proof of permission
     */
    static async fetch(
        network: AceNetwork,
        contractId: ContractID,
        domain: Uint8Array,
        proof: ProofOfPermission,
    ): Promise<Result<ThresholdDecryptionKey>> {
        return Result.captureAsync({
            task: async (extra) => {
                const aptos = createAptos(network);
                const contractAddress = normalizeAddress(network.contractAddress);

                // Fetch current committee
                const epochResult = await aptos.view({
                    payload: {
                        function: `${contractAddress}::ace_network::get_current_epoch`,
                        typeArguments: [],
                        functionArguments: [contractAddress],
                    },
                });
                const [, nodes, thresholdStr] = epochResult as [unknown, string[], string];
                const threshold = Number(thresholdStr);
                extra['nodes'] = nodes;
                extra['threshold'] = threshold;

                // Fetch endpoints for each node
                const endpoints = await Promise.all(nodes.map(async (nodeAddr) => {
                    const epResult = await aptos.view({
                        payload: {
                            function: `${contractAddress}::ace_network::get_node_endpoint`,
                            typeArguments: [],
                            functionArguments: [contractAddress, nodeAddr],
                        },
                    });
                    return epResult[0] as string;
                }));
                extra['endpoints'] = endpoints;

                // Request partial keys from workers (try all, collect ≥threshold successes)
                const partialResults = await Promise.all(
                    endpoints.map((endpoint, idx) =>
                        fetchPartialKey({ endpoint, workerIndex: idx + 1, contractId, domain, proof })
                    )
                );

                const partials: PartialIdentityKey[] = [];
                for (const r of partialResults) {
                    if (r.isOk && partials.length < threshold + 1) {
                        partials.push(r.okValue!);
                    }
                }
                extra['numPartials'] = partials.length;

                if (partials.length < threshold) {
                    throw `ThresholdDecryptionKey.fetch: only ${partials.length} partials collected, need ${threshold}`;
                }

                // Use exactly threshold partials
                const selectedPartials = partials.slice(0, threshold);
                const combinedIdKey = combinePartialKeys(selectedPartials);
                return new ThresholdDecryptionKey(combinedIdKey);
            },
            recordsExecutionTimeMs: true,
        });
    }
}

async function fetchPartialKey({
    endpoint,
    contractId,
    domain,
    proof,
}: {
    endpoint: string;
    workerIndex: number;
    contractId: ContractID;
    domain: Uint8Array;
    proof: ProofOfPermission;
}): Promise<Result<PartialIdentityKey>> {
    return Result.captureAsync({
        task: async (extra) => {
            extra['endpoint'] = endpoint;
            const request = new RequestForDecryptionKey({ contractId, domain, proof });
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 8000);
            let response: globalThis.Response | null = null;
            try {
                response = await fetch(endpoint, {
                    method: 'POST',
                    body: request.toHex(),
                    signal: controller.signal,
                });
            } catch {
                clearTimeout(timeoutId);
            }
            if (response == null) throw 'worker unresponsive';
            clearTimeout(timeoutId);
            const body = await response.text();
            extra['status'] = response.status;
            if (response.status !== 200) throw `worker rejected: ${body}`;
            return PartialIdentityKey.fromHex(body).unwrapOrThrow('failed to parse PartialIdentityKey');
        },
        recordsExecutionTimeMs: true,
    });
}

// ============================================================================
// ThresholdCiphertext
// ============================================================================

/**
 * Threshold ACE ciphertext: ONE IBE ciphertext encrypting the symmetric key,
 * plus the AES-GCM ciphertext for the actual data.
 */
export class ThresholdCiphertext {
    symCiph: sym.Ciphertext;
    ibeCiph: ibe.Ciphertext;    // ONE ciphertext (no Shamir splitting at encryption)

    constructor(symCiph: sym.Ciphertext, ibeCiph: ibe.Ciphertext) {
        this.symCiph = symCiph;
        this.ibeCiph = ibeCiph;
    }

    static deserialize(deserializer: Deserializer): Result<ThresholdCiphertext> {
        const task = (_extra: Record<string, any>) => {
            const symCiph = sym.Ciphertext.deserialize(deserializer).unwrapOrThrow(
                'ThresholdCiphertext.deserialize: sym error'
            );
            const ibeCiph = ibe.Ciphertext.deserialize(deserializer).unwrapOrThrow(
                'ThresholdCiphertext.deserialize: ibe error'
            );
            return new ThresholdCiphertext(symCiph, ibeCiph);
        };
        return Result.capture({ task, recordsExecutionTimeMs: false });
    }

    static fromBytes(bytes: Uint8Array): Result<ThresholdCiphertext> {
        const task = (_extra: Record<string, any>) => {
            const deserializer = new Deserializer(bytes);
            const ret = ThresholdCiphertext.deserialize(deserializer).unwrapOrThrow(
                'ThresholdCiphertext.fromBytes: deserialization error'
            );
            if (deserializer.remaining() !== 0) {
                throw 'ThresholdCiphertext.fromBytes: trailing bytes';
            }
            return ret;
        };
        return Result.capture({ task, recordsExecutionTimeMs: false });
    }

    static fromHex(hex: string): Result<ThresholdCiphertext> {
        return ThresholdCiphertext.fromBytes(hexToBytes(hex));
    }

    serialize(serializer: Serializer): void {
        this.symCiph.serialize(serializer);
        this.ibeCiph.serialize(serializer);
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

// ============================================================================
// encryptThreshold / decryptThreshold
// ============================================================================

/**
 * Encrypt plaintext using the committee's shared IBE MPK.
 * No Shamir splitting: one IBE ciphertext encrypts the symmetric key.
 */
export function encryptThreshold({
    encryptionKey,
    contractId,
    domain,
    plaintext,
}: {
    encryptionKey: ThresholdEncryptionKey;
    contractId: ContractID;
    domain: Uint8Array;
    plaintext: Uint8Array;
}): Result<{ fullDecryptionDomain: FullDecryptionDomain; ciphertext: ThresholdCiphertext }> {
    const task = (_extra: Record<string, any>) => {
        const fullDecryptionDomain = new FullDecryptionDomain({ contractId, domain });
        const symmKey = sym.keygen().unwrapOrThrow('encryptThreshold: sym keygen failed');
        const symmCiph = sym.encrypt(symmKey, plaintext).unwrapOrThrow('encryptThreshold: sym encrypt failed');
        const ibeCiph = ibe.encrypt(
            encryptionKey.ibeCompatMpk,
            fullDecryptionDomain.toBytes(),
            symmKey.toBytes(),
        ).unwrapOrThrow('encryptThreshold: ibe encrypt failed');
        return { fullDecryptionDomain, ciphertext: new ThresholdCiphertext(symmCiph, ibeCiph) };
    };
    return Result.capture({ task, recordsExecutionTimeMs: true });
}

/**
 * Decrypt a ThresholdCiphertext using the combined identity private key.
 */
export function decryptThreshold({
    decryptionKey,
    ciphertext,
}: {
    decryptionKey: ThresholdDecryptionKey;
    ciphertext: ThresholdCiphertext;
}): Result<Uint8Array> {
    const task = (_extra: Record<string, any>) => {
        const symmKeyBytes = ibe.decrypt(decryptionKey.combinedIdKey, ciphertext.ibeCiph)
            .unwrapOrThrow('decryptThreshold: ibe decrypt failed');
        const symmKey = sym.Key.fromBytes(symmKeyBytes).unwrapOrThrow('decryptThreshold: sym key parse failed');
        return sym.decrypt(symmKey, ciphertext.symCiph).unwrapOrThrow('decryptThreshold: sym decrypt failed');
    };
    return Result.capture({ task, recordsExecutionTimeMs: true });
}

// ============================================================================
// Re-export Aptos permission verification for use by workers
// ============================================================================

export { verifyPermission as verifyAptosPermission } from './aptos';

// ============================================================================
// Internal helpers
// ============================================================================

function normalizeAddress(addr: string): string {
    return addr.startsWith('0x') ? addr : `0x${addr}`;
}

function createAptos(network: AceNetwork): Aptos {
    const chainId = network.chainId;
    let config: AptosConfig;
    if (chainId === 1) {
        config = new AptosConfig({ network: Network.MAINNET });
    } else if (chainId === 2) {
        config = new AptosConfig({ network: Network.TESTNET });
    } else if (chainId === 4) {
        const endpoint = network.rpcConfig?.aptos?.localnet?.endpoint ?? 'http://localhost:8080/v1';
        config = new AptosConfig({ network: Network.CUSTOM, fullnode: endpoint });
    } else {
        config = new AptosConfig({ network: Network.CUSTOM, fullnode: 'http://localhost:8080/v1' });
    }
    return new Aptos(config);
}
