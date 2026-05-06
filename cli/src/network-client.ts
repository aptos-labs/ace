// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import {
    Account,
    AccountAddress,
    AptosConfig,
    Aptos,
    Ed25519PrivateKey,
    Network,
    PrivateKey,
    PrivateKeyVariants,
    Serializer,
} from '@aptos-labs/ts-sdk';
import { GasStationTransactionSubmitter } from '@aptos-labs/gas-station-client';
import { network as aceNetwork } from '@aptos-labs/ace-sdk';
import type { TrackedNode } from './config.js';

export type ProposalInput = {
    nodes: AccountAddress[];
    threshold: number;
    epochDurationMicros: bigint;
    secretsToRetain: AccountAddress[];
    newSecrets: number[];
    description: string;
    targetEpoch: number;
};

export function serializeProposal(proposal: ProposalInput): number[] {
    const ser = new Serializer();
    ser.serializeU32AsUleb128(proposal.nodes.length);
    for (const node of proposal.nodes) ser.serialize(node);
    ser.serializeU64(proposal.threshold);
    ser.serializeU64(proposal.epochDurationMicros);
    ser.serializeU32AsUleb128(proposal.secretsToRetain.length);
    for (const s of proposal.secretsToRetain) ser.serialize(s);
    ser.serializeU32AsUleb128(proposal.newSecrets.length);
    for (const s of proposal.newSecrets) ser.serializeU8(s);
    ser.serializeStr(proposal.description);
    ser.serializeU64(proposal.targetEpoch);
    return Array.from(ser.toUint8Array());
}

function inferNetwork(rpcUrl: string): Network {
    const url = rpcUrl.toLowerCase();
    if (url.includes('mainnet')) return Network.MAINNET;
    if (url.includes('testnet')) return Network.TESTNET;
    if (url.includes('devnet'))  return Network.DEVNET;
    if (url.includes('localhost') || url.includes('127.0.0.1')) return Network.LOCAL;
    return Network.CUSTOM;
}

function hexToBytes(hex: string): Uint8Array {
    return new Uint8Array(Buffer.from(hex.replace(/^0x/, ''), 'hex'));
}

function buildAptos(rpcUrl: string, rpcApiKey?: string, gasStationKey?: string): Aptos {
    const network = inferNetwork(rpcUrl);
    const clientConfig = rpcApiKey
        ? { HEADERS: { Authorization: `Bearer ${rpcApiKey}` } }
        : undefined;
    if (gasStationKey) {
        const gs = new GasStationTransactionSubmitter({ network, apiKey: gasStationKey });
        return new Aptos(new AptosConfig({
            network, fullnode: rpcUrl, clientConfig,
            pluginSettings: { TRANSACTION_SUBMITTER: gs },
        }));
    }
    return new Aptos(new AptosConfig({ network, fullnode: rpcUrl, clientConfig }));
}

export class NetworkClient {
    private aptos: Aptos;
    private aceAddr: string;
    private account: Account | undefined;
    private hasGasStation: boolean;

    static fromNode(node: TrackedNode): NetworkClient {
        const client = new NetworkClient(node.rpcUrl, node.aceAddr, node.rpcApiKey, node.gasStationKey);
        if (node.accountSk) {
            const sk = new Ed25519PrivateKey(PrivateKey.formatPrivateKey(node.accountSk, PrivateKeyVariants.Ed25519));
            client.account = Account.fromPrivateKey({ privateKey: sk });
        }
        return client;
    }

    constructor(rpcUrl: string, aceAddr: string, rpcApiKey?: string, gasStationKey?: string) {
        this.aceAddr       = aceAddr;
        this.aptos         = buildAptos(rpcUrl, rpcApiKey, gasStationKey);
        this.hasGasStation = !!gasStationKey;
    }

    signerAddress(): string | undefined {
        return this.account?.accountAddress.toStringLong();
    }

    async getNetworkState(): Promise<aceNetwork.State> {
        const [hex] = await this.aptos.view({
            payload: {
                function: `${this.aceAddr}::network::state_view_v0_bcs` as `${string}::${string}::${string}`,
                typeArguments: [],
                functionArguments: [],
            },
        });
        return aceNetwork.State.fromBytes(hexToBytes(hex as string))
            .unwrapOrThrow('Failed to parse network StateViewV0');
    }

    /**
     * Fetch the deployed Move package version for the named ACE package (default `Network`).
     * Reads `0x1::code::PackageRegistry` at the contract address; the per-package `manifest`
     * field is gzip-compressed Move.toml bytes, from which we grep `version = "..."`.
     * Returns null on any failure (RPC error, missing package, parse failure).
     *
     * Assumption: every ACE package shares the same version per release, so reading one
     * is sufficient. The republish flow (`ace deployment update-contracts`) enforces this.
     */
    async getDeployedContractVersion(packageName: string = 'Network'): Promise<string | null> {
        try {
            const resource = await this.aptos.getAccountResource({
                accountAddress: AccountAddress.fromString(this.aceAddr),
                resourceType: '0x1::code::PackageRegistry',
            });
            const packages = (resource as { packages?: Array<{ name: string; manifest: string }> }).packages ?? [];
            const pkg = packages.find(p => p.name === packageName);
            if (!pkg?.manifest) return null;
            const zlib = await import('zlib');
            const tomlStr = zlib.gunzipSync(Buffer.from(pkg.manifest.replace(/^0x/, ''), 'hex')).toString('utf8');
            return tomlStr.match(/^\s*version\s*=\s*"([^"]+)"/m)?.[1] ?? null;
        } catch {
            return null;
        }
    }

    async getAccountBalance(addr: string): Promise<bigint> {
        const octas = await this.aptos.getAccountAPTAmount({ accountAddress: AccountAddress.fromString(addr) });
        return BigInt(octas);
    }

    async getWorkerEndpoint(addr: string): Promise<string | null> {
        try {
            const [result] = await this.aptos.view({
                payload: {
                    function: `${this.aceAddr}::worker_config::get_endpoint` as `${string}::${string}::${string}`,
                    typeArguments: [],
                    functionArguments: [addr],
                },
            });
            return result as string;
        } catch {
            return null;
        }
    }

    async submitNewProposal(proposal: ProposalInput): Promise<{ hash: string }> {
        const account = this.requireSigner();
        const txn = await this.aptos.transaction.build.simple({
            sender: account.accountAddress,
            data: {
                function: `${this.aceAddr}::network::new_proposal` as `${string}::${string}::${string}`,
                functionArguments: [serializeProposal(proposal)],
            },
            options: { replayProtectionNonce: BigInt(Date.now()) },
            withFeePayer: this.hasGasStation,
        });
        const response = await this.aptos.signAndSubmitTransaction({ signer: account, transaction: txn });
        await this.aptos.waitForTransaction({ transactionHash: response.hash, options: { checkSuccess: true } });
        return { hash: response.hash };
    }

    async submitVote(votingSessionAddr: AccountAddress): Promise<string> {
        const account = this.requireSigner();
        const txn = await this.aptos.transaction.build.simple({
            sender: account.accountAddress,
            data: {
                function: `${this.aceAddr}::voting::vote` as `${string}::${string}::${string}`,
                functionArguments: [votingSessionAddr.toStringLong()],
            },
            options: { replayProtectionNonce: BigInt(Date.now()) },
            withFeePayer: this.hasGasStation,
        });
        const response = await this.aptos.signAndSubmitTransaction({ signer: account, transaction: txn });
        await this.aptos.waitForTransaction({ transactionHash: response.hash, options: { checkSuccess: true } });
        return response.hash;
    }

    private requireSigner(): Account {
        if (!this.account) throw new Error('No signer — node has no private key');
        return this.account;
    }
}
