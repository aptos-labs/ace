// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import {
    Account,
    AccountAddress,
    AptosConfig,
    Aptos,
    Ed25519PrivateKey,
    Network,
    Serializer,
} from '@aptos-labs/ts-sdk';
import { GasStationTransactionSubmitter } from '@aptos-labs/gas-station-client';
import { network as aceNetwork } from '@aptos-labs/ace-sdk';
import type { TrackedNode } from './config.js';

export type ProposalInput =
    | { kind: 'CommitteeChange'; nodes: AccountAddress[]; threshold: number }
    | { kind: 'ResharingIntervalUpdate'; newIntervalSecs: bigint }
    | { kind: 'NewSecret'; scheme: number }
    | { kind: 'SecretDeactivation'; originalDkgAddr: AccountAddress };

export function serializeProposal(proposal: ProposalInput): number[] {
    const ser = new Serializer();
    switch (proposal.kind) {
        case 'CommitteeChange':
            ser.serializeU8(0);
            ser.serializeU32AsUleb128(proposal.nodes.length);
            for (const node of proposal.nodes) ser.serialize(node);
            ser.serializeU64(proposal.threshold);
            break;
        case 'ResharingIntervalUpdate':
            ser.serializeU8(1);
            ser.serializeU64(proposal.newIntervalSecs);
            break;
        case 'NewSecret':
            ser.serializeU8(2);
            ser.serializeU8(proposal.scheme);
            break;
        case 'SecretDeactivation':
            ser.serializeU8(3);
            ser.serialize(proposal.originalDkgAddr);
            break;
    }
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

    static fromNode(node: TrackedNode): NetworkClient {
        const client = new NetworkClient(node.rpcUrl, node.aceAddr, node.rpcApiKey, node.gasStationKey);
        if (node.accountSk) {
            const sk = new Ed25519PrivateKey(node.accountSk);
            client.account = Account.fromPrivateKey({ privateKey: sk });
        }
        return client;
    }

    constructor(rpcUrl: string, aceAddr: string, rpcApiKey?: string, gasStationKey?: string) {
        this.aceAddr = aceAddr;
        this.aptos   = buildAptos(rpcUrl, rpcApiKey, gasStationKey);
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
