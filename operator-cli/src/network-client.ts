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

function buildAptos(profile: TrackedNode): Aptos {
    const network = inferNetwork(profile.rpcUrl);
    const clientConfig = profile.rpcApiKey
        ? { HEADERS: { Authorization: `Bearer ${profile.rpcApiKey}` } }
        : undefined;
    if (profile.gasStationKey) {
        const gs = new GasStationTransactionSubmitter({ network, apiKey: profile.gasStationKey });
        return new Aptos(new AptosConfig({
            network, fullnode: profile.rpcUrl, clientConfig,
            pluginSettings: { TRANSACTION_SUBMITTER: gs },
        }));
    }
    return new Aptos(new AptosConfig({ network, fullnode: profile.rpcUrl, clientConfig }));
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

export class NetworkClient {
    private aptos: Aptos;
    private aceAddr: string;
    private account: Account | undefined;

    constructor(private profile: TrackedNode) {
        this.aceAddr = profile.aceAddr;
        this.aptos = buildAptos(profile);
    }

    withSigner(): this {
        const sk = new Ed25519PrivateKey(this.profile.accountSk);
        this.account = Account.fromPrivateKey({ privateKey: sk });
        return this;
    }

    async getNetworkState(): Promise<aceNetwork.State> {
        const [hex] = await this.aptos.view({
            payload: {
                function: `${this.aceAddr}::network::state_bcs` as `${string}::${string}::${string}`,
                typeArguments: [],
                functionArguments: [],
            },
        });
        return aceNetwork.State.fromBytes(hexToBytes(hex as string))
            .unwrapOrThrow('Failed to parse network State');
    }

    async getProposalState(addr: AccountAddress): Promise<aceNetwork.ProposalState> {
        const [hex] = await this.aptos.view({
            payload: {
                function: `${this.aceAddr}::network::get_proposal_state_bcs` as `${string}::${string}::${string}`,
                typeArguments: [],
                functionArguments: [addr.toStringLong()],
            },
        });
        return aceNetwork.ProposalState.fromBytes(hexToBytes(hex as string))
            .unwrapOrThrow('Failed to parse ProposalState');
    }

    async submitNewProposal(proposal: ProposalInput): Promise<{ hash: string; proposalAddr?: string }> {
        const account = this.requireSigner();
        const txn = await this.aptos.transaction.build.simple({
            sender: account.accountAddress,
            data: {
                function: `${this.aceAddr}::network::new_proposal` as `${string}::${string}::${string}`,
                functionArguments: [serializeProposal(proposal)],
            },
        });
        const response = await this.aptos.signAndSubmitTransaction({ signer: account, transaction: txn });
        const committed = await this.aptos.waitForTransaction({
            transactionHash: response.hash,
            options: { checkSuccess: true },
        });
        const event = (committed as any).events?.find(
            (e: any) => typeof e.type === 'string' && e.type.endsWith('::network::ProposalCreated'),
        );
        const proposalAddr = (event?.data as { addr?: string } | undefined)?.addr;
        return { hash: response.hash, proposalAddr };
    }

    async submitApproveProposal(proposalAddr: AccountAddress): Promise<string> {
        const account = this.requireSigner();
        const txn = await this.aptos.transaction.build.simple({
            sender: account.accountAddress,
            data: {
                function: `${this.aceAddr}::network::approve_proposal` as `${string}::${string}::${string}`,
                functionArguments: [proposalAddr.toStringLong()],
            },
        });
        const response = await this.aptos.signAndSubmitTransaction({ signer: account, transaction: txn });
        await this.aptos.waitForTransaction({ transactionHash: response.hash, options: { checkSuccess: true } });
        return response.hash;
    }

    private requireSigner(): Account {
        if (!this.account) throw new Error('Call withSigner() first');
        return this.account;
    }
}
