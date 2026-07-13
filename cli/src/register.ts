// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import {
    Account,
    AptosConfig,
    Aptos,
    Ed25519PrivateKey,
    Network,
} from '@aptos-labs/ts-sdk';
import { GasStationTransactionSubmitter } from '@aptos-labs/gas-station-client';
import { workerConfig } from '@aptos-labs/ace-sdk';

function inferNetwork(rpcUrl: string): Network {
    const url = rpcUrl.toLowerCase();
    if (url.includes('mainnet')) return Network.MAINNET;
    if (url.includes('testnet')) return Network.TESTNET;
    if (url.includes('devnet'))  return Network.DEVNET;
    if (url.includes('localhost') || url.includes('127.0.0.1')) return Network.LOCAL;
    return Network.CUSTOM;
}

function localFaucetUrl(rpcUrl: string): string {
    try {
        const u = new URL(rpcUrl);
        u.port = '8081';
        u.pathname = '/';
        return u.origin;
    } catch {
        return 'http://127.0.0.1:8081';
    }
}

function buildAptos(rpcUrl: string, rpcApiKey?: string, gasStationKey?: string): Aptos {
    const network = inferNetwork(rpcUrl);
    const clientConfig = rpcApiKey
        ? { HEADERS: { Authorization: `Bearer ${rpcApiKey}` } }
        : undefined;
    const faucet = network === Network.LOCAL ? localFaucetUrl(rpcUrl) : undefined;

    if (gasStationKey) {
        const gasStation = new GasStationTransactionSubmitter({ network, apiKey: gasStationKey });
        return new Aptos(new AptosConfig({
            network, fullnode: rpcUrl, faucet, clientConfig,
            pluginSettings: { TRANSACTION_SUBMITTER: gasStation },
        }));
    }
    return new Aptos(new AptosConfig({ network, fullnode: rpcUrl, faucet, clientConfig }));
}

async function tryResource<T extends object>(aptos: Aptos, accountAddress: string, resourceType: string): Promise<T | null> {
    try {
        return await aptos.getAccountResource<T>({
            accountAddress,
            resourceType: resourceType as `${string}::${string}::${string}`,
        });
    } catch (e: unknown) {
        const msg = String((e as any)?.message ?? e);
        const vmCode = (e as any)?.data?.vm_error_code ??
            (msg.match(/"vm_error_code":(\d+)/)?.[1] ? Number(msg.match(/"vm_error_code":(\d+)/)?.[1]) : undefined);
        if (
            msg.includes('resource_not_found') ||
            msg.includes('RESOURCE_DOES_NOT_EXIST') ||
            msg.includes('NOT_FOUND') ||
            vmCode === 4008
        ) return null;
        throw e;
    }
}

export async function registerOnChain(
    node: {
        accountAddr: string;
        accountSk: string;
        pkeEk: string;
        sigPk: string;
        rpcUrl: string;
        aceAddr: string;
        rpcApiKey?: string;
        gasStationKey?: string;
    },
    endpoint: string,
    nodeMsgEndpoint: string,
): Promise<void> {
    const aptos = buildAptos(node.rpcUrl, node.rpcApiKey, node.gasStationKey);
    const sk = new Ed25519PrivateKey(node.accountSk);
    const account = Account.fromPrivateKey({ privateKey: sk });

    if (inferNetwork(node.rpcUrl) === Network.LOCAL) {
        process.stderr.write(`\nFunding account via localnet faucet...\n`);
        await aptos.fundAccount({
            accountAddress: account.accountAddress,
            amount: 100_000_000,
            options: { waitForIndexer: false },
        });
        process.stderr.write(`  ✓ Funded\n`);
    }

    async function submitEntry(fn: string, args: unknown[]): Promise<void> {
        const txn = await aptos.transaction.build.simple({
            sender: account.accountAddress,
            data: { function: fn as `${string}::${string}::${string}`, functionArguments: args as any[] },
            options: { replayProtectionNonce: BigInt(Date.now()) },
            withFeePayer: !!node.gasStationKey,
        });
        const response = await aptos.signAndSubmitTransaction({ signer: account, transaction: txn });
        process.stderr.write(`  txn ${response.hash}\n`);
        await aptos.waitForTransaction({ transactionHash: response.hash, options: { checkSuccess: true } });
        process.stderr.write(`  ✓ committed\n`);
    }

    // Client-facing endpoint
    process.stderr.write(`\nChecking client endpoint...\n`);
    const endpointResource = await tryResource<workerConfig.WorkerEndpointResource>(
        aptos,
        node.accountAddr,
        `${node.aceAddr}::worker_config::ClientEndpoint`,
    );
    if (endpointResource === null) {
        process.stderr.write(`  not registered — submitting register_client_endpoint\n`);
        await submitEntry(`${node.aceAddr}::worker_config::register_client_endpoint`, [endpoint]);
    } else {
        const onChain = workerConfig.endpointFromResource(endpointResource, 'ClientEndpoint resource');
        if (onChain !== endpoint) {
            throw new Error(`Client endpoint mismatch:\n  on-chain : ${onChain}\n  input    : ${endpoint}`);
        }
        process.stderr.write(`  already registered, matches — skipping\n`);
    }

    // Node-message endpoint
    process.stderr.write(`\nChecking node-message endpoint...\n`);
    const nodeMsgEndpointResource = await tryResource<workerConfig.WorkerEndpointResource>(
        aptos,
        node.accountAddr,
        `${node.aceAddr}::worker_config::NodeMsgEndpoint`,
    );
    if (nodeMsgEndpointResource === null) {
        process.stderr.write(`  not registered — submitting register_node_msg_endpoint\n`);
        await submitEntry(`${node.aceAddr}::worker_config::register_node_msg_endpoint`, [nodeMsgEndpoint]);
    } else {
        const onChain = workerConfig.endpointFromResource(nodeMsgEndpointResource, 'NodeMsgEndpoint resource');
        if (onChain !== nodeMsgEndpoint) {
            throw new Error(`Node-message endpoint mismatch:\n  on-chain : ${onChain}\n  input    : ${nodeMsgEndpoint}`);
        }
        process.stderr.write(`  already registered, matches — skipping\n`);
    }

    // PKE encryption key
    process.stderr.write(`\nChecking PKE encryption key...\n`);
    const pkeResource = await tryResource<workerConfig.WorkerPkeEncryptionKeyResource>(
        aptos,
        node.accountAddr,
        `${node.aceAddr}::worker_config::PkeEncryptionKey`,
    );
    const profileEkHex = node.pkeEk.replace(/^0x/i, '').toLowerCase();
    if (pkeResource === null) {
        process.stderr.write(`  not registered — submitting register_pke_enc_key\n`);
        const ekBytes = Array.from(Buffer.from(profileEkHex, 'hex'));
        await submitEntry(`${node.aceAddr}::worker_config::register_pke_enc_key`, [ekBytes]);
    } else {
        const onChainHex = workerConfig.pkeEncryptionKeyFromResource(pkeResource)
            .toHex()
            .replace(/^0x/i, '')
            .toLowerCase();
        if (onChainHex !== profileEkHex) {
            throw new Error(`PKE enc key mismatch:\n  on-chain : 0x${onChainHex}\n  profile  : 0x${profileEkHex}`);
        }
        process.stderr.write(`  already registered, matches — skipping\n`);
    }

    // Node-message signature verification key
    process.stderr.write(`\nChecking node-message signature key...\n`);
    const sigResource = await tryResource<workerConfig.WorkerSigVerificationKeyResource>(
        aptos,
        node.accountAddr,
        `${node.aceAddr}::worker_config::SigVerificationKey`,
    );
    const profileSigPkHex = node.sigPk.replace(/^0x/i, '').toLowerCase();
    if (sigResource === null) {
        process.stderr.write(`  not registered — submitting register_sig_verification_key\n`);
        const sigPkBytes = Array.from(Buffer.from(profileSigPkHex, 'hex'));
        await submitEntry(`${node.aceAddr}::worker_config::register_sig_verification_key`, [sigPkBytes]);
    } else {
        const onChainHex = workerConfig.sigVerificationKeyFromResource(sigResource)
            .toHex()
            .replace(/^0x/i, '')
            .toLowerCase();
        if (onChainHex !== profileSigPkHex) {
            throw new Error(`Node-message sig key mismatch:\n  on-chain : 0x${onChainHex}\n  profile  : 0x${profileSigPkHex}`);
        }
        process.stderr.write(`  already registered, matches — skipping\n`);
    }

    process.stderr.write(`\nRegistration complete.\n`);
}
