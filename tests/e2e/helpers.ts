// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { Account, Aptos, AptosConfig, Network } from '@aptos-labs/ts-sdk';
import { LOCALNET_URL, FAUCET_URL } from './config.js';

export function log(step: string, msg: string) {
    console.log(`\n[Step ${step}] ${msg}`);
}

export function assert(condition: boolean, msg: string) {
    if (!condition) throw new Error(`Assertion failed: ${msg}`);
}

export function sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
}

export async function waitFor(
    label: string,
    checkFn: () => Promise<boolean>,
    timeoutMs = 30_000,
    intervalMs = 1_000,
): Promise<void> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
        if (await checkFn()) return;
        await sleep(intervalMs);
    }
    throw new Error(`Timeout waiting for: ${label}`);
}

export function createAptos(): Aptos {
    return new Aptos(new AptosConfig({
        network: Network.CUSTOM,
        fullnode: LOCALNET_URL,
        faucet: FAUCET_URL,
    }));
}

export async function fundAccount(aptos: Aptos, account: Account): Promise<void> {
    // Call the faucet directly so we can wait on the REST API (no indexer needed).
    const resp = await fetch(
        `${FAUCET_URL}/mint?amount=1000000000&address=${account.accountAddress.toStringLong()}`,
        { method: 'POST' },
    );
    if (!resp.ok) throw new Error(`Faucet error: ${resp.status} ${await resp.text()}`);
    const hashes: string[] = await resp.json();
    for (const hash of hashes) {
        await aptos.waitForTransaction({ transactionHash: hash });
    }
}

export async function callView(aptos: Aptos, contractAddr: string, mod: string, fn: string, extraArgs: any[]): Promise<any[]> {
    return aptos.view({
        payload: {
            function: `${contractAddr}::${mod}::${fn}` as `${string}::${string}::${string}`,
            typeArguments: [],
            functionArguments: [contractAddr, ...extraArgs],
        },
    });
}

export async function submitTxn(
    aptos: Aptos,
    account: Account,
    contractAddr: string,
    mod: string,
    fn: string,
    args: any[],
): Promise<void> {
    const txn = await aptos.transaction.build.simple({
        sender: account.accountAddress,
        data: {
            function: `${contractAddr}::${mod}::${fn}` as `${string}::${string}::${string}`,
            typeArguments: [],
            functionArguments: args,
        },
    });
    const pending = await aptos.signAndSubmitTransaction({ signer: account, transaction: txn });
    await aptos.waitForTransaction({ transactionHash: pending.hash });
}
