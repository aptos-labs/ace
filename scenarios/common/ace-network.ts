// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * ACE-network bring-up helpers shared by access-failure scenarios. Splits the
 * scaffolding (fund worker accounts → register PKE / endpoints → start_initial_epoch
 * → spawn worker processes) from the test-specific bits (which Bob signs,
 * which keypair is used, etc.).
 *
 * `runDkg` is the per-secret DKG primitive — call once per keypair you want
 * available. Returns the new keypair's ID once the network state observes it.
 */

import { Account, AccountAddress } from '@aptos-labs/ts-sdk';
import * as ACE from '@aptos-labs/ace-sdk';
import { pke } from '@aptos-labs/ace-sdk';
import { ChildProcess } from 'child_process';

import { LOCALNET_URL, WORKER_BASE_PORT } from './config';
import {
    BaseAceActors,
    assertTxnSuccess,
    deployContracts,
    getNetworkState,
    proposeAndApprove,
    serializeNewSecretProposal,
    setupBaseAceActors,
    sleep,
    startLocalnet,
    submitTxn,
    waitFor,
} from './helpers';
import { buildRustWorkspace, spawnNetworkNodeMaybeSplit } from './network-clients';

/** The ACE Move packages, in dependency order. Used by
 *  [`deployAndBringUpAceNetwork`] and any scenario that wants to deploy the
 *  full set; mirrors what every access-failure scenario has historically
 *  duplicated inline. */
export const ACE_CONTRACTS: readonly string[] = [
    'pke', 'worker_config', 'group', 'secret-usage', 'fiat-shamir-transform', 'sigma-dlog-linear', 'pedersen-polynomial-commitment',
    'vss', 'dkg', 'dkr', 'epoch-change', 'voting', 'network',
];

export interface AceNetworkOptions {
    adminAccount: Account;
    /** Total worker accounts to mint. Indices 0..totalWorkers-1. */
    totalWorkers: number;
    /** Indices of the workers in the initial committee (subset of 0..totalWorkers-1). */
    epoch0WorkerIndices: number[];
    /** Threshold for the initial committee. */
    epoch0Threshold: number;
    /** Per-worker funding callback. Use the scenario's `fundAccount` so the
     *  faucet config (network/url) is consistent. */
    fundAccount: (address: AccountAddress) => Promise<void>;
    /** `resharing_interval_secs` arg to `network::start_initial_epoch`. Must
     *  be >= 30 (Move-side `MIN_RESHARING_INTERVAL_SECS`). Defaults to 600
     *  (10 minutes) — long enough that auto-rotation doesn't fire during
     *  normal access-failure tests. Set lower (e.g., 30) for scenarios that
     *  intentionally drive auto-rotations. */
    reshareIntervalSecs?: number;
}

export interface AceNetworkState {
    workerAccounts: Account[];
    encKeypairs: Awaited<ReturnType<typeof pke.keygen>>[];
    workers: ChildProcess[];
    epoch0WorkerAccounts: Account[];
    aceDeployment: ACE.AceDeployment;
    adminAccountAddress: AccountAddress;
}

/**
 * Funds `totalWorkers` deterministic worker accounts, registers their PKE
 * encryption keys + endpoints, calls `network::start_initial_epoch` with the
 * configured committee + threshold, builds the rust workspace, and spawns one
 * worker process per index (split into maintainer + handler subprocesses per
 * `spawnNetworkNodeMaybeSplit`).
 *
 * Assumes ACE contracts (`pke`, `worker_config`, …, `network`) are already
 * deployed at `adminAccount.accountAddress`.
 */
/**
 * Deploys [`ACE_CONTRACTS`] at `adminAccount.accountAddress` and then runs the
 * standard worker bring-up (delegates to [`setupAceNetworkAndWorkers`]). Most
 * access-failure scenarios want exactly this composition.
 */
export async function deployAndBringUpAceNetwork(
    opts: AceNetworkOptions,
): Promise<AceNetworkState> {
    await deployContracts(opts.adminAccount, [...ACE_CONTRACTS]);
    return setupAceNetworkAndWorkers(opts);
}

export async function setupAceNetworkAndWorkers(
    opts: AceNetworkOptions,
): Promise<AceNetworkState> {
    const { adminAccount, totalWorkers, epoch0WorkerIndices, epoch0Threshold } = opts;
    const reshareIntervalSecs = opts.reshareIntervalSecs ?? 600;
    const adminAddr = adminAccount.accountAddress.toStringLong();
    const adminAccountAddress = adminAccount.accountAddress;

    // ── Fund deterministic worker accounts ──────────────────────────────────
    const workerAccounts: Account[] = [];
    for (let i = 0; i < totalWorkers; i++) {
        const { Ed25519PrivateKey } = await import('@aptos-labs/ts-sdk');
        const key = new Ed25519PrivateKey(
            Buffer.from(new Uint8Array(32).map((_, j) => j + 10 + i)),
        );
        const acc = Account.fromPrivateKey({ privateKey: key });
        await opts.fundAccount(acc.accountAddress);
        workerAccounts.push(acc);
    }

    // ── Register PKE enc keys + endpoints ───────────────────────────────────
    const encKeypairs = await Promise.all(
        Array.from({ length: totalWorkers }, () => pke.keygen()),
    );
    for (let i = 0; i < totalWorkers; i++) {
        const endpoint = `http://localhost:${WORKER_BASE_PORT + i}`;
        assertTxnSuccess(
            await submitTxn({
                signer: workerAccounts[i]!,
                entryFunction: `${adminAddr}::worker_config::register_pke_enc_key`,
                args: [Array.from(encKeypairs[i]!.encryptionKey.toBytes())],
            }),
            `register_pke_enc_key worker ${i}`,
        );
        assertTxnSuccess(
            await submitTxn({
                signer: workerAccounts[i]!,
                entryFunction: `${adminAddr}::worker_config::register_endpoint`,
                args: [endpoint],
            }),
            `register_endpoint worker ${i}`,
        );
    }

    // ── Kick off the initial epoch ──────────────────────────────────────────
    const epoch0Addrs = epoch0WorkerIndices.map(
        (i) => workerAccounts[i]!.accountAddress.toStringLong(),
    );
    assertTxnSuccess(
        await submitTxn({
            signer: adminAccount,
            entryFunction: `${adminAddr}::network::start_initial_epoch`,
            args: [epoch0Addrs, epoch0Threshold, reshareIntervalSecs],
        }),
        'network::start_initial_epoch',
    );

    // ── Build + spawn worker processes ──────────────────────────────────────
    await buildRustWorkspace();
    const workers: ChildProcess[] = [];
    for (let i = 0; i < totalWorkers; i++) {
        const pkeDkHex = `0x${Buffer.from(encKeypairs[i]!.decryptionKey.toBytes()).toString('hex')}`;
        workers.push(...spawnNetworkNodeMaybeSplit({
            index: i,
            total: totalWorkers,
            runAs: workerAccounts[i]!,
            pkeDkHex,
            aceDeploymentAddr: adminAddr,
            aceDeploymentApi: LOCALNET_URL,
            workerBasePort: WORKER_BASE_PORT,
        }));
    }
    await sleep(2000);

    const aceDeployment = new ACE.AceDeployment({
        apiEndpoint: LOCALNET_URL,
        contractAddr: adminAccountAddress,
    });

    return {
        workerAccounts,
        encKeypairs,
        workers,
        epoch0WorkerAccounts: epoch0WorkerIndices.map((i) => workerAccounts[i]!),
        aceDeployment,
        adminAccountAddress,
    };
}

/**
 * Proposes and threshold-approves a new-secret proposal, then waits for the
 * resulting keypair to appear in the network state. Returns the new keypair's
 * ID. Caller is responsible for ordering: each `runDkg` call must complete
 * (the secret appears) before the next is proposed, or the network state
 * `secrets` count will be ambiguous.
 *
 * `dkgPrimitive` is the ACE primitive id passed to
 * `serializeNewSecretProposal`. Defaults to shortsig IBE, which is the normal
 * access-failure scenario key usage.
 */
export interface SetupAceOnLocalnetOpts {
    totalWorkers: number;
    epoch0WorkerIndices: number[];
    epoch0Threshold: number;
    /** Per-worker funding callback. Use the scenario's `fundAccount` so the
     *  faucet config (network/url) is consistent with the rest of the test. */
    fundAccount: (address: AccountAddress) => Promise<void>;
    /** How many DKGs to run after the initial epoch starts. 1 for scenarios
     *  whose Step A uses a nonexistent keypair; 2 for keyless/federated-
     *  keyless whose Step A uses a real-but-wrong keypair (keypair-1 against
     *  keypair-0 ciphertext). */
    numKeypairs: number;
    /** ACE primitive id for each DKG'd keypair. */
    dkgPrimitive?: number;
    /** Optional hook to run *after* `startLocalnet()` but *before* any ACE
     *  setup. The keyless scenarios use this to invoke their framework
     *  bootstrap (clear JWKs / install Groth16 VK / patch Configuration),
     *  which must precede contract deploys. */
    beforeAceSetup?: () => Promise<void>;
    /** Optional post-DKG settle delay in ms. Defaults to 10 000 — the same
     *  cushion the access-failure scenarios used before this helper existed,
     *  so workers can stabilise on the new shares before decrypt traffic. */
    postDkgSettleMs?: number;
    /** Forwarded to [`AceNetworkOptions.reshareIntervalSecs`]. Defaults to
     *  600 (no auto-rotation during normal tests). Set to 30 to drive
     *  auto-rotation in a buffer/epoch-transition test. */
    reshareIntervalSecs?: number;
}

export interface SetupAceOnLocalnetResult {
    localnetProc: ChildProcess;
    actors: BaseAceActors;
    ace: AceNetworkState;
    /** One entry per DKG, in order. Length matches `opts.numKeypairs`. */
    keypairIds: AccountAddress[];
}

/**
 * One-call front-door for every access-failure-style scenario: starts a fresh
 * localnet, runs the optional `beforeAceSetup` hook, funds [`BaseAceActors`],
 * deploys ACE contracts + brings up the worker network + starts epoch 0
 * (via [`deployAndBringUpAceNetwork`]), and runs `opts.numKeypairs` DKGs to
 * completion. Returns the localnet handle, the funded actors, the ACE network
 * state (workers, epoch-0 accounts, `aceDeployment`), and the DKG'd keypair
 * IDs in order.
 *
 * Caller is responsible for `cleanupScenario(result.ace.workers,
 * result.localnetProc)` in their `finally` block.
 */
export async function setupAceOnLocalnet(
    opts: SetupAceOnLocalnetOpts,
): Promise<SetupAceOnLocalnetResult> {
    const localnetProc = await startLocalnet();
    if (opts.beforeAceSetup) await opts.beforeAceSetup();
    const actors = await setupBaseAceActors();
    const ace = await deployAndBringUpAceNetwork({
        adminAccount: actors.admin,
        totalWorkers: opts.totalWorkers,
        epoch0WorkerIndices: opts.epoch0WorkerIndices,
        epoch0Threshold: opts.epoch0Threshold,
        fundAccount: opts.fundAccount,
        reshareIntervalSecs: opts.reshareIntervalSecs,
    });
    const approvers = ace.epoch0WorkerAccounts.slice(0, opts.epoch0Threshold);
    const keypairIds: AccountAddress[] = [];
    for (let i = 0; i < opts.numKeypairs; i++) {
        const id = await runDkg({
            approvers,
            adminAddr: actors.adminAddr,
            adminAccountAddress: ace.adminAccountAddress,
            expectedSecretsCountAfter: i + 1,
            primitive: opts.dkgPrimitive,
            label: `keypair-${i}`,
        });
        keypairIds.push(id);
    }
    await sleep(opts.postDkgSettleMs ?? 10_000);
    return { localnetProc, actors, ace, keypairIds };
}

export async function runDkg(opts: {
    approvers: Account[];
    adminAddr: string;
    adminAccountAddress: AccountAddress;
    expectedSecretsCountAfter: number;
    primitive?: number;
    timeoutMs?: number;
    label?: string;
}): Promise<AccountAddress> {
    const { approvers, adminAddr, adminAccountAddress } = opts;
    const primitive = opts.primitive ?? ACE.network.PRIMITIVE_BFIBE_BLS12381_SHORTSIG_AEAD;
    const timeoutMs = opts.timeoutMs ?? 90_000;
    const label = opts.label ?? `keypair-${opts.expectedSecretsCountAfter - 1}`;

    await proposeAndApprove(
        approvers[0]!,
        approvers,
        adminAddr,
        serializeNewSecretProposal(primitive),
    );
    await waitFor(
        `${label} DKG done`,
        async () => {
            const stateResult = await getNetworkState(adminAccountAddress);
            if (!stateResult.isOk) return false;
            return stateResult.okValue!.secrets.length >= opts.expectedSecretsCountAfter;
        },
        timeoutMs,
    );
    const state = (await getNetworkState(adminAccountAddress))
        .unwrapOrThrow(`state read failed after ${label} DKG`);
    const keypair = state.secrets[opts.expectedSecretsCountAfter - 1]!.keypairId;
    return keypair;
}
