// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Mints the encrypted request body the probe replays. Two responsibilities:
 *
 *   1. `buildOnce()` — build the per-worker threshold-VRF POST body for ONE
 *      target node via `session.buildPerNodeRequest` (no committee fanout, no
 *      output reconstruction). Smoke-tests by POSTing once and confirming the worker
 *      returns a parseable PKE-ciphertext share. Used at `loadtest run` startup
 *      and again each time the on-chain epoch changes.
 *
 *   2. `Minter` — a long-running poller that watches the on-chain epoch and
 *      re-mints whenever it advances. Crucially, it *delays* the re-mint by
 *      `epochTransitionDelaySec` seconds so the worker has time to finish
 *      reconstructing its new-epoch share (see worker-components/network-node/
 *      src/lib.rs:255 — old-epoch requests are served for ~30s after rotation;
 *      new-epoch URH reconstruction takes a few seconds). Sleeping here keeps
 *      the probe firing the still-valid old-epoch request through the gap.
 *
 * The probe reads the current `Pool` via `Minter.current()` (in-process,
 * no file system involved).
 */

import { Account, AccountAddress, Ed25519PrivateKey } from '@aptos-labs/ts-sdk';
import * as ACE from '@aptos-labs/ace-sdk';

export interface Pool {
    endpoint: string;
    encReqHex: string;
    epoch: number;
    mintedAt: string;
    requestSize: number;
}

export interface MintConfig {
    aceDeployment: ACE.AceDeployment;
    keypairId: AccountAddress;
    chainId: number;
    /** On-chain registered endpoint of the target node (used to look up its enc key). */
    targetEndpoint: string;
    /** Where the probe actually POSTs to. Defaults to targetEndpoint. Override for LB / proxy / VPC tests. */
    postUrl?: string;
    loadtester: Account;
    moduleAddr: AccountAddress;
    moduleName: string;
    label: Uint8Array;
}

/**
 * Build the per-node POST body for `targetEndpoint` and smoke-test it with a
 * single POST. Does NOT contact any other committee member.
 */
export async function buildOnce(cfg: MintConfig): Promise<Pool> {
    const session = await ACE.VRF_Aptos.DerivationSession.create({
        aceDeployment: cfg.aceDeployment,
        keypairId: cfg.keypairId,
        contractId: ACE.ContractID.newAptos({
            chainId: cfg.chainId,
            moduleAddr: cfg.moduleAddr,
            moduleName: cfg.moduleName,
        }),
        label: cfg.label,
        accountAddress: cfg.loadtester.accountAddress,
    });
    const msg = await session.getRequestToSign();
    const fullMessage = ACE.VRF_Aptos.buildAptosWalletFullMessage({
        accountAddress: cfg.loadtester.accountAddress,
        application: 'https://ace-loadtest.local',
        chainId: cfg.chainId,
        message: msg,
        nonce: `loadtest-${Date.now()}-${Math.random()}`,
    });
    const built = await session.buildPerNodeRequest({
        pubKey: cfg.loadtester.publicKey,
        signature: cfg.loadtester.sign(fullMessage),
        fullMessage,
        targetEndpoint: cfg.targetEndpoint,
    });

    const postUrl = cfg.postUrl ?? cfg.targetEndpoint;
    // Smoke test: POST once, confirm the response parses as a PKE ciphertext.
    const resp = await fetch(postUrl, { method: 'POST', body: built.encReqHex });
    if (!resp.ok) {
        const body = await resp.text().catch(() => '');
        throw new Error(`loadtest mint: smoke test POST ${postUrl} returned HTTP ${resp.status} — ${body.trim().slice(0, 200)}`);
    }
    const hexText = (await resp.text()).trim();
    ACE.pke.Ciphertext.fromHex(hexText).unwrapOrThrow('loadtest mint: smoke test response is not a valid PKE ciphertext');

    return {
        endpoint: postUrl,
        encReqHex: built.encReqHex,
        epoch: built.epoch,
        mintedAt: new Date().toISOString(),
        requestSize: built.encReqHex.length / 2,
    };
}

/**
 * Background re-minter. Call `start()` after the initial pool is in hand, then
 * `current()` returns the freshest valid pool the probe should replay.
 *
 * Lifecycle: a single poll loop runs every `pollIntervalSec` seconds. When it
 * sees the on-chain epoch advance, it sleeps `epochTransitionDelaySec` then
 * re-mints. Errors during re-mint are logged but don't crash the loop.
 */
export class Minter {
    private pool: Pool;
    private cfg: MintConfig;
    private pollIntervalSec: number;
    private epochTransitionDelaySec: number;
    private stopped = false;
    private onRefresh?: (p: Pool) => void;

    constructor(opts: {
        initial: Pool;
        cfg: MintConfig;
        pollIntervalSec?: number;
        epochTransitionDelaySec?: number;
        onRefresh?: (p: Pool) => void;
    }) {
        this.pool = opts.initial;
        this.cfg = opts.cfg;
        this.pollIntervalSec = opts.pollIntervalSec ?? 3;
        this.epochTransitionDelaySec = opts.epochTransitionDelaySec ?? 10;
        this.onRefresh = opts.onRefresh;
    }

    current(): Pool { return this.pool; }

    async start(): Promise<void> {
        while (!this.stopped) {
            await sleep(this.pollIntervalSec * 1000);
            if (this.stopped) break;
            try {
                const epoch = await fetchOnChainEpoch(this.cfg.aceDeployment);
                if (epoch !== this.pool.epoch) {
                    console.log(`  [minter] epoch ${this.pool.epoch} → ${epoch}, waiting ${this.epochTransitionDelaySec}s before re-mint`);
                    await sleep(this.epochTransitionDelaySec * 1000);
                    if (this.stopped) break;
                    const fresh = await buildOnce(this.cfg);
                    this.pool = fresh;
                    if (this.onRefresh) this.onRefresh(fresh);
                }
            } catch (e) {
                console.error(`  [minter] poll/mint failed: ${e}`);
            }
        }
    }

    stop(): void { this.stopped = true; }
}

/** Read the on-chain epoch number from the network state view. */
async function fetchOnChainEpoch(aceDeployment: ACE.AceDeployment): Promise<number> {
    const r = await fetch(`${aceDeployment.apiEndpoint}/view`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            function: `${aceDeployment.contractAddr.toStringLong()}::network::state_view_v0_bcs`,
            type_arguments: [],
            arguments: [],
        }),
    });
    if (!r.ok) throw new Error(`state view: HTTP ${r.status}`);
    const [hex] = await r.json() as [string];
    // First 8 bytes of the BCS-encoded state are epoch (u64 LE).
    const bytes = Buffer.from(hex.replace(/^0x/, ''), 'hex');
    return Number(bytes.readBigUInt64LE(0));
}

function sleep(ms: number): Promise<void> {
    return new Promise(r => setTimeout(r, ms));
}

export function loadtesterAccountFromSk(skHex: string): Account {
    return Account.fromPrivateKey({
        privateKey: new Ed25519PrivateKey(skHex.replace(/^0x/, '')),
    });
}
