// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Mints the encrypted request body the probe replays. Two responsibilities:
 *
 *   1. `buildOnce()` — drive a real end-to-end decrypt through the SDK and capture
 *      the per-worker POST body (the bytes the probe will replay). Used once at
 *      `loadtest run` startup as a smoke test, and again each time the on-chain
 *      epoch changes.
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
    targetEndpoint: string;
    loadtester: Account;
    moduleAddr: AccountAddress;
    moduleName: string;
    domain: Uint8Array;
}

/** Wrap globalThis.fetch to capture the next POST body sent to `targetUrl`. */
function wrapFetch(targetUrl: string): { capture: () => string | undefined; restore: () => void } {
    const orig = globalThis.fetch;
    let captured: string | undefined;
    globalThis.fetch = (async (input: any, init?: any) => {
        const url = typeof input === 'string' ? input : input?.url;
        if (init?.method === 'POST' && url && url.startsWith(targetUrl)) {
            const body = init.body;
            if (typeof body === 'string') captured = body;
        }
        return orig(input as any, init);
    }) as typeof fetch;
    return {
        capture: () => captured,
        restore: () => { globalThis.fetch = orig; },
    };
}

/**
 * Drive one full encrypt → decrypt cycle through the SDK; capture the POST body
 * sent to `targetEndpoint` and return it alongside the network epoch the request
 * is bound to. Also validates the round-trip (smoke test).
 */
export async function buildOnce(cfg: MintConfig): Promise<Pool> {
    const plaintext = new TextEncoder().encode('loadtest-mint');
    const ciphertext = (await ACE.AptosBasicFlow.encrypt({
        aceDeployment: cfg.aceDeployment,
        keypairId: cfg.keypairId,
        chainId: cfg.chainId,
        moduleAddr: cfg.moduleAddr,
        moduleName: cfg.moduleName,
        domain: cfg.domain,
        plaintext,
    })).unwrapOrThrow('loadtest mint: encrypt failed');

    const fw = wrapFetch(cfg.targetEndpoint);
    let networkEpoch = -1;
    try {
        const session = await ACE.AptosBasicFlow.DecryptionSession.create({
            aceDeployment: cfg.aceDeployment,
            keypairId: cfg.keypairId,
            chainId: cfg.chainId,
            moduleAddr: cfg.moduleAddr,
            moduleName: cfg.moduleName,
            domain: cfg.domain,
            ciphertext,
        });
        const msg = await session.getRequestToSign();
        networkEpoch = Number((session as any).networkState!.epoch);
        const result = await session.decryptWithProof({
            userAddr: cfg.loadtester.accountAddress,
            publicKey: cfg.loadtester.publicKey,
            signature: cfg.loadtester.sign(msg),
        });
        result.unwrapOrThrow('loadtest mint: decrypt failed (the target endpoint may not be in the current committee)');
    } finally {
        fw.restore();
    }

    const encReqHex = fw.capture();
    if (!encReqHex) {
        throw new Error(
            `loadtest mint: did not see a POST to ${cfg.targetEndpoint}. ` +
            `Is this endpoint a current committee member?`,
        );
    }
    return {
        endpoint: cfg.targetEndpoint,
        encReqHex,
        epoch: networkEpoch,
        mintedAt: new Date().toISOString(),
        requestSize: encReqHex.length / 2,
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
