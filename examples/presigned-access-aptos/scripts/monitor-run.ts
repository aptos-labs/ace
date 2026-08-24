// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * `pnpm monitor:run` — the headless health probe a monitor runs on a schedule.
 *
 * One shot, read-only, ZERO on-chain transactions (no gas): it re-encrypts a
 * fixed plaintext, re-derives the deterministic access key via threshold VRF,
 * runs the custom-flow decrypt against the live worker committee, and asserts
 * the round-trip. The on-chain `accessPublicKey` must already be registered by
 * `pnpm monitor:setup` (one-time) — this cycle only reads.
 *
 * Contract with the monitor harness:
 *   - Config comes entirely from env (see `readMonitorRunConfig`). No `data/`
 *     files, no prompts.
 *   - Exit 0 on success, 1 on any failure.
 *   - Exactly one structured JSON line is printed — to stdout on success, to
 *     stderr on failure — so Cloud Run ships it to Cloud Logging as
 *     jsonPayload. The SDK's own `[decrypt-custom]`/`[tVRF]` per-worker lines
 *     also flow to stdout, so a failed run is fully diagnosable from logs.
 *     `reason` buckets the failure so you can break down failure causes with a
 *     log-based metric.
 */

import {
    Account, AccountAddress, Ed25519PrivateKey, PrivateKey, PrivateKeyVariants,
} from '@aptos-labs/ts-sdk';
import * as ACE from '@aptos-labs/ace-sdk';

import {
    ReaderProof, SignableRequest,
    aceDeploymentFromConfig, aptosFromConfig, buildBlobId, deriveAccessKeypair,
    readMonitorRunConfig, signWithAccessPrivateKey,
} from './common.js';

/**
 * Bucket a failure into a stable `reason` for cause stats. The precise signal
 * (per-worker HTTP status) lives in the SDK's own log lines, not the generic
 * thrown message (`decryptCustomFlow` collapses share shortfalls to
 * "AptosCustomFlow.decrypt failed"), so we scan both.
 */
function classifyReason(message: string, sdkLogs: string[]): string {
    const m = message.toLowerCase();
    // Pre-decrypt asserts carry a specific thrown message.
    if (m.includes('missing required env')) return 'config-error';
    if (m.includes('chain id')) return 'chain-id-mismatch';
    if (m.includes('not in network state')) return 'keypair-missing';
    if (m.includes('committee size') || m.includes('threshold mismatch')) return 'committee-drift';
    if (m.includes('contract version')) return 'version-mismatch';
    if (m.includes('plaintext mismatch')) return 'plaintext-mismatch';

    // Share-collection failures: infer from the per-worker lines.
    const lines = sdkLogs.join('\n').toLowerCase();
    if (lines.includes('http 403')) return 'permission-denied';
    if (/http 5\d\d/.test(lines)) return 'worker-5xx';
    if (/http 4\d\d/.test(lines)) return 'worker-4xx';
    if (lines.includes('fetch error') || lines.includes('abort') || lines.includes('timeout')) return 'worker-timeout';
    if ((m.includes('need ') && m.includes('got ')) || m.includes('identity key shares')) return 'threshold-not-met';
    if (m.includes('decrypt failed')) return 'decrypt-shares-insufficient';

    // Chain-side reads (network state / version / view).
    if (m.includes('failed to parse ace network state') || m.includes('view') ||
        m.includes('econn') || m.includes('fetch') || m.includes('network')) return 'chain-read-error';
    return 'unknown';
}

/** Run the probe once. Throws on any failure; returns triage fields on success. */
async function runProbe(): Promise<Record<string, unknown>> {
    const cfg = readMonitorRunConfig();

    const aceDeployment = aceDeploymentFromConfig(cfg.ace);
    const ibeKeypairId = AccountAddress.fromString(cfg.ace.ibeKeypairId);
    const vrfKeypairId = AccountAddress.fromString(cfg.ace.vrfKeypairId);
    const moduleAddr = AccountAddress.fromString(cfg.appContractAddr);
    const alice = Account.fromPrivateKey({
        privateKey: new Ed25519PrivateKey(
            PrivateKey.formatPrivateKey(cfg.alicePrivateKeyHex, PrivateKeyVariants.Ed25519),
        ),
    });

    // chainId from the known deployment when available (discovery mode never touches the
    // fullnode); otherwise query the node.
    const chainId = cfg.ace.chainId ?? await aptosFromConfig(cfg.ace).getChainId();
    if (cfg.expect.chainId !== undefined && chainId !== cfg.expect.chainId) {
        throw new Error(`chain id mismatch: expected ${cfg.expect.chainId}, got ${chainId}`);
    }

    const blobId = buildBlobId(alice.accountAddress.toStringLong(), cfg.blobSuffix);
    const label = new TextEncoder().encode(blobId);
    const plaintext = new TextEncoder().encode(cfg.expectedPlaintext);

    const ciphertext = (await ACE.IBE_Aptos.encrypt({
        aceDeployment, keypairId: ibeKeypairId, chainId,
        moduleAddr, moduleName: cfg.appModuleName,
        label, plaintext,
    })).unwrapOrThrow('IBE encrypt failed');

    const { accessPrivateKey } = await deriveAccessKeypair({
        aceDeployment, vrfKeypairId, chainId, moduleAddr, moduleName: cfg.appModuleName,
        blobSuffix: cfg.blobSuffix, appOrigin: cfg.appOrigin, alice,
    });

    const { encryptionKey: epk, decryptionKey: edk } = await ACE.pke.keygen();
    const userEpkBytes = epk.toBytes();
    const originBytes = new TextEncoder().encode(cfg.appOrigin);
    const sig = signWithAccessPrivateKey(
        accessPrivateKey,
        new SignableRequest({ label, userEpk: userEpkBytes, origin: originBytes }).toBytes(),
    );
    const payload = new ReaderProof({ origin: originBytes, sig }).toBytes();

    const decrypted = await ACE.IBE_Aptos.decryptCustomFlow({
        ciphertext, label,
        encPk: userEpkBytes, encSk: edk.toBytes(), payload,
        aceDeployment, keypairId: ibeKeypairId, chainId,
        moduleAddr, moduleName: cfg.appModuleName,
    });
    const decoded = new TextDecoder().decode(decrypted);
    if (decoded !== cfg.expectedPlaintext) {
        throw new Error(`plaintext mismatch: expected ${JSON.stringify(cfg.expectedPlaintext)}, got ${JSON.stringify(decoded)}`);
    }

    return {
        chainId,
        blobId,
    };
}

async function main(): Promise<void> {
    const startedAt = Date.now();
    const base = {
        probe: 'presigned-access',
        serviceLabel: process.env.SERVICE_LABEL?.trim() || undefined,
        checkedAt: new Date().toISOString(),
    };

    // Tee the SDK's per-worker log lines into an array so we can classify the
    // failure precisely, while still letting them print to stdout for Logging.
    const sdkLogs: string[] = [];
    const origLog = console.log.bind(console);
    console.log = (...args: unknown[]): void => {
        sdkLogs.push(args.map(a => (typeof a === 'string' ? a : JSON.stringify(a))).join(' '));
        origLog(...args);
    };

    try {
        const info = await runProbe();
        console.log = origLog;
        origLog(JSON.stringify({
            ...base, ...info,
            ok: true, status: 'healthy', severity: 'INFO',
            durationMs: Date.now() - startedAt,
            message: `${info.blobId} custom-flow decrypt round-trip OK`,
        }));
        process.exit(0);
    } catch (err) {
        console.log = origLog;
        const message = err instanceof Error ? (err.stack ?? err.message) : String(err);
        console.error(JSON.stringify({
            ...base,
            ok: false, status: 'unhealthy', severity: 'ERROR',
            reason: classifyReason(message, sdkLogs),
            durationMs: Date.now() - startedAt,
            message,
        }));
        process.exit(1);
    }
}

void main();
