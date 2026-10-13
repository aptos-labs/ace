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
 *     also flow to stdout and are included in the failure record.
 */

import {
    Account, AccountAddress, Ed25519PrivateKey, PrivateKey, PrivateKeyVariants,
} from '@aptos-labs/ts-sdk';
import * as ACE from '@aptos-labs/ace-sdk';
import { inspect } from 'node:util';

import {
    ReaderProof, SignableRequest,
    aceDeploymentFromConfig, aptosFromConfig, buildBlobId, deriveAccessKeypair,
    readMonitorRunConfig, signWithAccessPrivateKey,
} from './common.js';

/** Include every available stack in an Error.cause chain in the failure log. */
function describeFailure(error: unknown): string {
    const stacks: string[] = [];
    const seen = new Set<unknown>();
    let current: unknown = error;
    while (current !== undefined && current !== null && !seen.has(current)) {
        seen.add(current);
        const value = current instanceof Error ? current.message
            : (typeof current === 'string' ? current : inspect(current, { depth: null }));
        stacks.push(current instanceof Error ? (current.stack ?? `${current.name}: ${value}`) : value);
        current = current instanceof Error ? current.cause : undefined;
    }
    if (current !== undefined && current !== null) stacks.push('[circular Error.cause]');
    return stacks.join('\nCaused by:\n');
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

    // Include the SDK's per-worker logs in the failure record while also
    // letting them print to stdout for Logging.
    const sdkLogs: string[] = [];
    const origLog = console.log.bind(console);
    console.log = (...args: unknown[]): void => {
        sdkLogs.push(args.map(a => a instanceof Error ? describeFailure(a)
            : (typeof a === 'string' ? a : inspect(a, { depth: null }))).join(' '));
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
        const failure = describeFailure(err);
        console.error(JSON.stringify({
            ...base,
            ok: false, status: 'unhealthy', severity: 'ERROR',
            durationMs: Date.now() - startedAt,
            message: failure,
            workerLogs: sdkLogs.length > 0 ? sdkLogs : undefined,
        }));
        process.exit(1);
    }
}

void main();
