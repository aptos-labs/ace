// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * `ace deployment reconstruct-secret` — disaster-recovery: collect ≥t raw scalar
 * shares from the committee and reveal the master secret `s` for a keypair.
 *
 * Run this **right after each DKG** and store `s` in cold storage. It requires
 * the deployment's reconstructor key (see `reconstruction-setup`) and that the
 * nodes were launched with the matching `--reconstructor-pk`.
 *
 * SECURITY: the revealed `s` decrypts *all* data under that keypair, bypassing
 * every access-control contract. Treat the output like a root key.
 */

import { AccountAddress } from '@aptos-labs/ts-sdk';
import { AceDeployment, adminRecovery, sig } from '@aptos-labs/ace-sdk';

import { resolveDeployment } from '../resolve-profile.js';
import { NetworkClient } from '../network-client.js';
import { escSelect } from '../esc-select.js';

const G = '\x1b[32m', E = '\x1b[31m', Y = '\x1b[33m', D = '\x1b[2m', B = '\x1b[1m', R = '\x1b[0m';

export async function reconstructSecretCommand(opts: {
    profile?: string;
    account?: string;
    keypair?: string;
}): Promise<void> {
    const { deploymentKey, deployment } = resolveDeployment(opts.profile, opts.account);

    if (!deployment.reconstructorKey) {
        throw new Error(
            `Deployment "${deploymentKey}" has no reconstructor key. Run \`ace deployment reconstruction-setup\` first.`,
        );
    }
    const signingKey = sig.SigningKey.fromHex(deployment.reconstructorKey).unwrapOrThrow(
        'parse deployment.reconstructorKey',
    );

    const client = NetworkClient.fromDeployment(deployment);
    const [state, chainId] = await Promise.all([client.getNetworkState(), client.getChainId()]);

    if (state.secrets.length === 0) {
        throw new Error('This deployment has no active secrets to reconstruct.');
    }

    // ── Select the keypair ────────────────────────────────────────────────────
    let keypairId: AccountAddress;
    if (opts.keypair) {
        const wanted = AccountAddress.fromString(opts.keypair).toStringLong();
        const found = state.secrets.find(s => s.keypairId.toStringLong() === wanted);
        if (!found) {
            throw new Error(
                `No active secret with keypair id "${opts.keypair}". Available: ${state.secrets.map(s => s.keypairId.toStringLong()).join(', ')}`,
            );
        }
        keypairId = found.keypairId;
    } else if (state.secrets.length === 1) {
        keypairId = state.secrets[0]!.keypairId;
    } else {
        const choice = await escSelect({
            message: 'Select a keypair to reconstruct',
            choices: state.secrets.map(s => ({
                name: `${s.keypairId.toStringLong()}  ${D}scheme=${s.scheme} ${s.note}${R}`,
                value: s.keypairId.toStringLong(),
            })),
        });
        if (!choice) {
            console.log(`${D}Cancelled.${R}`);
            return;
        }
        keypairId = AccountAddress.fromString(choice);
    }

    console.log(`${Y}${B}⚠ Reconstructing master secret${R} for keypair ${keypairId.toStringLong()}`);
    console.log(`${D}  deployment=${deploymentKey} chainId=${chainId} epoch=${state.epoch} threshold=${state.curThreshold}${R}`);

    const aceDeployment = new AceDeployment({
        apiEndpoint: deployment.rpcUrl,
        contractAddr: AccountAddress.fromString(deployment.aceAddr),
        apiKey: deployment.sharedNodeApiKey,
    });

    const result = await adminRecovery.reconstructSecret({
        aceDeployment,
        keypairId,
        signingKey,
        chainId,
        log: msg => console.log(`${D}${msg}${R}`),
    });

    const verifiedStr =
        result.verified === true ? `${G}verified against master public key${R}`
        : result.verified === false ? `${E}FAILED master-pk verification — do NOT trust this value${R}`
        : `${Y}unverified (master pk unavailable)${R}`;

    console.log('');
    console.log(`${G}${B}✔ Master secret reconstructed${R} (${result.sharesUsed} shares, epoch ${result.epoch}, ${verifiedStr})`);
    console.log(`${B}keypairId:${R} ${keypairId.toStringLong()}`);
    console.log(`${B}masterSecret (Fr, 32-byte LE hex):${R}`);
    console.log(result.secretHex);
    console.log('');
    console.log(`${Y}Store this in cold storage (KMS/HSM). It decrypts all data under this keypair.${R}`);
}
