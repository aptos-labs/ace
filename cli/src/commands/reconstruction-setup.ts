// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * `ace deployment reconstruction-setup` — enable disaster-recovery reconstruction
 * for a deployment.
 *
 * Generates a dedicated `sig` keypair (the "reconstructor" key), stores the
 * signing key in the deployment profile, prints the public key, then pushes the
 * public key to every node profile of this deployment (as `--reconstructor-pk`)
 * and redeploys them so they accept reconstruction requests signed by this key.
 *
 * Re-running rotates the key (all nodes must be redeployed with the new pk);
 * the command asks for confirmation before overwriting an existing key.
 */

import * as path from 'path';

import { sig } from '@aptos-labs/ace-sdk';

import {
    loadConfig, saveConfig, nodeMode, makeDeploymentKey,
    type TrackedNode,
} from '../config.js';
import { resolveDeployment } from '../resolve-profile.js';
import { escSelect } from '../esc-select.js';
import {
    gcpDeployCmd, gcpDeployCmdMicroservices, dockerRunCmd, localRunArgs,
    writeLogrotateConf, runLogrotate,
} from '../onboarding.js';
import { spawnLocalNode, killLocalNode, isLocalNodeAlive } from '../local-process.js';
import { gcloudReady, dockerReady, maybeAutoRun } from '../auto-deploy.js';

const G = '\x1b[32m', Y = '\x1b[33m', D = '\x1b[2m', B = '\x1b[1m', R = '\x1b[0m';

async function confirm(message: string): Promise<boolean> {
    const choice = await escSelect({
        message,
        choices: [
            { name: 'No', value: 'no' },
            { name: 'Yes', value: 'yes' },
        ],
    });
    return choice === 'yes';
}

/** Emit + optionally auto-run the redeploy command for one node, with its
 *  freshly-set `reconstructorPk`. Mirrors `edit-node`'s redeploy branches. */
async function redeployNode(nodeKey: string, node: TrackedNode): Promise<void> {
    const label = node.alias ?? nodeKey;
    const nodeArgs = {
        accountAddr:     node.accountAddr,
        accountSk:       node.accountSk ?? '',
        pkeDk:           node.pkeDk ?? '',
        reconstructorPk: node.reconstructorPk,
    };
    const { image, rpcApiKey, gasStationKey, chainRpc } = node;
    const mode = nodeMode(node);

    if (mode === 'metadata-management-only') {
        console.log(`${Y}• ${label}: metadata-management-only — profile updated, but you must redeploy it through your own system with --reconstructor-pk=${node.reconstructorPk}.${R}`);
        return;
    }

    if (node.platform === 'gcp' && node.gcp) {
        const cmd = mode === 'microservices'
            ? gcpDeployCmdMicroservices(
                {
                    project:               node.gcp.project,
                    region:                node.gcp.region,
                    maintainerServiceName: node.gcp.maintainerServiceName!,
                    handlerServiceName:    node.gcp.handlerServiceName!,
                    handlerMaxInstances:   node.gcp.handlerMaxInstances!,
                },
                image!, nodeArgs, node.rpcUrl, node.aceAddr, rpcApiKey, gasStationKey, chainRpc,
            )
            : gcpDeployCmd(
                node.gcp.serviceName!, image!, node.gcp.project, node.gcp.region,
                nodeArgs, node.rpcUrl, node.aceAddr, rpcApiKey, gasStationKey, chainRpc,
            );
        console.log(`\n${B}Re-deploy ${label}:${R}\n${cmd.display}\n`);
        await maybeAutoRun(cmd.run, gcloudReady(), `Apply ${label} now?`, cmd.env);
    } else if (node.platform === 'docker' && node.docker) {
        const cmd = [
            `docker rm -f ${node.docker.containerName} &&`,
            dockerRunCmd(
                node.docker.containerName, image!, node.docker.port,
                nodeArgs, node.nodeRpcUrl ?? node.rpcUrl, node.aceAddr, rpcApiKey, gasStationKey, chainRpc,
            ),
        ].join('\n');
        console.log(`\n${B}Restart ${label}:${R}\n${cmd}\n`);
        await maybeAutoRun(cmd, dockerReady(), `Apply ${label} now?`);
    } else if (node.platform === 'local' && node.local) {
        if (node.local.pid && isLocalNodeAlive(node.local.pid)) {
            console.log(`${D}Stopping old process (pid=${node.local.pid})…${R}`);
            killLocalNode(node.local.pid);
            await new Promise(r => setTimeout(r, 500));
        }
        const binaryPath = path.join(node.local.repoPath, 'target', 'release', 'network-node');
        const runArgs = localRunArgs(
            node.local.port, nodeArgs, node.rpcUrl, node.aceAddr, rpcApiKey, gasStationKey, chainRpc,
        );
        const logFile = node.local.logFile ?? '';
        if (node.local.logMaxMb && logFile) runLogrotate(writeLogrotateConf(logFile, node.local.logMaxMb));
        const pid = spawnLocalNode(binaryPath, runArgs, logFile);
        const config = loadConfig();
        const n = config.nodes[nodeKey];
        if (n && n.local) n.local.pid = pid;
        saveConfig(config);
        console.log(`${G}• ${label}: restarted (pid=${pid})${R}`);
    } else {
        console.log(`${Y}• ${label}: no known platform — profile updated; redeploy manually with --reconstructor-pk=${node.reconstructorPk}.${R}`);
    }
}

export async function reconstructionSetupCommand(opts: {
    profile?: string;
    account?: string;
}): Promise<void> {
    const { deploymentKey, deployment } = resolveDeployment(opts.profile, opts.account);

    if (deployment.reconstructorKey) {
        console.log(`${Y}Deployment "${deploymentKey}" already has a reconstructor key set.${R}`);
        const ok = await confirm('Rotate it? This overwrites the old key and requires redeploying all nodes.');
        if (!ok) {
            console.log(`${D}Cancelled — existing key kept.${R}`);
            return;
        }
    }

    // Generate the dedicated reconstructor keypair.
    const { publicKey, signingKey } = await sig.keygen();
    const pkHex = publicKey.toHex();

    const config = loadConfig();
    const dep = config.deployments[deploymentKey];
    if (!dep) throw new Error(`Deployment "${deploymentKey}" not found in config.`);
    dep.reconstructorKey = signingKey.toHex();
    saveConfig(config);

    console.log(`${G}${B}✔ Reconstructor key generated${R} for ${deploymentKey}`);
    console.log(`${B}Public key (pushed to nodes as --reconstructor-pk):${R}`);
    console.log(pkHex);
    console.log(`${D}Signing key stored in the deployment profile (local-only, 0600).${R}\n`);

    // Find this deployment's node profiles and push the pk to each.
    const nodeEntries = Object.entries(config.nodes).filter(
        ([, n]) => makeDeploymentKey(n.rpcUrl, n.aceAddr) === deploymentKey,
    );

    if (nodeEntries.length === 0) {
        console.log(`${Y}No node profiles found for this deployment. Add --reconstructor-pk=${pkHex} to each node's launch args manually.${R}`);
        return;
    }

    console.log(`Updating ${nodeEntries.length} node profile(s) and redeploying:\n`);
    for (const [nodeKey] of nodeEntries) {
        // Re-read + persist per node so a failure mid-loop leaves saved progress.
        const cfg = loadConfig();
        const node = cfg.nodes[nodeKey];
        if (!node) continue;
        node.reconstructorPk = pkHex;
        saveConfig(cfg);
        await redeployNode(nodeKey, node);
    }

    console.log(`\n${G}Done.${R} Nodes now accept reconstruction requests signed by this key.`);
    console.log(`${Y}Next: run \`ace deployment reconstruct-secret\` after each DKG and store the secret in cold storage.${R}`);
}
