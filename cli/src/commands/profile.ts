// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { confirm } from '@inquirer/prompts';
import { loadConfig, saveConfig, deriveRpcLabel } from '../config.js';
import { CLI } from '../cli-name.js';
import { isLocalNodeAlive, killLocalNode } from '../local-process.js';
import { deployLabel } from '../render-state.js';
import { gceResourceNames } from '../onboarding.js';

const D = '\x1b[2m', R = '\x1b[0m', B = '\x1b[1m', G = '\x1b[32m', E = '\x1b[31m';

export function profileListCommand(): void {
    const config = loadConfig();
    const entries = Object.entries(config.nodes);

    if (entries.length === 0) {
        console.log(`No node profiles configured. Run \`${CLI} node new\` to set one up.`);
        return;
    }

    console.log();
    for (const [key, node] of entries) {
        const isDefault = key === config.defaultNode;
        const label = node.alias ? `${B}${node.alias}${R}` : `${D}${key}${R}`;
        const defTag = isDefault ? `  ${G}(default)${R}` : '';
        console.log(`  ${label}${defTag}`);
        console.log(`    Network : ${deriveRpcLabel(node.rpcUrl)}`);
        console.log(`    Account : ${node.accountAddr}`);
        if (node.endpoint) console.log(`    Endpoint: ${node.endpoint}`);
        if (node.platform === 'local') {
            const alive = node.local?.pid ? isLocalNodeAlive(node.local.pid) : false;
            const procStatus = node.local?.pid
                ? (alive ? `${G}running pid=${node.local.pid}${R}` : `${E}stopped (was pid=${node.local.pid})${R}`)
                : `${D}not started${R}`;
            console.log(`    Deploy  : ${deployLabel(node)}  ${procStatus}`);
            if (node.local?.logFile) console.log(`    Log     : ${node.local.logFile}`);
        } else if (node.mode === 'metadata-management-only') {
            console.log(`    Deploy  : ${deployLabel(node)}`);
        } else if (node.platform) {
            console.log(`    Deploy  : ${deployLabel(node)}`);
        }
        console.log();
    }
}

function findProfile(config: ReturnType<typeof loadConfig>, aliasOrKey: string): [string, (typeof config.nodes)[string]] | undefined {
    return Object.entries(config.nodes).find(([key, n]) =>
        n.alias === aliasOrKey || key === aliasOrKey || n.accountAddr === aliasOrKey,
    );
}

export async function profileDeleteCommand(aliasOrKey: string): Promise<void> {
    const config = loadConfig();
    const entry = findProfile(config, aliasOrKey);
    if (!entry) {
        console.error(`No profile matching "${aliasOrKey}". Run \`${CLI} node ls\` to see available profiles.`);
        process.exit(1);
    }
    const [key, node] = entry;
    const label = node.alias ?? key;

    const ok = await confirm({ message: `Delete profile "${label}"?`, default: false });
    if (!ok) { console.log('Cancelled.'); return; }

    delete config.nodes[key];
    if (config.defaultNode === key) delete config.defaultNode;
    saveConfig(config);
    console.log(`✓ Profile "${label}" deleted.`);

    if (node.platform === 'docker' && node.docker?.containerName) {
        console.log(`\n  Don't forget to stop the container:\n`);
        console.log(`  docker rm -f ${node.docker.containerName}`);
    } else if (node.platform === 'gcp' && node.gcp) {
        console.log(`\n  Don't forget to delete the Cloud Run service:\n`);
        if (node.mode === 'microservices') {
            if (node.gcp.handlerServiceName) {
                console.log(`  gcloud run services delete ${node.gcp.handlerServiceName} --project ${node.gcp.project} --region ${node.gcp.region}`);
            }
            if (node.gcp.maintainerServiceName) {
                console.log(`  gcloud run services delete ${node.gcp.maintainerServiceName} --project ${node.gcp.project} --region ${node.gcp.region}`);
            }
            if (node.gcp.cloudSql?.instanceName) {
                console.log(`\n  Don't forget to delete the Cloud SQL VSS DB if this profile owns it:\n`);
                console.log(`  gcloud sql instances delete ${node.gcp.cloudSql.instanceName} --project ${node.gcp.project}`);
            }
        } else {
            console.log(`  gcloud run services delete ${node.gcp.serviceName} --project ${node.gcp.project} --region ${node.gcp.region}`);
        }
    } else if (node.platform === 'gcp-vm' && node.gce) {
        const names = {
            ...gceResourceNames(node.gce.instanceName),
            ...node.gce,
        };
        const region = node.gce.zone.replace(/-[a-z]$/, '');
        console.log(`\n  Don't forget to delete the VM resources:\n`);
        console.log(`  gcloud compute instances delete ${node.gce.instanceName} --project ${node.gce.project} --zone ${node.gce.zone}`);
        console.log(`  gcloud compute disks delete ${names.diskName} --project ${node.gce.project} --zone ${node.gce.zone}`);
        console.log(`  gcloud compute addresses delete ${names.staticIpName} --project ${node.gce.project} --region ${region}`);
        console.log(`  gcloud compute firewall-rules delete ${names.firewallRuleName} --project ${node.gce.project}`);
    } else if (node.platform === 'local' && node.local?.pid) {
        if (isLocalNodeAlive(node.local.pid)) {
            killLocalNode(node.local.pid);
            console.log(`\n  Background process stopped (pid=${node.local.pid}).`);
        }
    }
}

export function profileDefaultCommand(aliasOrKey: string): void {
    const config = loadConfig();
    const entry = findProfile(config, aliasOrKey);
    if (!entry) {
        console.error(`No profile matching "${aliasOrKey}". Run \`${CLI} node ls\` to see available profiles.`);
        process.exit(1);
    }
    const [key, node] = entry;
    config.defaultNode = key;
    saveConfig(config);
    console.log(`✓ Default profile set to "${node.alias ?? key}".`);
}
