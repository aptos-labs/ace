// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { select, confirm } from '@inquirer/prompts';
import { execSync } from 'child_process';
import { loadConfig, saveConfig, type TrackedNode } from '../config.js';
import { runOnboarding, gcpDeployCmd, dockerRunCmd } from '../onboarding.js';
import { selectImage } from '../docker-hub.js';

export async function runNodeCommand(): Promise<void> {
    // eslint-disable-next-line no-constant-condition
    while (true) {
        const config = loadConfig();
        const names = Object.keys(config.profiles);

        const selected = await select<string>({
            message: 'Nodes',
            choices: [
                ...names.map(name => ({
                    name: name === config.defaultProfile ? `${name}  [default]` : name,
                    value: name,
                })),
                { name: '+ Add new node', value: '__new__' },
            ],
        });

        if (selected === '__new__') {
            const node = await runOnboarding(config.profiles);
            const cfg = loadConfig();
            cfg.profiles[node.name] = node;
            if (Object.keys(cfg.profiles).length === 1) cfg.defaultProfile = node.name;
            saveConfig(cfg);
            console.log(`\n  ✓ Profile "${node.name}" saved${cfg.defaultProfile === node.name ? ' (set as default)' : ''}.\n`);
        } else {
            await nodeDetailMenu(selected);
        }
    }
}

async function nodeDetailMenu(profileName: string): Promise<void> {
    const config = loadConfig();
    const node = config.profiles[profileName];
    if (!node) return;

    printNodeDetails(node, profileName === config.defaultProfile);

    type Action = 'update-image' | 'set-default' | 'delete' | 'back';
    const action = await select<Action>({
        message: 'Action',
        choices: [
            { name: 'Update image',    value: 'update-image' },
            ...(profileName !== config.defaultProfile
                ? [{ name: 'Set as default', value: 'set-default' as Action }]
                : []),
            { name: 'Delete',          value: 'delete' },
            { name: '← Back',          value: 'back' },
        ],
    });

    if (action === 'back') return;

    if (action === 'set-default') {
        config.defaultProfile = profileName;
        saveConfig(config);
        console.log(`\n  ✓ "${profileName}" is now the default profile.\n`);
        return;
    }

    if (action === 'update-image') {
        await updateImage(node, profileName);
        return;
    }

    if (action === 'delete') {
        const ok = await confirm({
            message: `Terminate and delete "${profileName}"? This cannot be undone.`,
            default: false,
        });
        if (!ok) return;
        await terminateNode(node);
        const cfg = loadConfig();
        delete cfg.profiles[profileName];
        if (cfg.defaultProfile === profileName) {
            cfg.defaultProfile = Object.keys(cfg.profiles)[0];
        }
        saveConfig(cfg);
        console.log(`\n  ✓ "${profileName}" deleted.\n`);
    }
}

function printNodeDetails(node: TrackedNode, isDefault: boolean): void {
    console.log();
    console.log(`  Profile   : ${node.name}${isDefault ? '  [default]' : ''}`);
    console.log(`  Address   : ${node.accountAddr}`);
    console.log(`  Platform  : ${node.platform === 'gcp' ? 'GCP Cloud Run' : 'Docker'}`);
    if (node.gcp) {
        console.log(`  Project   : ${node.gcp.project}`);
        console.log(`  Region    : ${node.gcp.region}`);
        console.log(`  Service   : ${node.gcp.serviceName}`);
    }
    if (node.docker) {
        console.log(`  Container : ${node.docker.containerName}`);
        console.log(`  Port      : ${node.docker.port}`);
    }
    console.log(`  Image     : ${node.image}`);
    console.log(`  Endpoint  : ${node.endpoint}`);
    console.log(`  RPC URL   : ${node.rpcUrl}`);
    console.log(`  Contract  : ${node.aceAddr}`);
    console.log();
}

async function updateImage(node: TrackedNode, profileName: string): Promise<void> {
    const newImage = await selectImage(node.image);
    if (newImage === node.image) {
        console.log('\n  Image unchanged.\n');
        return;
    }

    if (node.platform === 'gcp' && node.gcp) {
        const { project, region, serviceName } = node.gcp;
        const cmd = `gcloud run services update ${serviceName} --image docker.io/${newImage} --project ${project} --region ${region}`;
        console.log(`\n  $ ${cmd}\n`);
        execSync(cmd, { stdio: 'inherit' });
    } else if (node.platform === 'docker' && node.docker) {
        const { containerName, port } = node.docker;
        console.log(`\n  Stopping container "${containerName}"...`);
        try { execSync(`docker stop ${containerName} && docker rm ${containerName}`, { stdio: 'inherit' }); } catch { /* already stopped */ }
        const cmd = dockerRunCmd(containerName, newImage, port, node, node.rpcUrl, node.aceAddr, node.rpcApiKey, node.gasStationKey);
        console.log(`\n  $ ${cmd}\n`);
        execSync(cmd, { stdio: 'inherit' });
    }

    const cfg = loadConfig();
    if (cfg.profiles[profileName]) cfg.profiles[profileName]!.image = newImage;
    saveConfig(cfg);
    console.log(`\n  ✓ Image updated to ${newImage}\n`);
}

async function terminateNode(node: TrackedNode): Promise<void> {
    if (node.platform === 'gcp' && node.gcp) {
        const { project, region, serviceName } = node.gcp;
        const cmd = `gcloud run services delete ${serviceName} --project ${project} --region ${region} --quiet`;
        console.log(`\n  Terminating GCP Cloud Run service "${serviceName}"...`);
        try { execSync(cmd, { stdio: 'inherit' }); } catch (e) {
            console.error(`  Warning: ${e}`);
        }
    } else if (node.platform === 'docker' && node.docker) {
        const { containerName } = node.docker;
        console.log(`\n  Stopping Docker container "${containerName}"...`);
        try { execSync(`docker stop ${containerName} && docker rm ${containerName}`, { stdio: 'inherit' }); } catch (e) {
            console.error(`  Warning: ${e}`);
        }
    }
}
