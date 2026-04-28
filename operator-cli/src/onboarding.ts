// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { input, select } from '@inquirer/prompts';
import { execSync } from 'child_process';
import { generateProfile } from './new-profile.js';
import { registerOnChain } from './register.js';
import { selectImage } from './docker-hub.js';
import { deriveRpcLabel, makeNodeKey, type TrackedNode, type Config } from './config.js';

function defaultGcpProject(): string | undefined {
    try {
        const out = execSync('gcloud config get-value project 2>/dev/null', { encoding: 'utf8' }).trim();
        return out || undefined;
    } catch {
        return undefined;
    }
}

function dockerRpcUrl(rpcUrl: string): string {
    return rpcUrl.replace(/localhost/g, 'host.docker.internal')
                 .replace(/127\.0\.0\.1/g, 'host.docker.internal');
}

export function gcpDeployCmd(
    serviceName: string, image: string, project: string, region: string,
    node: { accountAddr: string; accountSk: string; pkeDk: string },
    rpcUrl: string, aceAddr: string, rpcApiKey?: string, gasStationKey?: string,
): string {
    const args = nodeRunArgs(node, rpcUrl, aceAddr, rpcApiKey, gasStationKey);
    return [
        `gcloud run deploy ${serviceName}`,
        `  --image docker.io/${image}`,
        `  --project ${project}`,
        `  --region ${region}`,
        `  --no-allow-unauthenticated`,
        `  --min-instances 1`,
        `  --no-cpu-throttling`,
        `  --args "${args.join(',')}"`,
    ].join(' \\\n');
}

export function dockerRunCmd(
    containerName: string, image: string, port: string,
    node: { accountAddr: string; accountSk: string; pkeDk: string },
    rpcUrl: string, aceAddr: string, rpcApiKey?: string, gasStationKey?: string,
): string {
    rpcUrl = dockerRpcUrl(rpcUrl);
    return [
        `docker run -d --platform linux/amd64 --restart unless-stopped`,
        `  --name ${containerName}`,
        `  -p ${port}:${port}`,
        `  ${image}`,
        `  run`,
        `  --ace-deployment-api ${rpcUrl}`,
        `  --ace-deployment-addr ${aceAddr}`,
        ...(rpcApiKey     ? [`  --ace-deployment-apikey ${rpcApiKey}`]     : []),
        ...(gasStationKey ? [`  --ace-deployment-gaskey ${gasStationKey}`] : []),
        `  --account-addr ${node.accountAddr}`,
        `  --account-sk ${node.accountSk}`,
        `  --pke-dk ${node.pkeDk}`,
        `  --port ${port}`,
    ].join(' \\\n');
}

function nodeRunArgs(
    node: { accountAddr: string; accountSk: string; pkeDk: string },
    rpcUrl: string, aceAddr: string, rpcApiKey?: string, gasStationKey?: string,
): string[] {
    return [
        'run',
        `--ace-deployment-api=${rpcUrl}`,
        `--ace-deployment-addr=${aceAddr}`,
        ...(rpcApiKey     ? [`--ace-deployment-apikey=${rpcApiKey}`]     : []),
        ...(gasStationKey ? [`--ace-deployment-gaskey=${gasStationKey}`] : []),
        `--account-addr=${node.accountAddr}`,
        `--account-sk=${node.accountSk}`,
        `--pke-dk=${node.pkeDk}`,
        '--port=8080',
    ];
}

interface NetworkDetails {
    rpcUrl:     string;
    aceAddr:    string;
    rpcApiKey?: string;
    gasStationKey?: string;
}

/** Full guided wizard for adding a new node you control. */
export async function runOnboarding(
    existingConfig: Config,
): Promise<{ nodeKey: string; node: TrackedNode }> {
    console.log('\n  ACE Node Setup\n');

    console.log('Generating node keys...\n');
    const profile = generateProfile();
    console.log(`  Account address : ${profile.accountAddr}`);
    console.log(`  PKE enc key     : ${profile.pkeEk}\n`);

    // Network details — offer to copy from an existing node on the same network.
    let net: NetworkDetails;

    const existingNodes = Object.values(existingConfig.nodes);
    // Deduplicate by rpcUrl+aceAddr
    const uniqueNets = [...new Map(
        existingNodes.map(n => [`${n.rpcUrl}|${n.aceAddr}`, n]),
    ).values()];

    if (uniqueNets.length > 0) {
        const chosen = await select<string>({
            message: 'Which network?',
            choices: [
                ...uniqueNets.map(n => ({
                    name: n.alias
                        ? `${n.alias}  (${deriveRpcLabel(n.rpcUrl)})`
                        : deriveRpcLabel(n.rpcUrl),
                    value: `${n.rpcUrl}|||${n.aceAddr}|||${n.rpcApiKey ?? ''}|||${n.gasStationKey ?? ''}`,
                })),
                { name: '+ Enter new network details', value: '__new__' },
            ],
        });

        if (chosen !== '__new__') {
            const [rpcUrl, aceAddr, rpcApiKey, gasStationKey] = chosen.split('|||');
            net = { rpcUrl: rpcUrl!, aceAddr: aceAddr!, rpcApiKey: rpcApiKey || undefined, gasStationKey: gasStationKey || undefined };
            console.log();
        } else {
            net = await promptNetworkDetails();
        }
    } else {
        net = await promptNetworkDetails();
    }

    const image = await selectImage() ?? 'aptoslabs/ace-node:latest';
    console.log();

    const platform = await select<'gcp' | 'docker'>({
        message: 'Where will you run this node?',
        choices: [
            { name: 'Google Cloud Platform (Cloud Run)', value: 'gcp' },
            { name: 'My own machine (Docker)',            value: 'docker' },
        ],
    });

    let endpoint: string;
    let gcpCfg:    TrackedNode['gcp'];
    let dockerCfg: TrackedNode['docker'];

    if (platform === 'gcp') {
        const project     = await input({ message: 'GCP project ID', default: defaultGcpProject() });
        const region      = await input({ message: 'Region', default: 'us-central1' });
        const contractPrefix = net.aceAddr.replace(/^0x/i, '').slice(0, 6);
        const accountPrefix  = profile.accountAddr.replace(/^0x/i, '').slice(0, 6);
        const serviceName = await input({
            message: 'Service name',
            default: `ace-${contractPrefix}-${accountPrefix}`,
            validate: (val) => {
                if (!/^[a-z]/.test(val)) return 'Must begin with a lowercase letter';
                if (!/^[a-z][a-z0-9-]*$/.test(val)) return 'Only lowercase letters, digits, and hyphens are allowed';
                if (val.endsWith('-')) return 'Must not end with a hyphen';
                if (val.length >= 64) return 'Must be less than 64 characters';
                return true;
            },
        });
        gcpCfg = { project, region, serviceName };

        console.log('\nRun this command to deploy your node:\n');
        console.log(gcpDeployCmd(serviceName, image, project, region, profile, net.rpcUrl, net.aceAddr, net.rpcApiKey, net.gasStationKey));
        console.log();
        endpoint = await input({ message: 'Cloud Run service URL (paste after deploy completes)' });
    } else {
        const usedPorts = new Set(
            Object.values(existingConfig.nodes).map(n => n.docker?.port).filter(Boolean),
        );
        let defaultPort = 19000;
        while (usedPorts.has(String(defaultPort))) defaultPort++;

        const usedContainerNames = new Set(
            Object.values(existingConfig.nodes).map(n => n.docker?.containerName).filter(Boolean),
        );
        const defaultContainerName = (() => {
            if (!usedContainerNames.has('ace-node')) return 'ace-node';
            let i = 2;
            while (usedContainerNames.has(`ace-node-${i}`)) i++;
            return `ace-node-${i}`;
        })();

        const port          = await input({ message: 'Port', default: String(defaultPort) });
        const containerName = await input({ message: 'Container name', default: defaultContainerName });
        dockerCfg = { containerName, port };

        console.log('\nRun this command to start your node:\n');
        console.log(dockerRunCmd(containerName, image, port, profile, net.rpcUrl, net.aceAddr, net.rpcApiKey, net.gasStationKey));
        console.log();

        const isLocalnet = /localhost|127\.0\.0\.1/.test(net.rpcUrl);
        const defaultEndpoint = isLocalnet ? `http://localhost:${port}` : undefined;
        endpoint = await input({ message: "Your node's public URL", default: defaultEndpoint });
    }

    const alias = (await input({ message: 'Node alias (Enter to skip)', default: '' })).trim() || undefined;

    console.log('\nRegistering on-chain...\n');
    await registerOnChain(
        { ...profile, rpcUrl: net.rpcUrl, aceAddr: net.aceAddr, rpcApiKey: net.rpcApiKey, gasStationKey: net.gasStationKey },
        endpoint,
    );

    const node: TrackedNode = {
        rpcUrl:    net.rpcUrl,
        aceAddr:   net.aceAddr,
        rpcApiKey: net.rpcApiKey,
        accountAddr: profile.accountAddr,
        accountSk:   profile.accountSk,
        pkeDk:       profile.pkeDk,
        pkeEk:       profile.pkeEk,
        alias,
        endpoint,
        image,
        platform,
        gcp:          gcpCfg,
        docker:       dockerCfg,
        gasStationKey: net.gasStationKey,
    };

    const nodeKey = makeNodeKey(net.rpcUrl, net.aceAddr, profile.accountAddr);

    console.log('\nShare your account address with the ACE deployer to be added to the committee:\n');
    console.log(`  ${profile.accountAddr}\n`);

    return { nodeKey, node };
}

async function promptNetworkDetails(): Promise<NetworkDetails> {
    console.log('\nACE deployment details\n');
    const blob = (await input({ message: 'Paste deployment blob from admin (or Enter to fill manually)' })).trim();
    if (blob) {
        try {
            const p = JSON.parse(blob) as Record<string, string>;
            if (typeof p.rpcUrl === 'string' && typeof p.aceAddr === 'string') {
                console.log(`  ✓ Parsed — contract ${p.aceAddr.slice(0, 10)}...\n`);
                return {
                    rpcUrl:        p.rpcUrl,
                    aceAddr:       p.aceAddr,
                    rpcApiKey:     p.rpcApiKey     || undefined,
                    gasStationKey: p.gasStationKey || undefined,
                };
            }
        } catch {
            // fall through
        }
        console.log('  Could not parse blob — please fill in manually.\n');
    }

    const rpcUrl        = await input({ message: 'Deployment API URL' });
    const aceAddr       = await input({ message: 'Contract address' });
    const rpcApiKey     = (await input({ message: 'API key         (Enter to skip)' })) || undefined;
    const gasStationKey = (await input({ message: 'Gas station key (Enter to skip)' })) || undefined;
    console.log();
    return { rpcUrl, aceAddr, rpcApiKey, gasStationKey };
}
