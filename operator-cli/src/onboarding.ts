// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { input, select } from '@inquirer/prompts';
import { generateProfile } from './new-profile.js';
import { register } from './register.js';
import { selectImage } from './docker-hub.js';
import type { TrackedNode } from './config.js';

export async function runOnboarding(existingNames: string[]): Promise<TrackedNode> {
    console.log('\n  ACE Node Setup\n');

    const defaultName = (() => {
        if (!existingNames.includes('my-node')) return 'my-node';
        let i = 2;
        while (existingNames.includes(`my-node-${i}`)) i++;
        return `my-node-${i}`;
    })();
    const name = await input({
        message: 'Profile name',
        default: defaultName,
        validate: v => (existingNames.includes(v) ? `Profile "${v}" already exists` : true),
    });

    console.log('\nGenerating node keys...\n');
    const profile = generateProfile();
    console.log(`  Account address : ${profile.accountAddr}`);
    console.log(`  PKE enc key     : ${profile.pkeEk}\n`);

    console.log('ACE deployment details (ask your ACE deployer)\n');
    const rpcUrl        = await input({ message: 'Deployment API URL' });
    const aceAddr       = await input({ message: 'Contract address' });
    const rpcApiKey     = (await input({ message: 'API key         (Enter to skip)' })) || undefined;
    const gasStationKey = (await input({ message: 'Gas station key (Enter to skip)' })) || undefined;
    console.log();

    const image = await selectImage();
    console.log();

    const platform = await select<'gcp' | 'docker'>({
        message: 'Where will you run this node?',
        choices: [
            { name: 'Google Cloud Platform (Cloud Run)', value: 'gcp' },
            { name: 'My own machine (Docker)',            value: 'docker' },
        ],
    });

    let endpoint: string;
    let gcpCfg: TrackedNode['gcp'];
    let dockerCfg: TrackedNode['docker'];

    if (platform === 'gcp') {
        const project     = await input({ message: 'GCP project ID' });
        const region      = await input({ message: 'Region', default: 'us-central1' });
        const serviceName = await input({ message: 'Service name', default: 'ace-node' });
        gcpCfg = { project, region, serviceName };

        console.log('\nRun this command to deploy your node:\n');
        console.log(gcpDeployCmd(serviceName, image, project, region, profile, rpcUrl, aceAddr, rpcApiKey, gasStationKey));
        console.log();
        endpoint = await input({ message: 'Cloud Run service URL (paste after deploy completes)' });
    } else {
        const port          = await input({ message: 'Port', default: '9000' });
        const containerName = await input({ message: 'Container name', default: 'ace-node' });
        dockerCfg = { containerName, port };

        console.log('\nRun this command to start your node:\n');
        console.log(dockerRunCmd(containerName, image, port, profile, rpcUrl, aceAddr, rpcApiKey, gasStationKey));
        console.log();
        endpoint = await input({ message: "Your node's public URL (e.g. https://mynode.example.com:9000)" });
    }

    console.log('\nRegistering on-chain...\n');
    await register(profile, { rpcUrl, rpcApikey: rpcApiKey, aceAddr, endpoint, gasStationKey });

    console.log('\nShare your account address with the ACE deployer to be added to the committee:\n');
    console.log(`  ${profile.accountAddr}\n`);

    return {
        name,
        accountAddr: profile.accountAddr,
        accountSk:   profile.accountSk,
        pkeDk:       profile.pkeDk,
        pkeEk:       profile.pkeEk,
        rpcUrl,
        aceAddr,
        rpcApiKey,
        gasStationKey,
        image,
        platform,
        gcp:    gcpCfg,
        docker: dockerCfg,
        endpoint,
    };
}

function nodeRunArgs(
    profile: { accountAddr: string; accountSk: string; pkeDk: string },
    rpcUrl: string, aceAddr: string, rpcApiKey?: string, gasStationKey?: string,
): string[] {
    return [
        'run',
        `--ace-deployment-api=${rpcUrl}`,
        `--ace-deployment-addr=${aceAddr}`,
        ...(rpcApiKey     ? [`--ace-deployment-apikey=${rpcApiKey}`]     : []),
        ...(gasStationKey ? [`--ace-deployment-gaskey=${gasStationKey}`] : []),
        `--account-addr=${profile.accountAddr}`,
        `--account-sk=${profile.accountSk}`,
        `--pke-dk=${profile.pkeDk}`,
        '--port=8080',
    ];
}

export function gcpDeployCmd(
    serviceName: string, image: string, project: string, region: string,
    profile: { accountAddr: string; accountSk: string; pkeDk: string },
    rpcUrl: string, aceAddr: string, rpcApiKey?: string, gasStationKey?: string,
): string {
    return [
        `gcloud run deploy ${serviceName}`,
        `  --image docker.io/${image}`,
        `  --project ${project}`,
        `  --region ${region}`,
        `  --no-allow-unauthenticated`,
        `  --min-instances 1`,
        `  --no-cpu-throttling`,
        `  --args "${nodeRunArgs(profile, rpcUrl, aceAddr, rpcApiKey, gasStationKey).join(',')}"`,
    ].join(' \\\n');
}

export function dockerRunCmd(
    containerName: string, image: string, port: string,
    profile: { accountAddr: string; accountSk: string; pkeDk: string },
    rpcUrl: string, aceAddr: string, rpcApiKey?: string, gasStationKey?: string,
): string {
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
        `  --account-addr ${profile.accountAddr}`,
        `  --account-sk ${profile.accountSk}`,
        `  --pke-dk ${profile.pkeDk}`,
        `  --port ${port}`,
    ].join(' \\\n');
}
