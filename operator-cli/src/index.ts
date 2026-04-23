// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { input, select } from '@inquirer/prompts';
import { writeFileSync } from 'fs';
import { generateProfile, formatEnvFile } from './new-profile.js';
import { register } from './register.js';

async function main(): Promise<void> {
  console.log('\n  ACE Node Setup\n');

  // ── Step 1: Profile ────────────────────────────────────────────────────────
  console.log('Step 1 · Generate your node profile\n');
  const profile = generateProfile();
  console.log(`  Account address : ${profile.accountAddr}`);
  console.log(`  PKE enc key     : ${profile.pkeEk}\n`);

  const savePath = await input({ message: 'Save profile to', default: './ace-node.env' });
  writeFileSync(savePath, formatEnvFile(profile), { mode: 0o600 });
  console.log(`  ✓ Saved to ${savePath}  (keep it secret — contains private keys)\n`);

  // ── Step 2: Deployment details ─────────────────────────────────────────────
  console.log('Step 2 · ACE deployment details  (get these from the ACE deployer)\n');
  const rpcUrl        = await input({ message: 'Deployment API URL' });
  const aceAddr       = await input({ message: 'Contract address' });
  const rpcApikey     = (await input({ message: 'API key          (Enter to skip)' })) || undefined;
  const gasStationKey = (await input({ message: 'Gas station key  (Enter to skip)' })) || undefined;
  const image         = await input({ message: 'Node image', default: 'aptoslabs/ace-node:latest' });
  console.log();

  // ── Step 3: Platform ───────────────────────────────────────────────────────
  console.log('Step 3 · Start your node\n');
  const platform = await select<'gcp' | 'docker'>({
    message: 'Where will you run your node?',
    choices: [
      { name: 'Google Cloud Platform (Cloud Run)', value: 'gcp'    },
      { name: 'My own machine (Docker)',            value: 'docker' },
    ],
  });

  let endpoint: string;

  if (platform === 'gcp') {
    const project     = await input({ message: 'GCP project ID' });
    const region      = await input({ message: 'Region', default: 'us-central1' });
    const serviceName = await input({ message: 'Service name', default: 'ace-node' });

    const nodeArgs = [
      'run',
      `--ace-deployment-api=${rpcUrl}`,
      `--ace-deployment-addr=${aceAddr}`,
      ...(rpcApikey     ? [`--ace-deployment-apikey=${rpcApikey}`]     : []),
      ...(gasStationKey ? [`--ace-deployment-gaskey=${gasStationKey}`] : []),
      `--account-addr=${profile.accountAddr}`,
      `--account-sk=${profile.accountSk}`,
      `--pke-dk=${profile.pkeDk}`,
      '--port=8080',
    ].join(',');

    const cmd = [
      `gcloud run deploy ${serviceName}`,
      `  --image docker.io/${image}`,
      `  --project ${project}`,
      `  --region ${region}`,
      `  --no-allow-unauthenticated`,
      `  --min-instances 1`,
      `  --no-cpu-throttling`,
      `  --args "${nodeArgs}"`,
    ].join(' \\\n');

    console.log('\nRun this command to deploy your node:\n');
    console.log(cmd);
    console.log();

    endpoint = await input({ message: 'Cloud Run service URL (paste after deploy completes)' });

  } else {
    const port = await input({ message: 'Port', default: '9000' });

    const cmd = [
      'docker run -d --platform linux/amd64',
      `  -p ${port}:${port}`,
      `  ${image}`,
      `  run`,
      `  --ace-deployment-api ${rpcUrl}`,
      `  --ace-deployment-addr ${aceAddr}`,
      ...(rpcApikey     ? [`  --ace-deployment-apikey ${rpcApikey}`]     : []),
      ...(gasStationKey ? [`  --ace-deployment-gaskey ${gasStationKey}`] : []),
      `  --account-addr ${profile.accountAddr}`,
      `  --account-sk ${profile.accountSk}`,
      `  --pke-dk ${profile.pkeDk}`,
      `  --port ${port}`,
    ].join(' \\\n');

    console.log('\nRun this command to start your node:\n');
    console.log(cmd);
    console.log();

    endpoint = await input({ message: "Your node's public URL (e.g. https://mynode.example.com:9000)" });
  }

  // ── Step 4: Register ───────────────────────────────────────────────────────
  console.log('\nStep 4 · Register on-chain\n');
  await register(profile, { rpcUrl, rpcApikey, aceAddr, endpoint, gasStationKey });

  // ── Step 5: Done ───────────────────────────────────────────────────────────
  console.log('\nStep 5 · All done!\n');
  console.log('Share your account address with the ACE deployer to be added to the network:\n');
  console.log(`  ${profile.accountAddr}\n`);
}

main().catch((e: unknown) => {
  if ((e as any)?.name === 'ExitPromptError') {
    console.log('\nSetup cancelled.');
    process.exit(0);
  }
  process.stderr.write(`\nError: ${e instanceof Error ? e.message : String(e)}\n`);
  process.exit(1);
});
