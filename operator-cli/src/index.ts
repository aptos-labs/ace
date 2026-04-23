// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { Command } from 'commander';
import { newProfile } from './new-profile.js';
import { register } from './register.js';
import { run } from './run.js';
import { readProfile } from './profile.js';

const program = new Command();

program
  .name('ace-node')
  .description('CLI for ACE node operators')
  .version('0.1.0')
  .enablePositionalOptions();

// ── new-profile ───────────────────────────────────────────────────────────────

program
  .command('new-profile')
  .description(
    'Generate a new node profile: Ed25519 account keypair + PKE keypair.\n' +
    'Outputs .env format to stdout; human summary to stderr.\n\n' +
    'Usage: ace-node new-profile > ace-node.env',
  )
  .action(() => {
    newProfile();
  });

// ── register ──────────────────────────────────────────────────────────────────

program
  .command('register')
  .description(
    'Register this node on-chain at an ACE deployment.\n' +
    'Submits two transactions: register_endpoint and register_pke_enc_key.',
  )
  .option('--profile <path>',         'Profile .env file (default: read ACE_* env vars)')
  .requiredOption('--rpc-url <url>',   'Aptos fullnode URL for the ACE deployment')
  .option('--rpc-apikey <key>',        'Geomi node API key (Authorization: Bearer header, avoids rate limits)')
  .requiredOption('--ace-addr <addr>', 'ACE contract address on Aptos')
  .requiredOption('--endpoint <url>',  'Public HTTP URL this node will serve, e.g. https://mynode.example.com:9000')
  .option('--gas-station-key <key>',   'Geomi gas station API key (when set the deployer pays gas; otherwise the operator does)')
  .action(async (opts) => {
    try {
      const profile = readProfile(opts.profile);
      await register(profile, {
        rpcUrl:          opts.rpcUrl,
        rpcApikey:       opts.rpcApikey,
        aceAddr:         opts.aceAddr,
        endpoint:        opts.endpoint,
        gasStationKey:   opts.gasStationKey,
      });
    } catch (e) {
      process.stderr.write(`Error: ${e instanceof Error ? e.message : String(e)}\n`);
      process.exit(1);
    }
  });

// ── run ───────────────────────────────────────────────────────────────────────

program
  .command('run')
  .description(
    'Run the ACE node Docker image, translating the profile into network-node flags.\n\n' +
    'Any arguments after -- are forwarded verbatim to the network-node binary.\n\n' +
    'Usage: ace-node run --profile ace-node.env --rpc-url ... --ace-addr ... -- --max-concurrent 200',
  )
  .option('--profile <path>',         'Profile .env file (default: read ACE_* env vars)')
  .requiredOption('--rpc-url <url>',   'Aptos fullnode URL for the ACE deployment')
  .option('--rpc-apikey <key>',        'Geomi node API key (Authorization: Bearer header)')
  .requiredOption('--ace-addr <addr>', 'ACE contract address on Aptos')
  .option('--gas-station-key <key>',   'Geomi gas station API key')
  .option('--port <port>',             'Host port to expose and pass to the binary', parseInt)
  .option('--image <image>',           'Docker image to run', 'aptoslabs/ace-node:latest')
  .passThroughOptions()
  .argument('[extraArgs...]',          'Extra arguments forwarded to network-node run (after --)')
  .action((extraArgs: string[], opts) => {
    try {
      const profile = readProfile(opts.profile);
      run(profile, {
        rpcUrl:        opts.rpcUrl,
        rpcApikey:     opts.rpcApikey,
        aceAddr:       opts.aceAddr,
        gasStationKey: opts.gasStationKey,
        port:          opts.port,
        image:         opts.image,
        extraArgs,
      });
    } catch (e) {
      process.stderr.write(`Error: ${e instanceof Error ? e.message : String(e)}\n`);
      process.exit(1);
    }
  });

program.parse();
