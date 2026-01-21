#!/usr/bin/env node
// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { Command } from 'commander';
import * as NewWorkerProfile from './cmd_new_worker_profile.js';
import * as RunWorker from './cmd_run_worker.js';

const program = new Command();

program
  .name('ace-worker')
  .description('ACE Worker - key management and decryption share generation')
  .version('0.1.0');

program
  .command('new-worker-profile')
  .description('Generate a new worker profile with IBE master keys.')
  .action(NewWorkerProfile.run);

program
  .command('run-worker')
  .description(`Start the ACE worker server.

Environment Variables:
  IBE_MSK                       (required) IBE master secret key in hex
  IBE_MPK                       (optional) IBE master public key for validation

  APTOS_MAINNET_API_ENDPOINT    Aptos mainnet RPC endpoint
  APTOS_MAINNET_API_KEY         Aptos mainnet API key
  APTOS_TESTNET_API_ENDPOINT    Aptos testnet RPC endpoint
  APTOS_TESTNET_API_KEY         Aptos testnet API key
  APTOS_LOCALNET_API_ENDPOINT   Aptos localnet RPC endpoint

  SOLANA_MAINNET_API_ENDPOINT   Solana mainnet-beta RPC endpoint
  SOLANA_TESTNET_API_ENDPOINT   Solana testnet RPC endpoint
  SOLANA_DEVNET_API_ENDPOINT    Solana devnet RPC endpoint
  SOLANA_LOCALNET_API_ENDPOINT  Solana localnet RPC endpoint`)
  .requiredOption('--port <port>', 'Port to listen on', (value) => parseInt(value, 10))
  .action((options) => RunWorker.run({ port: options.port }));

program.parse();

