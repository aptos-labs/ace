// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import {
  Account,
  AptosConfig,
  Aptos,
  Ed25519PrivateKey,
  Network,
  type SimpleEntryFunctionArgumentTypes,
} from '@aptos-labs/ts-sdk';
import { GasStationTransactionSubmitter } from '@aptos-labs/gas-station-client';
import type { NodeProfile } from './profile.js';

export interface RegisterOptions {
  rpcUrl: string;
  /** Geomi node API key — attached as `Authorization: Bearer` to every fullnode request. */
  rpcApikey?: string;
  aceAddr: string;
  /** Public HTTP URL this node will serve, e.g. `https://mynode.example.com:9000`. */
  endpoint: string;
  /** Geomi gas station API key.  When present the ACE deployer's gas station pays all gas. */
  gasStationKey?: string;
}

function inferNetwork(rpcUrl: string): Network {
  const url = rpcUrl.toLowerCase();
  if (url.includes('mainnet')) return Network.MAINNET;
  if (url.includes('testnet')) return Network.TESTNET;
  if (url.includes('devnet'))  return Network.DEVNET;
  if (url.includes('localhost') || url.includes('127.0.0.1')) return Network.LOCAL;
  return Network.CUSTOM;
}

function buildAptos(opts: RegisterOptions): Aptos {
  const network = inferNetwork(opts.rpcUrl);
  const clientConfig = opts.rpcApikey
    ? { HEADERS: { Authorization: `Bearer ${opts.rpcApikey}` } }
    : undefined;

  if (opts.gasStationKey) {
    const gasStation = new GasStationTransactionSubmitter({
      network,
      apiKey: opts.gasStationKey,
    });
    return new Aptos(new AptosConfig({
      network,
      fullnode: opts.rpcUrl,
      clientConfig,
      pluginSettings: { TRANSACTION_SUBMITTER: gasStation },
    }));
  }

  return new Aptos(new AptosConfig({ network, fullnode: opts.rpcUrl, clientConfig }));
}

/** Call a view function; returns the result array or null if the resource doesn't exist. */
async function tryView(aptos: Aptos, fn: string, args: string[]): Promise<unknown[] | null> {
  try {
    return await aptos.view({
      payload: {
        function: fn as `${string}::${string}::${string}`,
        typeArguments: [],
        functionArguments: args,
      },
    });
  } catch (e: unknown) {
    const msg = String((e as any)?.message ?? e);
    const vmCode = (e as any)?.data?.vm_error_code ?? (msg.match(/"vm_error_code":(\d+)/)?.[1] ? Number(msg.match(/"vm_error_code":(\d+)/)?.[1]) : undefined);
    if (
      msg.includes('resource_not_found') ||
      msg.includes('RESOURCE_DOES_NOT_EXIST') ||
      msg.includes('NOT_FOUND') ||
      vmCode === 4008  // Move MISSING_DATA: borrow_global on non-existent resource
    ) {
      return null;
    }
    throw e;
  }
}

export async function register(profile: NodeProfile, opts: RegisterOptions): Promise<void> {
  const aptos = buildAptos(opts);
  const sk = new Ed25519PrivateKey(profile.accountSk);
  const account = Account.fromPrivateKey({ privateKey: sk });

  const derivedAddr = account.accountAddress.toStringLong();
  if (derivedAddr !== profile.accountAddr) {
    throw new Error(
      `Private key derives address ${derivedAddr} but profile has ${profile.accountAddr}`,
    );
  }

  // Fund via faucet on localnet so the account can pay gas.
  if (inferNetwork(opts.rpcUrl) === Network.LOCAL) {
    process.stderr.write(`\nFunding account via localnet faucet...\n`);
    await aptos.fundAccount({ accountAddress: account.accountAddress, amount: 100_000_000 });
    process.stderr.write(`  ✓ Funded\n`);
  }

  const withFeePayer = !!opts.gasStationKey;

  async function submitEntry(fn: string, args: SimpleEntryFunctionArgumentTypes[]): Promise<void> {
    const txn = await aptos.transaction.build.simple({
      sender: account.accountAddress,
      ...(withFeePayer ? { withFeePayer: true } : {}),
      data: {
        function: fn as `${string}::${string}::${string}`,
        functionArguments: args,
      },
    });
    const response = await aptos.signAndSubmitTransaction({ signer: account, transaction: txn });
    process.stderr.write(`  txn ${response.hash}\n`);
    await aptos.waitForTransaction({ transactionHash: response.hash, options: { checkSuccess: true } });
    process.stderr.write(`  ✓ committed\n`);
  }

  // 1. Endpoint
  process.stderr.write(`\nChecking endpoint...\n`);
  const endpointResult = await tryView(aptos, `${opts.aceAddr}::worker_config::get_endpoint`, [profile.accountAddr]);
  if (endpointResult === null) {
    process.stderr.write(`  not registered — submitting register_endpoint\n`);
    await submitEntry(`${opts.aceAddr}::worker_config::register_endpoint`, [opts.endpoint]);
  } else {
    const onChain = endpointResult[0] as string;
    if (onChain !== opts.endpoint) {
      throw new Error(`Endpoint mismatch:\n  on-chain : ${onChain}\n  input    : ${opts.endpoint}`);
    }
    process.stderr.write(`  already registered, matches — skipping\n`);
  }

  // 2. PKE encryption key
  process.stderr.write(`\nChecking PKE encryption key...\n`);
  const pkeResult = await tryView(aptos, `${opts.aceAddr}::worker_config::get_pke_enc_key_bcs`, [profile.accountAddr]);
  const profileEkHex = profile.pkeEk.replace(/^0x/i, '').toLowerCase();
  if (pkeResult === null) {
    process.stderr.write(`  not registered — submitting register_pke_enc_key\n`);
    const ekBytes = Array.from(Buffer.from(profileEkHex, 'hex'));
    await submitEntry(`${opts.aceAddr}::worker_config::register_pke_enc_key`, [ekBytes]);
  } else {
    const onChainHex = (pkeResult[0] as string).replace(/^0x/i, '').toLowerCase();
    if (onChainHex !== profileEkHex) {
      throw new Error(`PKE enc key mismatch:\n  on-chain : 0x${onChainHex}\n  profile  : 0x${profileEkHex}`);
    }
    process.stderr.write(`  already registered, matches — skipping\n`);
  }

  process.stderr.write(`\nRegistration complete.\n`);
  process.stderr.write(`  Account : ${profile.accountAddr}\n`);
  process.stderr.write(`  Endpoint: ${opts.endpoint}\n`);
  process.stderr.write(`\nShare your account address with the ACE deployer to be added to the network.\n`);
}
