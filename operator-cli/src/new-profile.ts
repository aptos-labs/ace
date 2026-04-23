// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { Account } from '@aptos-labs/ts-sdk';
import { pke } from '@aptos-labs/ace-sdk';

export function newProfile(): void {
  const account = Account.generate();
  const addr = account.accountAddress.toStringLong();
  const skHex = Buffer.from(
    (account.privateKey as { toUint8Array(): Uint8Array }).toUint8Array(),
  ).toString('hex');

  const { encryptionKey, decryptionKey } = pke.keygen();
  const dk = '0x' + decryptionKey.toHex();
  const ek = '0x' + encryptionKey.toHex();

  // Human-readable summary → stderr (does not pollute a redirected .env file)
  process.stderr.write(`ACE node profile generated.\n`);
  process.stderr.write(`  Account address : ${addr}\n`);
  process.stderr.write(`  PKE enc key     : ${ek}\n`);
  process.stderr.write(`\n`);
  process.stderr.write(`Fund the account before calling 'register'.\n`);
  process.stderr.write(`  https://aptos.dev/network/faucet?address=${addr}\n`);
  process.stderr.write(`\n`);
  process.stderr.write(`Save the profile: ace-node new-profile > ace-node.env\n`);

  // .env content → stdout
  console.log(`# ACE node profile — KEEP THIS FILE SECRET`);
  console.log(`# Generated: ${new Date().toISOString()}`);
  console.log(`#`);
  console.log(`# ACE_ACCOUNT_ADDR  Aptos account address (safe to share)`);
  console.log(`# ACE_ACCOUNT_SK    Ed25519 signing key   (SECRET)`);
  console.log(`# ACE_PKE_DK        PKE decryption key    (SECRET)`);
  console.log(`# ACE_PKE_EK        PKE encryption key    (safe to share; registered on-chain)`);
  console.log(`ACE_ACCOUNT_ADDR=${addr}`);
  console.log(`ACE_ACCOUNT_SK=0x${skHex}`);
  console.log(`ACE_PKE_DK=${dk}`);
  console.log(`ACE_PKE_EK=${ek}`);
}
