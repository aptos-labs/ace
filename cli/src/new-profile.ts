// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { Account } from '@aptos-labs/ts-sdk';
import { pke, sig } from '@aptos-labs/ace-sdk';
import type { NodeProfile } from './profile.js';

export async function generateProfile(): Promise<NodeProfile> {
  const account = Account.generate();
  const skHex = '0x' + Buffer.from(
    (account.privateKey as { toUint8Array(): Uint8Array }).toUint8Array(),
  ).toString('hex');

  const { encryptionKey, decryptionKey } = await pke.keygen();
  const sigKeypair = await sig.keygen();

  return {
    accountAddr: account.accountAddress.toStringLong(),
    accountSk:   skHex,
    pkeDk:       '0x' + decryptionKey.toHex(),
    pkeEk:       '0x' + encryptionKey.toHex(),
    sigSk:       '0x' + sigKeypair.signingKey.toHex(),
    sigPk:       '0x' + sigKeypair.publicKey.toHex(),
  };
}

export function formatEnvFile(p: NodeProfile): string {
  return [
    '# ACE node profile — KEEP THIS FILE SECRET',
    `# Generated: ${new Date().toISOString()}`,
    '#',
    '# ACE_ACCOUNT_ADDR  Aptos account address (safe to share)',
    '# ACE_ACCOUNT_SK    Ed25519 signing key   (SECRET)',
    '# ACE_PKE_DK        PKE decryption key    (SECRET)',
    '# ACE_PKE_EK        PKE encryption key    (safe to share; registered on-chain)',
    '# ACE_SIG_SK        Node-message signing key (SECRET)',
    '# ACE_SIG_PK        Node-message verification key (safe to share; registered on-chain)',
    `ACE_ACCOUNT_ADDR=${p.accountAddr}`,
    `ACE_ACCOUNT_SK=${p.accountSk}`,
    `ACE_PKE_DK=${p.pkeDk}`,
    `ACE_PKE_EK=${p.pkeEk}`,
    `ACE_SIG_SK=${p.sigSk}`,
    `ACE_SIG_PK=${p.sigPk}`,
    '',
  ].join('\n');
}
