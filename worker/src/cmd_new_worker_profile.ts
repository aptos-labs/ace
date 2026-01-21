// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { ibe } from '@aptos-labs/ace-sdk';

export async function run(): Promise<void> {
  const ibeMsk = ibe.keygen().unwrapOrThrow('Failed to generate IBE master key');
  const ibeMpk = ibe.derivePublicKey(ibeMsk).unwrapOrThrow('Failed to derive IBE public key');
  
  console.log(`# ACE Worker Profile`);
  console.log(`# Generated at: ${new Date().toISOString()}`);
  console.log(`#`);
  console.log(`# IMPORTANT: Keep IBE_MSK secret! Only IBE_MPK should be shared publicly.`);
  console.log(``);
  console.log(`IBE_MSK=0x${ibeMsk.toHex()}`);
  console.log(`IBE_MPK=0x${ibeMpk.toHex()}`);
}

