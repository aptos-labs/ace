// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Step 5 — Alice rotates the `accessPublicKey` on-chain.
 *
 * Re-registering under the same `blob_suffix` overwrites the previous
 * entry; the old `accessPrivateKey` no longer signs anything that verifies
 * under the new `accessPublicKey`. This is the demo's "revoke" knob.
 *
 * The contract only checks that `accessPublicKey` is a well-formed G1 point.
 * Here Alice generates a fresh keypair directly from a secure RNG.
 */

import { Account, Ed25519PrivateKey } from '@aptos-labs/ts-sdk';
import { bytesToHex } from '@noble/hashes/utils';

import {
    ALICE_FILE, AccountFile, CONFIG_FILE, ConfigFile,
    aptosFromConfig, generateAccessKeypair, log, readAceConfig, readJson,
} from './common.js';

const BLOB_SUFFIX = 'song-1.mp3';

async function main() {
    const cfg = readAceConfig();
    const conf = readJson<ConfigFile>(CONFIG_FILE);
    const aliceFile = readJson<AccountFile>(ALICE_FILE);
    const alice = Account.fromPrivateKey({ privateKey: new Ed25519PrivateKey(aliceFile.privateKeyHex) });

    const aptos = aptosFromConfig(cfg);

    const { accessPublicKey: accessPublicKeyPrime } = generateAccessKeypair();
    log(`Rotating accessPublicKey -> 0x${bytesToHex(accessPublicKeyPrime)}`);

    const txn = await aptos.transaction.build.simple({
        sender: alice.accountAddress,
        data: {
            function: `${conf.appContractAddr}::capability_access::register` as `${string}::${string}::${string}`,
            typeArguments: [],
            functionArguments: [BLOB_SUFFIX, accessPublicKeyPrime],
        },
    });
    const submitted = await aptos.signAndSubmitTransaction({ signer: alice, transaction: txn });
    await aptos.waitForTransaction({ transactionHash: submitted.hash });
    log('Rotation done. The accessPrivateKey in data/capability.json is now stale.');
    log('');
    log('Next: pnpm 6-decrypt-after-rotate — the old capability should now be rejected.');
}

main().catch(err => { console.error(err); process.exit(1); });
