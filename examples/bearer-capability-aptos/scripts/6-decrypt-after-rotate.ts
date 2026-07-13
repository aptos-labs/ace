// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Step 6 — The stale capability from step 3 no longer decrypts.
 *
 * Same decrypt flow as step 4 — same accessPrivateKey, same signed message
 * shape — but the on-chain accessPublicKey has been rotated by step 5, so the
 * sig under the *old* accessPrivateKey doesn't verify against the *new*
 * accessPublicKey. Workers return 403 and the SDK reports the share count is
 * below threshold.
 */

import { AccountAddress } from '@aptos-labs/ts-sdk';
import * as ACE from '@aptos-labs/ace-sdk';
import { hexToBytes } from '@noble/hashes/utils';

import {
    APP_ORIGIN, CONFIG_FILE, ConfigFile, CAPABILITY_FILE, CapabilityFile, ReaderProof, SignableRequest,
    accessPrivateKeyFromHex, aceDeploymentFromConfig, aptosFromConfig, log,
    readAceConfig, readJson, signWithAccessPrivateKey,
} from './common.js';

async function main() {
    const cfg = readAceConfig();
    const conf = readJson<ConfigFile>(CONFIG_FILE);
    const capability = readJson<CapabilityFile>(CAPABILITY_FILE);

    const aceDeployment = aceDeploymentFromConfig(cfg);
    const ibeKeypairId = AccountAddress.fromString(cfg.ibeKeypairId);
    const moduleAddr = AccountAddress.fromString(conf.appContractAddr);
    const moduleName = 'capability_access';

    const label = hexToBytes(capability.blobIdHex);
    const ciphertext = hexToBytes(capability.ciphertextHex);
    const accessPrivateKey = accessPrivateKeyFromHex(capability.accessPrivateKeyHex);

    const aptos = aptosFromConfig(cfg);
    const chainId = await aptos.getChainId();
    const session = await ACE.IBE_Aptos.CustomDecryptionSession.create({
        aceDeployment, keypairId: ibeKeypairId, chainId, moduleAddr, moduleName, label,
    });
    const userEpkBytes = session.getEncryptionKeyBytes();
    const originBytes = new TextEncoder().encode(APP_ORIGIN);
    const sig = signWithAccessPrivateKey(
        accessPrivateKey,
        new SignableRequest({ label, userEpk: userEpkBytes, origin: originBytes }).toBytes(),
    );
    const payload = new ReaderProof({ origin: originBytes, sig }).toBytes();

    log('Attempting decrypt with the now-stale accessPrivateKey (should fail)...');
    const result = await session.decrypt({ ciphertext, payload });
    if (result.isOk) {
        console.error('UNEXPECTED: decrypt succeeded after rotation.');
        process.exit(1);
    }
    log(`Decrypt rejected (expected): ${String(result.errValue).split('(')[0].trim()}`);
    log('');
    log('Demo complete — rotation revoked the capability.');
}

main().catch(err => { console.error(err); process.exit(1); });
