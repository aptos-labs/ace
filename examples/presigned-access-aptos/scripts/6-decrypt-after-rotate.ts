// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Step 6 — The stale grant from step 3 no longer decrypts.
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
    APP_ORIGIN, CONFIG_FILE, ConfigFile, GRANT_FILE, GrantFile, ReaderProof, SignableRequest,
    accessPrivateKeyFromHex, aceDeploymentFromConfig, aptosFromConfig, log,
    readAceConfig, readJson, signWithAccessPrivateKey,
} from './common.js';

async function main() {
    const cfg = readAceConfig();
    const conf = readJson<ConfigFile>(CONFIG_FILE);
    const grant = readJson<GrantFile>(GRANT_FILE);

    const aceDeployment = aceDeploymentFromConfig(cfg);
    const ibeKeypairId = AccountAddress.fromString(cfg.ibeKeypairId);
    const moduleAddr = AccountAddress.fromString(conf.appContractAddr);
    const moduleName = 'presigned_access';

    const label = hexToBytes(grant.blobIdHex);
    const ciphertext = hexToBytes(grant.ciphertextHex);
    const accessPrivateKey = accessPrivateKeyFromHex(grant.accessPrivateKeyHex);

    const { encryptionKey: epk, decryptionKey: edk } = await ACE.pke.keygen();
    const userEpkBytes = epk.toBytes();
    const originBytes = new TextEncoder().encode(APP_ORIGIN);
    const sig = signWithAccessPrivateKey(
        accessPrivateKey,
        new SignableRequest({ label, userEpk: userEpkBytes, origin: originBytes }).toBytes(),
    );
    const payload = new ReaderProof({ origin: originBytes, sig }).toBytes();

    const aptos = aptosFromConfig(cfg);
    const chainId = await aptos.getChainId();

    log('Attempting decrypt with the now-stale accessPrivateKey (should fail)...');
    try {
        await ACE.IBE_Aptos.decryptCustomFlow({
            ciphertext, label,
            encPk: userEpkBytes, encSk: edk.toBytes(),
            payload,
            aceDeployment, keypairId: ibeKeypairId, chainId, moduleAddr, moduleName,
        });
        console.error('UNEXPECTED: decrypt succeeded after rotation.');
        process.exit(1);
    } catch (e) {
        log(`Decrypt rejected (expected): ${(e as Error).message?.split('(')[0].trim() ?? e}`);
    }
    log('');
    log('Demo complete — rotation revoked the grant.');
}

main().catch(err => { console.error(err); process.exit(1); });
