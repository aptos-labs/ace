// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Step 6 — The stale grant from step 3 no longer decrypts.
 *
 * Same decrypt flow as step 4 — same accessToken, same signed message
 * shape — but the on-chain accessPk has been rotated by step 5, so the
 * sig under the *old* accessToken doesn't verify against the *new*
 * accessPk. Workers return 403 and the SDK reports the share count is
 * below threshold.
 */

import { AccountAddress, Aptos, AptosConfig, Network } from '@aptos-labs/ts-sdk';
import * as ACE from '@aptos-labs/ace-sdk';
import { hexToBytes } from '@noble/hashes/utils';

import {
    APP_ORIGIN, CONFIG_FILE, ConfigFile, GRANT_FILE, GrantFile,
    aceDeploymentFromConfig, buildPayload, buildSignableMessage, log,
    readJson, readLocalnetConfig, signWithAccessToken, vrfOutputToAccessToken,
} from './common.js';

async function main() {
    const cfg = readLocalnetConfig();
    const conf = readJson<ConfigFile>(CONFIG_FILE);
    const grant = readJson<GrantFile>(GRANT_FILE);

    const aceDeployment = aceDeploymentFromConfig(cfg);
    const keypairId = AccountAddress.fromString(cfg.keypairId);
    const moduleAddr = AccountAddress.fromString(conf.appContractAddr);
    const moduleName = 'presigned_access';

    const label = hexToBytes(grant.blobIdHex);
    const ciphertext = hexToBytes(grant.ciphertextHex);
    const accessToken = vrfOutputToAccessToken(hexToBytes(grant.accessTokenHex));

    const { encryptionKey: epk, decryptionKey: edk } = await ACE.pke.keygen();
    const userEpkBytes = epk.toBytes();
    const originBytes = new TextEncoder().encode(APP_ORIGIN);
    const sig = signWithAccessToken(
        accessToken,
        buildSignableMessage({ label, userEpk: userEpkBytes, origin: originBytes }),
    );
    const payload = buildPayload(originBytes, sig);

    const aptos = new Aptos(new AptosConfig({ network: Network.LOCAL, fullnode: cfg.apiEndpoint }));
    const chainId = await aptos.getChainId();

    log('Attempting decrypt with the now-stale accessToken (should fail)...');
    try {
        await ACE.AptosCustomFlow.decrypt({
            ciphertext, label,
            encPk: userEpkBytes, encSk: edk.toBytes(),
            payload,
            aceDeployment, keypairId, chainId, moduleAddr, moduleName,
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
