// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Step 4 — Anyone holding `data/grant.json` decrypts the ciphertext.
 *
 * The bearer of the grant does not need an Aptos account — there is no
 * on-chain identity check at decrypt time. The contract's custom-flow
 * hook only verifies that the request's `claimed_origin` matches
 * `EXPECTED_APP_ORIGIN` AND that the request's BLS sig verifies under the
 * `accessPublicKey` registered for `label`. Possession of `accessPrivateKey` is the
 * single capability check.
 *
 * Flow:
 *   - Generate a fresh ephemeral PKE keypair for the response.
 *   - Sign `BCS(SignableRequest { dst, label, user_epk, origin })` with
 *     `accessPrivateKey`.
 *   - Wrap `payload = BCS({ origin, sig })` and call ACE.IBE_Aptos.decryptCustomFlow.
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
    log(`Decrypting "${new TextDecoder().decode(label)}"`);

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

    const plaintext = await ACE.IBE_Aptos.decryptCustomFlow({
        ciphertext, label,
        encPk: userEpkBytes, encSk: edk.toBytes(),
        payload,
        aceDeployment, keypairId: ibeKeypairId, chainId, moduleAddr, moduleName,
    });
    log(`Decrypted: "${new TextDecoder().decode(plaintext)}"`);
    log('');
    log('Try `pnpm 5-rotate` next to watch Alice revoke the grant by registering a fresh accessPublicKey.');
}

main().catch(err => { console.error(err); process.exit(1); });
