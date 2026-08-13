// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * CI scenario: stand up the ACE local network, then exercise the Aptos custom flow
 * using the `check_acl_demo` contract.
 *
 * Test cases:
 *   - Encrypt a plaintext, decrypt with wrong payload → expect failure.
 *   - Decrypt with correct payload → expect success, verify plaintext.
 *   - Step A: decrypt with a nonexistent keypair_id → expect failure.
 *   - Step C: decrypt with a wrong label → expect failure.
 */

import { AccountAddress } from '@aptos-labs/ts-sdk';
import * as ACE from '@aptos-labs/ace-sdk';
import { pathToFileURL } from 'url';

import {
    CHAIN_ID,
} from './common/config';
import {
    assert,
    log,
} from './common/helpers';
import {
    type AptosCustomFlowSetup,
    bringUpAceAndDeployCheckAclDemo,
    prepareEncryptedContent,
} from './custom-flow-aptos/helpers';

async function main() {
    let setup: AptosCustomFlowSetup | undefined;
    const cleanup = () => {
        if (setup) for (const p of setup.nodeProcs) p.kill();
        setup?.localnetProc.kill();
    };
    process.on('SIGINT', () => { cleanup(); process.exit(1); });
    process.on('SIGTERM', () => { cleanup(); process.exit(1); });

    let exitCode = 0;
    try {
        setup = await bringUpAceAndDeployCheckAclDemo();
        await runCustomFlowTestCases(setup);
        log('\n✅ Aptos custom-flow tests passed!\n');
    } catch (err) {
        console.error('\n❌ Test failed:', err);
        exitCode = 1;
    } finally {
        cleanup();
        process.exit(exitCode);
    }
}

/** Run all four custom-flow test cases against the prepared setup:
 *  wrong-payload (B) / happy-path (D) / bad-keypair_id (A) / wrong-label (C). */
async function runCustomFlowTestCases(setup: AptosCustomFlowSetup): Promise<void> {
    const f = await prepareEncryptedContent(setup);
    log('Attempting decrypt with wrong payload (should fail)...');
    await expectCustomFlowDecryptFails(
        { ...f.baseArgs, label: f.label, payload: f.wrongCode, keypairId: f.keypairId },
        'wrong payload',
    );
    log('Attempting decrypt with correct payload (should succeed)...');
    // Keep the custom-flow identity-key-share path covered instead of relying
    // only on the one-shot decrypt wrapper.
    const identityKeyShares = (await ACE.IBE_Aptos.fetchIdentityKeySharesCustomFlow({
        label: f.label,
        encPk: f.baseArgs.encPk,
        encSk: f.baseArgs.encSk,
        payload: f.correctCode,
        aceDeployment: f.baseArgs.aceDeployment,
        keypairId: f.keypairId,
        chainId: CHAIN_ID,
        moduleAddr: f.adminAddr,
        moduleName: 'check_acl_demo',
    })).unwrapOrThrow('fetchIdentityKeySharesCustomFlow failed');
    const decrypted = ACE.IBE_Aptos.decryptWithIdentityKeyShares({
        ciphertext: f.baseArgs.ciphertext,
        identityKeyShares,
    }).unwrapOrThrow('decryptWithIdentityKeyShares failed');
    assert(
        new TextDecoder().decode(decrypted) === 'HELLO CUSTOM FLOW',
        `plaintext mismatch: ${new TextDecoder().decode(decrypted)}`,
    );
    log('Correct payload accepted; plaintext recovered ✓');
    // Step A: bad keypair_id → SDK pre-flight `fetchCurrentSessionPks` throws.
    log('Step A: decrypt with nonexistent keypair_id (should fail)...');
    await expectCustomFlowDecryptFails(
        { ...f.baseArgs, label: f.label, payload: f.correctCode,
            keypairId: AccountAddress.fromString('0x' + 'ab'.repeat(32)) },
        'bad keypair_id',
    );
    // Step C: wrong label → on-chain custom-flow hook returns false → HTTP 403.
    log('Step C: decrypt with wrong label (should fail)...');
    await expectCustomFlowDecryptFails(
        { ...f.baseArgs, label: new TextEncoder().encode('different-content'),
            payload: f.correctCode, keypairId: f.keypairId },
        'wrong label',
    );
}

/** Calls ACE.IBE_Aptos.decryptCustomFlow with the given args; asserts that the
 *  call throws (i.e., decrypt is rejected). Logs the case label. */
async function expectCustomFlowDecryptFails(
    args: Parameters<typeof ACE.IBE_Aptos.decryptCustomFlow>[0],
    caseLabel: string,
): Promise<void> {
    let failed = false;
    try {
        await ACE.IBE_Aptos.decryptCustomFlow(args);
    } catch (_e) {
        failed = true;
    }
    assert(failed, `${caseLabel}: decrypt should have been rejected`);
    log(`  ✓ ${caseLabel} rejected`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
    main();
}
