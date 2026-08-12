// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * CI scenario: stand up the ACE Aptos localnet custom-flow environment, then
 * verify the Python SDK can decrypt through the real worker HTTP endpoints.
 */

import { execFile } from 'child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'fs';
import * as os from 'os';
import * as path from 'path';

import {
    CHAIN_ID,
    LOCALNET_URL,
    REPO_ROOT,
} from './common/config';
import {
    cleanupScenario,
    log,
} from './common/helpers';
import {
    type AptosCustomFlowSetup,
    bringUpAceAndDeployCheckAclDemo,
    prepareEncryptedContent,
} from './custom-flow-aptos/helpers';

const PYTHON_BIN = path.join(REPO_ROOT, 'python-sdk', '.venv', 'bin', 'python');
const PYTHON_CLIENT = path.join(REPO_ROOT, 'scenarios', 'python-sdk-custom-flow-client.py');
const EXPECTED_PLAINTEXT = 'HELLO CUSTOM FLOW';

function hex(data: Uint8Array): string {
    return Buffer.from(data).toString('hex');
}

function accountHex(addr: { toStringLong(): string }): string {
    return addr.toStringLong();
}

function writePythonClientInput(setup: AptosCustomFlowSetup): Promise<string> {
    return prepareEncryptedContent(setup).then(fixtures => {
        const tmpRoot = mkdtempSync(path.join(os.tmpdir(), 'ace-python-sdk-custom-flow-'));
        const fixturePath = path.join(tmpRoot, 'fixture.json');
        writeFileSync(fixturePath, JSON.stringify({
            api_endpoint: LOCALNET_URL,
            contract_addr: accountHex(fixtures.adminAddr),
            keypair_id: accountHex(fixtures.keypairId),
            chain_id: CHAIN_ID,
            module_addr: accountHex(fixtures.adminAddr),
            module_name: 'check_acl_demo',
            label_hex: hex(fixtures.label),
            payload_hex: hex(fixtures.correctCode),
            enc_pk_hex: hex(fixtures.baseArgs.encPk),
            enc_sk_hex: hex(fixtures.baseArgs.encSk),
            ciphertext_hex: hex(fixtures.baseArgs.ciphertext),
            expected_plaintext: EXPECTED_PLAINTEXT,
        }), 'utf8');
        return fixturePath;
    });
}

function runPythonClient(fixturePath: string): Promise<void> {
    return new Promise((resolve, reject) => {
        const child = execFile(PYTHON_BIN, [PYTHON_CLIENT, fixturePath], {
            cwd: path.join(REPO_ROOT, 'scenarios'),
        });
        child.stdout?.on('data', chunk => process.stdout.write(chunk));
        child.stderr?.on('data', chunk => process.stderr.write(chunk));
        child.once('error', reject);
        child.once('close', code => {
            if (code === 0) resolve();
            else reject(new Error(`Python custom-flow client exited with code ${code}`));
        });
    });
}

async function main(): Promise<void> {
    let setup: AptosCustomFlowSetup | undefined;
    let fixturePath: string | undefined;
    let exitCode = 0;
    try {
        setup = await bringUpAceAndDeployCheckAclDemo();
        fixturePath = await writePythonClientInput(setup);
        await runPythonClient(fixturePath);
        log('\n✅ Python SDK custom-flow scenario passed!\n');
    } catch (err) {
        console.error('\n❌ Test failed:', err);
        exitCode = 1;
    } finally {
        if (fixturePath) rmSync(path.dirname(fixturePath), { recursive: true, force: true });
        if (setup) cleanupScenario(setup.nodeProcs, setup.localnetProc);
        process.exit(exitCode);
    }
}

main();
