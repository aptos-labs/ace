// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Disaster-recovery reconstruction test.
 *
 * Brings up a 3-worker committee (mixed monolith + split handler) launched with
 * `--reconstructor-pk`, runs one DKG, then:
 *   A. reconstructs the master secret with the correct reconstructor key and
 *      verifies it against the on-chain master public key;
 *   B. confirms a WRONG reconstructor key is rejected by every node, so the
 *      reconstruction can't reach threshold.
 *
 * This exercises the full cross-language wire path (TS-built, per-node-encrypted
 * ReconstructionRequest → Rust worker verify + raw-share release → TS Lagrange).
 *
 * Run:
 *   cd scenarios && pnpm test-reconstruction
 */

import { adminRecovery, sig } from '@aptos-labs/ace-sdk';
import { ChildProcess } from 'child_process';

import { CHAIN_ID } from './common/config';
import { setupAceOnLocalnet } from './common/ace-network';
import { assert, cleanupScenario, fundAccount } from './common/helpers';

const TOTAL_WORKERS = 3;
const EPOCH0_WORKER_INDICES = [0, 1, 2];
const EPOCH0_THRESHOLD = 2;

async function main(): Promise<void> {
    let workers: ChildProcess[] = [];
    let localnetProc: ChildProcess | null = null;
    let exitCode = 0;
    try {
        const { publicKey, signingKey } = await sig.keygen();

        const setup = await setupAceOnLocalnet({
            totalWorkers: TOTAL_WORKERS,
            epoch0WorkerIndices: EPOCH0_WORKER_INDICES,
            epoch0Threshold: EPOCH0_THRESHOLD,
            fundAccount,
            numKeypairs: 1,
            reconstructorPk: publicKey.toHex(),
        });
        localnetProc = setup.localnetProc;
        workers = setup.ace.workers;
        const { ace, keypairIds: [keypairId] } = setup;

        // ── A. Happy path: reconstruct with the correct key ────────────────────
        const result = await adminRecovery.reconstructSecret({
            aceDeployment: ace.aceDeployment,
            keypairId: keypairId!,
            signingKey,
            chainId: CHAIN_ID,
            log: m => console.log(`  ${m}`),
        });
        assert(
            result.sharesUsed >= EPOCH0_THRESHOLD,
            `expected >= ${EPOCH0_THRESHOLD} shares, got ${result.sharesUsed}`,
        );
        assert(
            result.verified === true,
            `reconstructed secret failed master-pk verification (verified=${result.verified})`,
        );
        console.log(`✔ reconstructed master secret (verified against master pk): ${result.secretHex}`);

        // ── B. Negative: a wrong reconstructor key is rejected by every node ───
        const wrong = (await sig.keygen()).signingKey;
        let rejected = false;
        try {
            await adminRecovery.reconstructSecret({
                aceDeployment: ace.aceDeployment,
                keypairId: keypairId!,
                signingKey: wrong,
                chainId: CHAIN_ID,
                log: () => {},
            });
        } catch {
            rejected = true;
        }
        assert(rejected, 'expected reconstruction with a wrong reconstructor key to fail (below threshold)');
        console.log('✔ wrong reconstructor key rejected by the committee');

        console.log('\n✅ Reconstruction disaster-recovery test passed!\n');
    } catch (err) {
        console.error('\n❌ Test failed:', err);
        exitCode = 1;
    } finally {
        cleanupScenario(workers, localnetProc);
        process.exit(exitCode);
    }
}

main();
