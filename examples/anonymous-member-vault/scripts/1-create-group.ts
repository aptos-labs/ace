// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Script 1 - Create Anonymous Member Group
 *
 * Builds a small Poseidon Merkle tree of member commitments. The tree root is
 * public and goes on-chain; each member keeps their secret + Merkle path private.
 *
 * Output:
 *   data/group.json
 *   data/member-credential.json  (one demo member's private credential)
 */

import * as path from 'path';
import { DATA_DIR, buildGroup, ensureDataDir, writeJson, type GroupData } from './common.js';

const DEFAULT_MEMBERS = ['alice', 'bob', 'carol', 'dana'];
const DEMO_MEMBER = 'bob';

async function main() {
    ensureDataDir();

    const group = await buildGroup(DEFAULT_MEMBERS);
    const credential = group.members.find(m => m.name === DEMO_MEMBER);
    if (!credential) throw new Error(`demo member ${DEMO_MEMBER} missing from group`);

    const publicGroup: GroupData = {
        depth: group.depth,
        root: group.root,
        members: group.members.map(({ name, index, commitment }) => ({ name, index, commitment })),
        leaves: group.leaves,
    };

    const groupPath = path.join(DATA_DIR, 'group.json');
    const credentialPath = path.join(DATA_DIR, 'member-credential.json');
    writeJson(groupPath, publicGroup);
    writeJson(credentialPath, credential);

    console.log('Anonymous member group created.');
    console.log(`  Members     : ${DEFAULT_MEMBERS.join(', ')}`);
    console.log(`  Public root : ${group.root}`);
    console.log(`  Demo member : ${credential.name}`);
    console.log('');
    console.log('group.json is public metadata: root + commitments, no member secrets.');
    console.log('member-credential.json contains bob\'s private member secret and path.');
    console.log('');
    console.log(`Saved group      : ${groupPath}`);
    console.log(`Saved credential : ${credentialPath}`);
    console.log('');
    console.log('Next: run `pnpm setup-circuit`, then script 2 to deploy the verifier.');
}

main().catch(err => { console.error(err); process.exit(1); });
