// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { buildV6GovernancePayload, serializeV6EpochConfig } from './v6-governance.js';
import { deriveResourceAccount } from './v6-bootstrap.js';

const a = `0x${'00'.repeat(31)}01`;
const b = `0x${'00'.repeat(31)}02`;
const admin = `0x${'00'.repeat(31)}03`;

test('v6 resource address uses Aptos account derivation', () => {
    assert.equal(
        deriveResourceAccount('0x1', Uint8Array.from([0xab, 0xcd])),
        '0xa33e40f2d8e3dd5af8fbfd07ce872bd3675eda6cd6c589444f078b5a000ac6f1',
    );
});

test('v6 config BCS agrees with Python SDK and Move field order', () => {
    const config = {
        nodes: [a, b], threshold: 2, epoch_duration_micros: 30_000_000,
        secrets_to_retain: [a], new_secrets: [{ expected_usage: 2, note: 'x' }],
        description: 'next', target_epoch: 5, next_admin_multisig: admin,
        features_to_activate: [0, 63],
    };
    const expected = '0200000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002020000000000000080c3c901000000000100000000000000000000000000000000000000000000000000000000000000010102000000000000000178046e657874050000000000000000000000000000000000000000000000000000000000000000000000000000030200000000000000003f00000000000000';
    assert.equal(Buffer.from(serializeV6EpochConfig(config)).toString('hex'), expected);
    const payload = buildV6GovernancePayload('epoch-config', admin, config);
    assert.equal(payload[0], 0); // native MultisigTransactionPayload::EntryFunction
    assert.equal(Buffer.from(payload).toString('hex').endsWith(expected), true);
});

test('v6 proposal refuses an invalid feature or mismatched threshold', () => {
    const config = {
        nodes: [a, b], threshold: 2, epoch_duration_micros: 30_000_000,
        secrets_to_retain: [], new_secrets: [], description: '', target_epoch: 0,
        next_admin_multisig: admin, features_to_activate: [64],
    };
    assert.throws(() => serializeV6EpochConfig(config), /feature IDs/);
    assert.throws(() => serializeV6EpochConfig({ ...config, threshold: 1, features_to_activate: [] }), /threshold/);
});
