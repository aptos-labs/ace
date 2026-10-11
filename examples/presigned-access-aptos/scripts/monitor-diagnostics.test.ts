// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import assert from 'node:assert/strict';
import test from 'node:test';
import { classifyReason, failureDetail, failureMessage } from './monitor-diagnostics.js';

test('discovery HTTP errors retain status without logging URL or credentials', () => {
    const error = new Error('AptosCustomFlow.decrypt failed (fetch identity key shares)', {
        cause: new Error('ACE discovery: GET https://user:private@host/bcs -> HTTP 503'),
    });
    assert.equal(classifyReason(error, []), 'chain-read-error');
    assert.equal(failureDetail(error), 'discovery-http-503');
    assert.doesNotMatch(JSON.stringify({reason: classifyReason(error, []), detail: failureDetail(error)}), /private|host/);
});

test('snapshot mismatch is a chain read failure, even with a generic decrypt wrapper', () => {
    const error = new Error('AptosCustomFlow.decrypt failed (fetch identity key shares)', {
        cause: new Error('ACE discovery: session 0xabc not in snapshot'),
    });
    assert.equal(classifyReason(error, []), 'chain-read-error');
    assert.equal(failureDetail(error), 'discovery-session-not-in-snapshot');
});

test('share shortfall preserves threshold counts', () => {
    const error = new Error('AptosCustomFlow.decrypt failed (fetch identity key shares)', {
        cause: 'ACE.fetchIdentityKeySharesCoreCustom: need 3 identity key shares, got 1',
    });
    assert.equal(classifyReason(error, []), 'threshold-not-met');
    assert.equal(failureDetail(error), 'identity-shares-1-of-3');
});

test('local decrypt, transport errors and unknown wrapper are distinct', () => {
    assert.equal(classifyReason(new Error('AptosCustomFlow.decrypt failed (local decrypt)'), []), 'decrypt-failed');
    assert.equal(classifyReason(new Error('AptosCustomFlow.decrypt failed (fetch identity key shares)', {
        cause: new TypeError('terminated'),
    }), []), 'chain-read-error');
    assert.equal(classifyReason(new Error('AptosCustomFlow.decrypt failed'), []), 'unknown');
});

test('local primitive failure is classified without serializing its raw cause', () => {
    const error = new Error('AptosCustomFlow.decrypt failed (local decrypt)', {
        cause: new Error('TEST_ONLY_PRIVATE_KEY=do-not-log'),
    });
    const logLine = JSON.stringify({
        message: failureMessage(error),
        reason: classifyReason(error, []),
        detail: failureDetail(error),
    });
    assert.equal(classifyReason(error, []), 'decrypt-failed');
    assert.doesNotMatch(logLine, /TEST_ONLY_PRIVATE_KEY|do-not-log/);
});

test('worker HTTP and transport failures still use per-worker log lines', () => {
    const error = new Error('AptosCustomFlow.decrypt failed (fetch identity key shares)');
    assert.equal(classifyReason(error, ['[decrypt-custom] worker x: HTTP 403']), 'permission-denied');
    assert.equal(classifyReason(error, ['[decrypt-custom] worker x: HTTP 502']), 'worker-5xx');
    assert.equal(classifyReason(error, ['[decrypt-custom] worker x: fetch error — connect ECONNRESET']), 'worker-transport-error');
});
