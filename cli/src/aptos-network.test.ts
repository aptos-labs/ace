// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { Network } from '@aptos-labs/ts-sdk';
import { inferNetwork } from './aptos-network.js';

describe('inferNetwork', () => {
    it('maps public AptosLabs hosts', () => {
        assert.equal(inferNetwork('https://api.mainnet.aptoslabs.com/v1'), Network.MAINNET);
        assert.equal(inferNetwork('https://api.testnet.aptoslabs.com/v1'), Network.TESTNET);
        assert.equal(inferNetwork('https://api.devnet.aptoslabs.com/v1'), Network.DEVNET);
    });

    it('maps local RPC', () => {
        assert.equal(inferNetwork('http://localhost:8080/v1'), Network.LOCAL);
        assert.equal(inferNetwork('http://127.0.0.1:8080/v1'), Network.LOCAL);
    });

    it('maps shelbynet and netna', () => {
        assert.equal(inferNetwork('https://api.shelbynet.shelby.xyz/v1'), Network.SHELBYNET);
        assert.equal(inferNetwork('https://api.shelbynet.aptoslabs.com/v1'), Network.SHELBYNET);
        assert.equal(inferNetwork('https://api.netna.staging.aptoslabs.com/v1'), Network.NETNA);
    });

    it('keeps ACE shelby-private-beta as CUSTOM', () => {
        assert.equal(
            inferNetwork('https://fullnode.shelby-private-beta.example.com/v1'),
            Network.CUSTOM,
        );
    });

    it('maps unknown hosts to CUSTOM', () => {
        assert.equal(inferNetwork('https://my-node.example.com/v1'), Network.CUSTOM);
    });
});
