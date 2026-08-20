// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { Network } from '@aptos-labs/ts-sdk';
import { GasStationTransactionSubmitter } from '@aptos-labs/gas-station-client';
import { gasStationTransactionSubmitter } from './gas-station.js';

describe('gasStationTransactionSubmitter', () => {
    it('exposes submitTransaction without returning the v5 class instance', () => {
        const submitter = gasStationTransactionSubmitter({
            network: Network.TESTNET,
            apiKey: 'test-key',
        });
        assert.equal(typeof submitter.submitTransaction, 'function');
        assert.equal(submitter instanceof GasStationTransactionSubmitter, false);
    });
});
