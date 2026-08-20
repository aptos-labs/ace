// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { Network } from '@aptos-labs/ts-sdk';
import { GasStationTransactionSubmitter } from '@aptos-labs/gas-station-client';
import { gasStationOptions, gasStationTransactionSubmitter } from './gas-station.js';

describe('gasStationOptions', () => {
    it('selects the shelbynet gas-station baseUrl', () => {
        assert.deepEqual(
            gasStationOptions('https://api.shelbynet.shelby.xyz/v1', Network.CUSTOM, 'k'),
            { network: Network.CUSTOM, apiKey: 'k', baseUrl: 'https://api.shelbynet.shelby.xyz/gs/v1' },
        );
        assert.deepEqual(
            gasStationOptions('https://api.shelbynet.aptoslabs.com/v1', Network.CUSTOM, 'k'),
            { network: Network.CUSTOM, apiKey: 'k', baseUrl: 'https://api.shelbynet.aptoslabs.com/gs/v1' },
        );
    });

    it('omits baseUrl for other hosts', () => {
        assert.deepEqual(
            gasStationOptions('https://api.testnet.aptoslabs.com/v1', Network.TESTNET, 'k'),
            { network: Network.TESTNET, apiKey: 'k' },
        );
    });
});

describe('gasStationTransactionSubmitter', () => {
    it('exposes submitTransaction without returning the v5 class instance', () => {
        const submitter = gasStationTransactionSubmitter(
            'https://api.testnet.aptoslabs.com/v1',
            Network.TESTNET,
            'test-key',
        );
        assert.equal(typeof submitter.submitTransaction, 'function');
        assert.equal(submitter instanceof GasStationTransactionSubmitter, false);
    });
});
