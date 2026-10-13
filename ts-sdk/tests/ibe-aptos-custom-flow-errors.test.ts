// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { AccountAddress } from '@aptos-labs/ts-sdk';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { AceDeployment, IBE_Aptos, Result, pke, tibe } from '../src';

describe('Aptos custom-flow decrypt errors', () => {
    afterEach(() => {
        vi.restoreAllMocks();
        vi.unstubAllGlobals();
    });

    it('preserves a discovery error thrown before the share fetch returns a Result', async () => {
        vi.spyOn(tibe.Ciphertext, 'fromBytes').mockReturnValue(Result.Ok({
            value: new tibe.Ciphertext(tibe.SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD, null),
        }));
        vi.stubGlobal('fetch', vi.fn(async () => ({ok: false, status: 503})));

        const address = AccountAddress.fromString('0x1');
        const {encryptionKey, decryptionKey} = await pke.keygen();
        const aceDeployment = new AceDeployment({
            apiEndpoint: 'https://fullnode.example/v1',
            contractAddr: address,
            discoveryUrl: 'https://discovery.example',
        });

        await expect(IBE_Aptos.decryptCustomFlow({
            ciphertext: new Uint8Array([1]),
            label: new Uint8Array(),
            encPk: encryptionKey.toBytes(),
            encSk: decryptionKey.toBytes(),
            payload: new Uint8Array(),
            aceDeployment,
            keypairId: address,
            chainId: 1,
            moduleAddr: address,
            moduleName: 'monitor',
        })).rejects.toMatchObject({
            message: 'AptosCustomFlow.decrypt failed (fetch identity key shares)',
            cause: expect.objectContaining({message: expect.stringContaining('HTTP 503')}),
        });
    });
});
