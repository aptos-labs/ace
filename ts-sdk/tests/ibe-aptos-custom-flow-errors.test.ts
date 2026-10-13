// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { AccountAddress } from '@aptos-labs/ts-sdk';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { AceDeployment, IBE_Aptos, Result, pke, tibe } from '../src';

const address = AccountAddress.fromString('0x1');
const aceDeployment = new AceDeployment({
    apiEndpoint: 'https://fullnode.example/v1',
    contractAddr: address,
    discoveryUrl: 'https://discovery.example',
});

async function decryptArgs() {
    const {encryptionKey, decryptionKey} = await pke.keygen();
    return {
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
    };
}

describe('Aptos IBE diagnostic errors', () => {
    afterEach(() => {
        vi.restoreAllMocks();
        vi.unstubAllGlobals();
    });

    it('keeps the existing custom-flow rejection value by default', async () => {
        vi.spyOn(tibe.Ciphertext, 'fromBytes').mockReturnValue(Result.Err({error: 'invalid ciphertext'}));
        await expect(IBE_Aptos.decryptCustomFlow(await decryptArgs()))
            .rejects.toBe('AptosCustomFlow.decrypt failed');
    });

    it('adds stage context to a discovery error only when requested', async () => {
        vi.spyOn(tibe.Ciphertext, 'fromBytes').mockReturnValue(Result.Ok({
            value: new tibe.Ciphertext(tibe.SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD, null),
        }));
        vi.stubGlobal('fetch', vi.fn(async () => ({ok: false, status: 503})));
        const args = await decryptArgs();

        await expect(IBE_Aptos.decryptCustomFlow(args)).rejects.toMatchObject({
            message: expect.stringContaining('HTTP 503'),
        });
        await expect(IBE_Aptos.decryptCustomFlow({...args, detailedErrors: true})).rejects.toMatchObject({
            message: 'AptosCustomFlow.decrypt failed (fetch identity key shares)',
            cause: expect.objectContaining({message: expect.stringContaining('HTTP 503')}),
        });
    });

    it('keeps encrypt errValue by default and retains the discovery cause when requested', async () => {
        vi.stubGlobal('fetch', vi.fn(async () => ({ok: false, status: 503})));
        const args = {
            aceDeployment, keypairId: address, chainId: 1,
            moduleAddr: address, moduleName: 'monitor',
            label: new Uint8Array(), plaintext: new Uint8Array([1]),
        };

        const legacy = await IBE_Aptos.encrypt(args);
        expect(legacy.errValue).toBe('AptosEncrypt: fetchPk failed');

        const detailed = await IBE_Aptos.encrypt({...args, detailedErrors: true});
        expect(detailed.errValue).toMatchObject({
            message: 'AptosEncrypt: fetchPk failed',
            cause: expect.objectContaining({message: expect.stringContaining('HTTP 503')}),
        });
    });

    it('retains the local decrypt cause only when requested', () => {
        vi.spyOn(tibe.Ciphertext, 'fromBytes').mockReturnValue(Result.Ok({
            value: new tibe.Ciphertext(tibe.SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD, {c0: null}),
        }));
        const args = {ciphertext: new Uint8Array([1]), identityKeyShares: []};

        const legacy = IBE_Aptos.decryptWithIdentityKeyShares(args);
        expect(legacy.errValue).toBe('ACE.decryptWithIdentityKeyShares: tibe.decrypt failed');

        const detailed = IBE_Aptos.decryptWithIdentityKeyShares({...args, detailedErrors: true});
        expect(detailed.errValue).toMatchObject({
            message: 'ACE.decryptWithIdentityKeyShares: tibe.decrypt failed',
            cause: {
                message: 'decrypt failed',
                cause: 'decrypt: no IDK shares provided',
            },
        });
    });
});
