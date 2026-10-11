// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { AccountAddress, Serializer } from '@aptos-labs/ts-sdk';
import { bytesToHex } from '@noble/hashes/utils';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { AceDeployment, IBE_Aptos, Result, pke, tibe } from '../src';

const address = AccountAddress.fromString('0x1');
const deployment = new AceDeployment({
    apiEndpoint: 'https://fullnode.example/v1',
    contractAddr: address,
    discoveryUrl: 'https://discovery.example',
});

// A valid, empty DiscoveryViewV0: no committee or secret means the share
// fetcher returns Result.Err before sending any worker request.
function emptyDiscoveryView(): string {
    const s = new Serializer();
    s.serializeU64(0n); // epoch
    s.serializeU64(0n); // epoch start
    s.serializeU64(0n); // epoch duration
    s.serializeU32AsUleb128(0); // current nodes
    s.serializeU64(0n); // threshold
    s.serializeU32AsUleb128(0); // secrets
    s.serializeU32AsUleb128(0); // proposals
    s.serializeU8(0); // epoch change info
    s.serializeU32AsUleb128(0); // discovery nodes
    s.serializeU32AsUleb128(0); // discovery sessions
    return `0x${bytesToHex(s.toUint8Array())}`;
}

async function decryptArgs() {
    const {encryptionKey, decryptionKey} = await pke.keygen();
    return {
        ciphertext: new Uint8Array([1]),
        label: new Uint8Array(),
        encPk: encryptionKey.toBytes(),
        encSk: decryptionKey.toBytes(),
        payload: new Uint8Array(),
        aceDeployment: deployment,
        keypairId: address,
        chainId: 1,
        moduleAddr: address,
        moduleName: 'monitor',
    };
}

describe('Aptos custom-flow decrypt errors', () => {
    afterEach(() => {
        vi.restoreAllMocks();
        vi.unstubAllGlobals();
    });

    it('preserves a share-fetch Result.Err as the cause', async () => {
        vi.spyOn(tibe.Ciphertext, 'fromBytes').mockReturnValue(Result.Ok({
            value: new tibe.Ciphertext(tibe.SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD, null),
        }));
        vi.stubGlobal('fetch', vi.fn(async () => ({
            ok: true, status: 200, text: async () => emptyDiscoveryView(),
        })));

        try {
            await IBE_Aptos.decryptCustomFlow(await decryptArgs());
            expect.fail('expected the share fetch to fail');
        } catch (error) {
            expect(error).toBeInstanceOf(Error);
            expect((error as Error).message).toBe('AptosCustomFlow.decrypt failed (fetch identity key shares)');
            expect((error as Error).cause).toMatch(/not found in network state secrets/);
        }
    });

    it('preserves a discovery failure thrown before share collection', async () => {
        vi.spyOn(tibe.Ciphertext, 'fromBytes').mockReturnValue(Result.Ok({
            value: new tibe.Ciphertext(tibe.SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD, null),
        }));
        vi.stubGlobal('fetch', vi.fn(async () => ({ok: false, status: 503})));

        await expect(IBE_Aptos.decryptCustomFlow(await decryptArgs())).rejects.toMatchObject({
            message: 'AptosCustomFlow.decrypt failed (fetch identity key shares)',
            cause: expect.objectContaining({message: expect.stringContaining('HTTP 503')}),
        });
    });

    it('labels ciphertext parse failure and retains its parse error', async () => {
        await expect(IBE_Aptos.decryptCustomFlow(await decryptArgs())).rejects.toMatchObject({
            message: 'AptosCustomFlow.decrypt failed (parse ciphertext)',
            cause: expect.anything(),
        });
    });

    it('retains the primitive BF-IBE error through tibe and common without logging it', () => {
        const parseCiphertext = vi.spyOn(tibe.Ciphertext, 'fromBytes');
        const log = vi.spyOn(console, 'log').mockImplementation(() => {});
        const errorLog = vi.spyOn(console, 'error').mockImplementation(() => {});

        for (const scheme of [
            tibe.SCHEME_BFIBE_BLS12381_SHORTPK_OTP_HMAC,
            tibe.SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD,
        ]) {
            parseCiphertext.mockReturnValueOnce(Result.Ok({
                value: new tibe.Ciphertext(scheme, {c0: null}),
            }));
            const result = IBE_Aptos.decryptWithIdentityKeyShares({
                ciphertext: new Uint8Array([1]), identityKeyShares: [],
            });

            expect(result.isOk).toBe(false);
            expect(result.errValue).toBe('decrypt: no IDK shares provided');
            expect(result.extra?._sdk_execution_time_ms).toEqual(expect.any(Number));
        }
        expect(log).not.toHaveBeenCalled();
        expect(errorLog).not.toHaveBeenCalled();
    });
});
