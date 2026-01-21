// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest';
import * as IBE from '../src/ibe';
import { hexToBytes } from '@noble/hashes/utils';

describe('IBE (Identity-Based Encryption)', () => {
    describe('Compatibility Test', () => {
        it('should match Move compat test with pre-serialized data', () => {
            const plaintext = new TextEncoder().encode('The Boneh Franklin scheme is an identity-based encryption system proposed by Dan Boneh and Matthew K. Franklin in 2001.');
            const mskBytes = hexToBytes('00308f99be251a14ee0595d0d9fde39966c3845b297f6a27f8562e013bd5bd3d315f69ad7dcc0168ff0336a32b102fa2f33e20249c5fa717def559216c10864ae023c93973dd3ba7e481f4f47f333df6707321');
            const mpkBytes = hexToBytes('00308f99be251a14ee0595d0d9fde39966c3845b297f6a27f8562e013bd5bd3d315f69ad7dcc0168ff0336a32b102fa2f33e30adaddd577a893e79dabfd531482ac1087be10942f976a18317a87da57cd8c69b783a22adb08b7815865259d3badcc705');
            const randTape = hexToBytes('2e327dfc2bcec60148acba6a82bb1886ed1b4173b547951fc1a46780537aed09');
            const iskBytes = hexToBytes('0060a033ebf77057d8b073d64889f3ea258c6ffbcb519bbfdf3d1c777bd3c285a86c7253a3700e3b2350314ffab02f8799e203fcdcacaba90e9eb492eebc6ed2f1f6fe3289250226717369b1149094ecc5102c95a7300ea35dcd6290a45156fcf345');
            const ciphertextBytes = hexToBytes('0030a360d817116e1bd93cb12b15bb3f347e333dc309de963321e4b500c2777759cb722220c93c2a9b596482f0a7c7746ca27744e5719dee777accc0bafc69131425531fd03d1c04f4abafd673ec6b5ec49c57b2b3b02740fc055bf37b258725120dc90f3cdcb3c2233f0be29a1ccfe3f9261ceb4ef12582f69e9c0e26af70c1dec073e38c1781e3e31dd179020d7b051cac20e1aa3caae25bf49214204783a7ef36ea439bd0c19ec2b8207b6bb04f31a13fbd3f437f8ddccfcb55a1d40e6d6584c400f720b8eff5e85701');
            const identity = new TextEncoder().encode('alice@gmail.com');

            const msk = IBE.MasterPrivateKey.fromBytes(mskBytes).unwrapOrThrow('msk deserialization failed');
            const mpk = IBE.MasterPublicKey.fromBytes(mpkBytes).unwrapOrThrow('mpk deserialization failed');
            const isk = IBE.IdentityPrivateKey.fromBytes(iskBytes).unwrapOrThrow('isk deserialization failed');
            const ciphertext = IBE.Ciphertext.fromBytes(ciphertextBytes).unwrapOrThrow('ciphertext deserialization failed');

            expect(IBE.derivePublicKey(msk).unwrapOrThrow('derivePublicKey failed').toBytes()).toEqual(mpkBytes);
            expect(IBE.encryptWithRandomness(mpk, identity, plaintext, randTape).unwrapOrThrow('encryptWithRandomness failed').toBytes()).toEqual(ciphertextBytes);
            expect(IBE.extract(msk, identity).unwrapOrThrow('extract failed').toBytes()).toEqual(iskBytes);
            expect(IBE.decrypt(isk, ciphertext).unwrapOrThrow('decrypt failed')).toEqual(plaintext);
        });
    });

    describe('End-to-end Test', () => {
        it('should encrypt and decrypt correctly with fresh keys', () => {
            const plaintext = new TextEncoder().encode('Hello, IBE!');
            const identity = new TextEncoder().encode('bob@example.com');

            // Generate fresh keys
            const msk = IBE.keygen().unwrapOrThrow('keygen failed');
            const mpk = IBE.derivePublicKey(msk).unwrapOrThrow('derivePublicKey failed');

            // Encrypt
            const ciphertext = IBE.encrypt(mpk, identity, plaintext).unwrapOrThrow('encrypt failed');

            // Extract identity key and decrypt
            const isk = IBE.extract(msk, identity).unwrapOrThrow('extract failed');
            const decrypted = IBE.decrypt(isk, ciphertext).unwrapOrThrow('decrypt failed');

            expect(decrypted).toEqual(plaintext);
        });

        it('should fail decryption with wrong identity', () => {
            const plaintext = new TextEncoder().encode('Secret message');
            const identity1 = new TextEncoder().encode('alice@example.com');
            const identity2 = new TextEncoder().encode('eve@example.com');

            const msk = IBE.keygen().unwrapOrThrow('keygen failed');
            const mpk = IBE.derivePublicKey(msk).unwrapOrThrow('derivePublicKey failed');

            // Encrypt for identity1
            const ciphertext = IBE.encrypt(mpk, identity1, plaintext).unwrapOrThrow('encrypt failed');

            // Try to decrypt with identity2's key
            const wrongIsk = IBE.extract(msk, identity2).unwrapOrThrow('extract failed');
            const decryptResult = IBE.decrypt(wrongIsk, ciphertext);

            // Should fail (return Err due to MAC check)
            expect(decryptResult.isOk).toBe(false);
        });

        it('should work with decrypt Result type', () => {
            const plaintext = new TextEncoder().encode('Testing Result type');
            const identity = new TextEncoder().encode('test@example.com');

            const msk = IBE.keygen().unwrapOrThrow('keygen failed');
            const mpk = IBE.derivePublicKey(msk).unwrapOrThrow('derivePublicKey failed');
            const ciphertext = IBE.encrypt(mpk, identity, plaintext).unwrapOrThrow('encrypt failed');
            const isk = IBE.extract(msk, identity).unwrapOrThrow('extract failed');

            const result = IBE.decrypt(isk, ciphertext);
            expect(result.isOk).toBe(true);
            expect(result.unwrapOrThrow('decryption failed')).toEqual(plaintext);
        });

        it('should serialize and deserialize correctly', () => {
            const msk = IBE.keygen().unwrapOrThrow('keygen failed');
            const mpk = IBE.derivePublicKey(msk).unwrapOrThrow('derivePublicKey failed');
            const identity = new TextEncoder().encode('serialize@test.com');
            const isk = IBE.extract(msk, identity).unwrapOrThrow('extract failed');
            const plaintext = new TextEncoder().encode('Serialization test');
            const ciphertext = IBE.encrypt(mpk, identity, plaintext).unwrapOrThrow('encrypt failed');

            // Round-trip serialization
            const mskRestored = IBE.MasterPrivateKey.fromBytes(msk.toBytes()).unwrapOrThrow('msk deserialization failed');
            const mpkRestored = IBE.MasterPublicKey.fromBytes(mpk.toBytes()).unwrapOrThrow('mpk deserialization failed');
            const iskRestored = IBE.IdentityPrivateKey.fromBytes(isk.toBytes()).unwrapOrThrow('isk deserialization failed');
            const ciphertextRestored = IBE.Ciphertext.fromBytes(ciphertext.toBytes()).unwrapOrThrow('ciphertext deserialization failed');

            // Verify restored keys work
            expect(IBE.derivePublicKey(mskRestored).unwrapOrThrow('derivePublicKey failed').toBytes()).toEqual(mpk.toBytes());
            expect(IBE.decrypt(iskRestored, ciphertextRestored).unwrapOrThrow('decrypt failed')).toEqual(plaintext);
        });

        it('should work with hex serialization', () => {
            const msk = IBE.keygen().unwrapOrThrow('keygen failed');
            const mpk = IBE.derivePublicKey(msk).unwrapOrThrow('derivePublicKey failed');

            const mpkHex = mpk.toHex();
            const mpkRestored = IBE.MasterPublicKey.fromHex(mpkHex).unwrapOrThrow('hex deserialization failed');

            expect(mpkRestored.toBytes()).toEqual(mpk.toBytes());
        });

        it('should return Err for invalid deserialization', () => {
            const invalidBytes = new Uint8Array([0xff, 0x01, 0x02, 0x03]);
            
            const mpkResult = IBE.MasterPublicKey.fromBytes(invalidBytes);
            expect(mpkResult.isOk).toBe(false);

            const mskResult = IBE.MasterPrivateKey.fromBytes(invalidBytes);
            expect(mskResult.isOk).toBe(false);

            const iskResult = IBE.IdentityPrivateKey.fromBytes(invalidBytes);
            expect(iskResult.isOk).toBe(false);

            const ciphertextResult = IBE.Ciphertext.fromBytes(invalidBytes);
            expect(ciphertextResult.isOk).toBe(false);
        });
    });
});
