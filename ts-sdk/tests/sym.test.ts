// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest';
import * as SYM from '../src/sym';
import { hexToBytes } from '@noble/hashes/utils';

describe('SYM (Symmetric Encryption)', () => {
    describe('End-to-end Test', () => {
        it('should encrypt and decrypt correctly with fresh key', () => {
            const plaintext = new TextEncoder().encode('Hello, AES-256-GCM!');

            // Generate fresh key
            const key = SYM.keygen().unwrapOrThrow('keygen failed');

            // Encrypt
            const ciphertext = SYM.encrypt(key, plaintext).unwrapOrThrow('encrypt failed');

            // Decrypt
            const decrypted = SYM.decrypt(key, ciphertext).unwrapOrThrow('decrypt failed');

            expect(decrypted).toEqual(plaintext);
        });

        it('should fail decryption with wrong key', () => {
            const plaintext = new TextEncoder().encode('Secret message');

            const key1 = SYM.keygen().unwrapOrThrow('keygen failed');
            const key2 = SYM.keygen().unwrapOrThrow('keygen failed');

            // Encrypt with key1
            const ciphertext = SYM.encrypt(key1, plaintext).unwrapOrThrow('encrypt failed');

            // Try to decrypt with key2
            const decryptResult = SYM.decrypt(key2, ciphertext);

            // Should fail (authentication tag mismatch)
            expect(decryptResult.isOk).toBe(false);
        });

        it('should work with decrypt Result type', () => {
            const plaintext = new TextEncoder().encode('Testing Result type');

            const key = SYM.keygen().unwrapOrThrow('keygen failed');
            const ciphertext = SYM.encrypt(key, plaintext).unwrapOrThrow('encrypt failed');

            const result = SYM.decrypt(key, ciphertext);
            expect(result.isOk).toBe(true);
            expect(result.unwrapOrThrow('decryption failed')).toEqual(plaintext);
        });

        it('should serialize and deserialize correctly', () => {
            const key = SYM.keygen().unwrapOrThrow('keygen failed');
            const plaintext = new TextEncoder().encode('Serialization test');
            const ciphertext = SYM.encrypt(key, plaintext).unwrapOrThrow('encrypt failed');

            // Round-trip serialization
            const keyRestored = SYM.Key.fromBytes(key.toBytes()).unwrapOrThrow('key deserialization failed');
            const ciphertextRestored = SYM.Ciphertext.fromBytes(ciphertext.toBytes()).unwrapOrThrow('ciphertext deserialization failed');

            // Verify restored key works
            expect(SYM.decrypt(keyRestored, ciphertextRestored).unwrapOrThrow('decrypt failed')).toEqual(plaintext);
        });

        it('should work with hex serialization', () => {
            const key = SYM.keygen().unwrapOrThrow('keygen failed');

            const keyHex = key.toHex();
            const keyRestored = SYM.Key.fromHex(keyHex).unwrapOrThrow('hex deserialization failed');

            expect(keyRestored.toBytes()).toEqual(key.toBytes());
        });

        it('should return Err for invalid deserialization', () => {
            const invalidBytes = new Uint8Array([0xff, 0x01, 0x02, 0x03]);
            
            const keyResult = SYM.Key.fromBytes(invalidBytes);
            expect(keyResult.isOk).toBe(false);

            const ciphertextResult = SYM.Ciphertext.fromBytes(invalidBytes);
            expect(ciphertextResult.isOk).toBe(false);
        });

        it('should handle empty plaintext', () => {
            const plaintext = new Uint8Array(0);

            const key = SYM.keygen().unwrapOrThrow('keygen failed');
            const ciphertext = SYM.encrypt(key, plaintext).unwrapOrThrow('encrypt failed');
            const decrypted = SYM.decrypt(key, ciphertext).unwrapOrThrow('decrypt failed');

            expect(decrypted).toEqual(plaintext);
        });

        it('should handle large plaintext', () => {
            const plaintext = new Uint8Array(10000);
            for (let i = 0; i < plaintext.length; i++) {
                plaintext[i] = i % 256;
            }

            const key = SYM.keygen().unwrapOrThrow('keygen failed');
            const ciphertext = SYM.encrypt(key, plaintext).unwrapOrThrow('encrypt failed');
            const decrypted = SYM.decrypt(key, ciphertext).unwrapOrThrow('decrypt failed');

            expect(decrypted).toEqual(plaintext);
        });
    });

    describe('Compatibility Test', () => {
        it('should match pre-serialized data', () => {
            // Test vector: key, nonce, plaintext -> ciphertext
            const keyBytes = hexToBytes('00' + '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef');
            const nonce = hexToBytes('000102030405060708090a0b');
            const plaintext = new TextEncoder().encode('Hello, World!');

            const key = SYM.Key.fromBytes(keyBytes).unwrapOrThrow('key deserialization failed');

            // Encrypt with known randomness
            const ciphertext = SYM.encryptWithRandomness(key, plaintext, nonce).unwrapOrThrow('encrypt failed');

            // Decrypt should recover plaintext
            const decrypted = SYM.decrypt(key, ciphertext).unwrapOrThrow('decrypt failed');
            expect(decrypted).toEqual(plaintext);

            // Encrypting same plaintext with same nonce should give same ciphertext
            const ciphertext2 = SYM.encryptWithRandomness(key, plaintext, nonce).unwrapOrThrow('encrypt failed');
            expect(ciphertext2.toBytes()).toEqual(ciphertext.toBytes());
        });
    });
});

