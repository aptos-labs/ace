// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Test-only WebAuthn (passkeys) signer. Real wallet flows go through
 * `navigator.credentials.get()` and the hardware authenticator; in tests we
 * hold the P-256 private key directly and synthesize the same three byte
 * buffers (`authenticatorData`, `clientDataJSON`, `signature`) a browser
 * would hand back.
 *
 * Pairs with [`DecryptionSession.getRequestToSignForWebAuthn`] /
 * [`DecryptionSession.decryptWithWebAuthnAssertion`] — the SDK builds the
 * 32-byte challenge for us; this signer just wraps it into a
 * `clientDataJSON` and signs over `authenticatorData || SHA-256(clientDataJSON)`
 * with P-256, returning a **DER-encoded** signature (the wire shape browsers
 * emit) so the SDK's DER→raw decoding path is exercised end-to-end.
 *
 * The auth-key for the resulting account is the standard SingleKey
 * derivation `SHA3-256( BCS(AnyPublicKey::Secp256r1Ecdsa(pk)) || 0x02 )` —
 * `AuthenticationKey.fromPublicKey({ publicKey: new AnyPublicKey(pk) })`
 * produces it.
 */

import {
    AccountAddress,
    AnyPublicKey,
    AuthenticationKey,
    Secp256r1PrivateKey,
    Secp256r1PublicKey,
} from '@aptos-labs/ts-sdk';
import { p256 } from '@noble/curves/p256';
import { sha256 } from '@noble/hashes/sha256';

/** Stable rpIdHash for tests. The worker does not validate it — only the
 *  `challenge` field of `clientDataJSON` is checked — so its value is
 *  arbitrary, but keeping it constant makes traces reproducible. */
const RP_ID_HASH = sha256(new TextEncoder().encode('ace.test'));
const RP_ORIGIN = 'https://ace.test';

/** Mirror of what a browser hands back from `navigator.credentials.get()`. */
export interface WebAuthnAssertion {
    authenticatorData: Uint8Array;
    clientDataJSON: Uint8Array;
    /** DER-encoded P-256 ECDSA signature, as emitted by browsers. The SDK
     *  decodes it to raw `r || s` (low-s normalised) on submit. */
    signature: Uint8Array;
}

export class WebAuthnSigner {
    private readonly privateKey: Uint8Array;
    public readonly publicKey: Secp256r1PublicKey;
    /** SingleKey auth-key derived from `AnyPublicKey(publicKey)`. */
    public readonly accountAddress: AccountAddress;

    constructor(seed: Uint8Array) {
        if (seed.length !== 32) throw new Error('WebAuthnSigner seed must be 32 bytes');
        this.privateKey = seed;
        this.publicKey = new Secp256r1PrivateKey(seed).publicKey();
        const authKey = AuthenticationKey.fromPublicKey({ publicKey: new AnyPublicKey(this.publicKey) });
        this.accountAddress = AccountAddress.from(authKey.toUint8Array());
    }

    /** Synthesize an assertion over the given 32-byte challenge — i.e. the
     *  value the SDK's `getRequestToSignForWebAuthn()` returned. */
    buildAssertion(challenge: Uint8Array): WebAuthnAssertion {
        const { authData, clientDataJSON, ecdsaPreimage } = this.envelope(challenge);
        const sig = p256.sign(ecdsaPreimage, this.privateKey, { prehash: true, lowS: true });
        return {
            authenticatorData: authData,
            clientDataJSON,
            signature: sig.toDERRawBytes(),
        };
    }

    /** Step-E mauler — produce a valid-shape assertion but with the last byte
     *  of the DER signature twiddled. The last byte is the least-significant
     *  byte of `s`; flipping it always lands inside `1..curve_order` (so DER
     *  parsing + low-s normalisation succeed) but cryptographically breaks
     *  the signature so the worker's P-256 verify fails. Flipping the first
     *  byte of `r` instead would occasionally produce an out-of-range integer
     *  that fails DER validation client-side. */
    buildAssertionWithMauledSignature(challenge: Uint8Array): WebAuthnAssertion {
        const a = this.buildAssertion(challenge);
        const mauled = new Uint8Array(a.signature);
        mauled[mauled.length - 1] ^= 0x01;
        return { ...a, signature: mauled };
    }

    private envelope(challenge: Uint8Array): {
        authData: Uint8Array;
        clientDataJSON: Uint8Array;
        ecdsaPreimage: Uint8Array;
    } {
        const clientDataJSON = new TextEncoder().encode(JSON.stringify({
            type: 'webauthn.get',
            challenge: base64UrlEncode(challenge),
            origin: RP_ORIGIN,
        }));
        // authData = rpIdHash(32) || flags=0x01(UP) || signCount=0u32(BE).
        const authData = new Uint8Array(32 + 1 + 4);
        authData.set(RP_ID_HASH, 0);
        authData[32] = 0x01;
        const cdjHash = sha256(clientDataJSON);
        const ecdsaPreimage = new Uint8Array(authData.length + cdjHash.length);
        ecdsaPreimage.set(authData, 0);
        ecdsaPreimage.set(cdjHash, authData.length);
        return { authData, clientDataJSON, ecdsaPreimage };
    }
}

function base64UrlEncode(bytes: Uint8Array): string {
    // Buffer.toString('base64') in Node produces standard base64 with `+`/`/`
    // and `=` padding; convert to URL-safe no-pad per the WebAuthn spec.
    return Buffer.from(bytes).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}
