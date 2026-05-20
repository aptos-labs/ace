// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Test-only WebAuthn (passkeys) helpers. Real wallet flows go through
 * `navigator.credentials.get()` and the hardware authenticator; in tests
 * we hold the P-256 private key directly and synthesise the same three
 * byte buffers (`authenticatorData`, `clientDataJSON`, `signature`) a
 * browser would hand back, with the signature DER-encoded so the SDK's
 * `decryptWithWebAuthnAssertion` exercises its DER→raw decoding path
 * end-to-end.
 *
 * The account's auth-key is the standard SingleKey derivation
 * `SHA3-256( BCS(AnyPublicKey::Secp256r1Ecdsa(pk)) || 0x02 )` — computed
 * via `AuthenticationKey.fromPublicKey({ publicKey: new AnyPublicKey(pk) })`.
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

/** Mirror of what `navigator.credentials.create()` would register on a real
 *  device: the P-256 private key (kept in the authenticator hardware) plus
 *  the public key + auth-key the relying party stores against the user. */
export interface WebAuthnAccount {
    privateKey: Uint8Array;
    publicKey: Secp256r1PublicKey;
    accountAddress: AccountAddress;
}

export function newWebAuthnAccount(seed: Uint8Array): WebAuthnAccount {
    if (seed.length !== 32) throw new Error('WebAuthn seed must be 32 bytes');
    const publicKey = new Secp256r1PrivateKey(seed).publicKey();
    const authKey = AuthenticationKey.fromPublicKey({ publicKey: new AnyPublicKey(publicKey) });
    return {
        privateKey: seed,
        publicKey,
        accountAddress: AccountAddress.from(authKey.toUint8Array()),
    };
}

/** Synthesise an assertion over the given 32-byte challenge — i.e. the
 *  value the SDK's `getRequestToSignForWebAuthn()` returned. Mirrors what
 *  `navigator.credentials.get(...)` would hand back. */
export function buildAssertion(challenge: Uint8Array, privateKey: Uint8Array): WebAuthnAssertion {
    const clientDataJSON = new TextEncoder().encode(JSON.stringify({
        type: 'webauthn.get',
        challenge: base64UrlEncode(challenge),
        origin: RP_ORIGIN,
    }));
    // authData = rpIdHash(32) || flags=0x01(UP) || signCount=0u32(BE).
    const authenticatorData = new Uint8Array(32 + 1 + 4);
    authenticatorData.set(RP_ID_HASH, 0);
    authenticatorData[32] = 0x01;
    // P-256 ECDSA signs over `authenticatorData || SHA-256(clientDataJSON)`
    // with SHA-256 prehash applied internally (noble curves `prehash:true`).
    const preimage = new Uint8Array(authenticatorData.length + 32);
    preimage.set(authenticatorData, 0);
    preimage.set(sha256(clientDataJSON), authenticatorData.length);
    return {
        authenticatorData,
        clientDataJSON,
        signature: p256.sign(preimage, privateKey, { prehash: true, lowS: true }).toDERRawBytes(),
    };
}

function base64UrlEncode(bytes: Uint8Array): string {
    // Buffer.toString('base64') in Node produces standard base64 with `+`/`/`
    // and `=` padding; convert to URL-safe no-pad per the WebAuthn spec.
    return Buffer.from(bytes).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}
