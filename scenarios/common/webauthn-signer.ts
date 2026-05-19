// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Test-only WebAuthn (passkeys) signer. Real wallet flows go through
 * `navigator.credentials.get()` and the hardware authenticator; in tests we
 * hold the P-256 private key directly and synthesize a syntactically valid
 * `WebAuthnAssertion` ourselves.
 *
 * The wire spec produced here matches the worker's verifier at
 * `worker-components/network-node/src/verify/aptos/any/secp256r1.rs`:
 *
 *   challenge   = SHA3-256( SHA3-256(b"ACE::DecryptionRequestPayload")
 *                          || BCS(DecryptionRequestPayload) )
 *   clientData  = JSON.stringify({ type:"webauthn.get",
 *                                  challenge: base64url(challenge),
 *                                  origin: "https://ace.test" })
 *   authData    = rpIdHash(32) || flags=0x01 || signCount=0u32(big-endian)
 *   ecdsaInput  = authData || SHA-256(clientData)
 *   signature   = P-256 ECDSA over ecdsaInput, low-s normalized, raw r||s (64B)
 *   fullMessage = hex(ecdsaInput)
 *
 * The auth-key for the resulting account is the standard SingleKey
 * derivation `SHA3-256( BCS(AnyPublicKey::Secp256r1Ecdsa(pk)) || 0x02 )` —
 * `AuthenticationKey.fromPublicKey({ publicKey: anyPk })` produces it.
 */

import {
    AccountAddress,
    AnyPublicKey,
    AnySignature,
    AuthenticationKey,
    Secp256r1PrivateKey,
    WebAuthnSignature,
} from '@aptos-labs/ts-sdk';
import { p256 } from '@noble/curves/p256';
import { sha256 } from '@noble/hashes/sha256';
import { sha3_256 } from '@noble/hashes/sha3';
import { bytesToHex } from '@noble/hashes/utils';

const PAYLOAD_DST = new TextEncoder().encode('ACE::DecryptionRequestPayload');
/** Stable rpIdHash for tests. The worker does not validate it — only the
 *  `challenge` field of `clientDataJSON` is checked — so its value is
 *  arbitrary, but keeping it constant makes traces reproducible. */
const RP_ID_HASH = sha256(new TextEncoder().encode('ace.test'));
const RP_ORIGIN = 'https://ace.test';

export interface ProofInputs {
    publicKey: AnyPublicKey;
    signature: AnySignature;
    fullMessage: string;
}

export class WebAuthnSigner {
    private readonly privateKey: Uint8Array;
    /** Cached AnyPublicKey wrapping a Secp256r1PublicKey. */
    public readonly publicKey: AnyPublicKey;
    /** SingleKey auth-key derived from `publicKey`. */
    public readonly accountAddress: AccountAddress;

    constructor(seed: Uint8Array) {
        if (seed.length !== 32) throw new Error('WebAuthnSigner seed must be 32 bytes');
        this.privateKey = seed;
        const sk = new Secp256r1PrivateKey(seed);
        this.publicKey = new AnyPublicKey(sk.publicKey());
        const authKey = AuthenticationKey.fromPublicKey({ publicKey: this.publicKey });
        this.accountAddress = AccountAddress.from(authKey.toUint8Array());
    }

    /** Build a WebAuthn assertion over `requestBcsBytes` (= BCS of the
     *  `DecryptionRequestPayload`) and return the (publicKey, signature,
     *  fullMessage) triple to feed straight into `session.decryptWithProof`. */
    signRequest(requestBcsBytes: Uint8Array): ProofInputs {
        const { authData, clientDataJSON, ecdsaPreimage } = this.buildAssertionBody(requestBcsBytes);
        const sig = p256.sign(ecdsaPreimage, this.privateKey, { prehash: true, lowS: true });
        return this.wrap(sig.toCompactRawBytes(), authData, clientDataJSON, ecdsaPreimage);
    }

    /** Step-E mauler — produce a valid-shape assertion but with the first
     *  byte of `r` flipped, so P-256 verify fails inside the worker before any
     *  on-chain check is hit. */
    signRequestWithMauledSignature(requestBcsBytes: Uint8Array): ProofInputs {
        const { authData, clientDataJSON, ecdsaPreimage } = this.buildAssertionBody(requestBcsBytes);
        const sig = p256.sign(ecdsaPreimage, this.privateKey, { prehash: true, lowS: true });
        const mauledRs = sig.toCompactRawBytes();
        mauledRs[0] ^= 0x01;
        return this.wrap(mauledRs, authData, clientDataJSON, ecdsaPreimage);
    }

    private buildAssertionBody(requestBcsBytes: Uint8Array): {
        authData: Uint8Array;
        clientDataJSON: Uint8Array;
        ecdsaPreimage: Uint8Array;
    } {
        // 1. challenge = SHA3-256(seed || BCS(payload)).
        const seed = sha3_256(PAYLOAD_DST);
        const preimage = concat(seed, requestBcsBytes);
        const challenge = sha3_256(preimage);

        // 2. clientDataJSON — WebAuthn requires `challenge` base64url-encoded.
        const clientDataJSON = new TextEncoder().encode(JSON.stringify({
            type: 'webauthn.get',
            challenge: base64UrlEncode(challenge),
            origin: RP_ORIGIN,
        }));

        // 3. authData = rpIdHash(32) || flags=0x01 || signCount=0u32(BE).
        const authData = new Uint8Array(32 + 1 + 4);
        authData.set(RP_ID_HASH, 0);
        authData[32] = 0x01;

        // 4. ECDSA preimage.
        const ecdsaPreimage = concat(authData, sha256(clientDataJSON));
        return { authData, clientDataJSON, ecdsaPreimage };
    }

    private wrap(
        rs: Uint8Array,
        authData: Uint8Array,
        clientDataJSON: Uint8Array,
        ecdsaPreimage: Uint8Array,
    ): ProofInputs {
        const webAuthnSig = new WebAuthnSignature(rs, authData, clientDataJSON);
        return {
            publicKey: this.publicKey,
            signature: new AnySignature(webAuthnSig),
            fullMessage: bytesToHex(ecdsaPreimage),
        };
    }
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
    const out = new Uint8Array(a.length + b.length);
    out.set(a, 0);
    out.set(b, a.length);
    return out;
}

function base64UrlEncode(bytes: Uint8Array): string {
    // Buffer.toString('base64') in Node produces standard base64 with `+`/`/`
    // and `=` padding; convert to URL-safe no-pad per the WebAuthn spec.
    return Buffer.from(bytes).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}
