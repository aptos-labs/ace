// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import {
    AccountAddress,
    AnyPublicKey,
    AnySignature,
    PublicKey,
    Secp256r1PublicKey,
    Signature,
    WebAuthnSignature,
} from "@aptos-labs/ts-sdk";
import { p256 } from "@noble/curves/p256";
import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex } from "@noble/hashes/utils";
import { Result } from "../../result";
import * as pke from "../../pke";
import { State as NetworkState } from "../../network";
import {
    AceDeployment,
    ContractID,
    FullDecryptionDomain,
    ProofOfPermission,
    DecryptionRequestPayload,
    fetchNetworkStateAndBuildRequest,
    decryptCore,
    buildPerNodeRequestCore,
} from "../../_internal/common";

export class DecryptionSession {
    aceDeployment: AceDeployment;
    fullDecryptionDomain: FullDecryptionDomain;
    ciphertext: Uint8Array;
    ephemeralDecryptionKey: pke.DecryptionKey;
    ephemeralEncryptionKey: pke.EncryptionKey;
    request: DecryptionRequestPayload | undefined;
    networkState: NetworkState | undefined;

    private constructor({
        aceDeployment, keypairId, chainId, moduleAddr, moduleName, functionName, domain, ciphertext,
        ephemeralEncryptionKey, ephemeralDecryptionKey,
    }: {
        aceDeployment: AceDeployment,
        keypairId: AccountAddress,
        chainId: number,
        moduleAddr: AccountAddress,
        moduleName: string,
        functionName?: string,
        domain: Uint8Array,
        ciphertext: Uint8Array,
        ephemeralEncryptionKey: pke.EncryptionKey,
        ephemeralDecryptionKey: pke.DecryptionKey,
    }) {
        this.aceDeployment = aceDeployment;
        if (functionName === undefined) functionName = 'check_permission';
        const contractId = ContractID.newAptos({chainId, moduleAddr, moduleName, functionName});
        this.fullDecryptionDomain = new FullDecryptionDomain({keypairId, contractId, domain});
        this.ciphertext = ciphertext;
        this.ephemeralEncryptionKey = ephemeralEncryptionKey;
        this.ephemeralDecryptionKey = ephemeralDecryptionKey;
    }

    static async create(params: {
        aceDeployment: AceDeployment,
        keypairId: AccountAddress,
        chainId: number,
        moduleAddr: AccountAddress,
        moduleName: string,
        functionName?: string,
        domain: Uint8Array,
        ciphertext: Uint8Array,
    }): Promise<DecryptionSession> {
        const {encryptionKey, decryptionKey} = await pke.keygen();
        return new DecryptionSession({
            ...params,
            ephemeralEncryptionKey: encryptionKey,
            ephemeralDecryptionKey: decryptionKey,
        });
    }

    /**
     * Returns the UTF-8 pretty-printed `DecryptionRequestPayload` string that
     * the signer is expected to sign over. Use this for account types whose
     * signature scheme digests the message string directly:
     *
     *   - bare Ed25519              (`pk_scheme=0`)
     *   - bare Keyless              (`pk_scheme=4`)
     *   - bare FederatedKeyless     (`pk_scheme=5`)
     *   - `AnyPublicKey` wrapping any of `Ed25519`, `Secp256k1Ecdsa`,
     *     `Keyless`, or `FederatedKeyless` (`pk_scheme=1` inner 0/1/3/4)
     *
     * For passkeys (`AnyPublicKey<Secp256r1Ecdsa>+AnySignature<WebAuthn>`),
     * use [`getRequestToSignForWebAuthn`] instead — that path signs a
     * WebAuthn-shaped challenge derived from the BCS body, not the pretty
     * string.
     */
    async getRequestToSign(): Promise<string> {
        const {networkState, request} = await fetchNetworkStateAndBuildRequest(
            this.aceDeployment, this.fullDecryptionDomain, this.ephemeralEncryptionKey);
        this.networkState = networkState;
        this.request = request;
        return request.toPrettyMessage();
    }

    /**
     * Returns the 32-byte WebAuthn challenge bytes for this session — the
     * relying-party-supplied value the wallet base64url-encodes into
     * `clientDataJSON.challenge` before calling
     * `navigator.credentials.get(...)`.
     *
     * Pair with [`decryptWithWebAuthnAssertion`] to submit the resulting
     * assertion. Only used by the `AnyPublicKey<Secp256r1Ecdsa>+AnySignature<WebAuthn>`
     * (passkeys) account type.
     */
    async getRequestToSignForWebAuthn(): Promise<Uint8Array> {
        const {networkState, request} = await fetchNetworkStateAndBuildRequest(
            this.aceDeployment, this.fullDecryptionDomain, this.ephemeralEncryptionKey);
        this.networkState = networkState;
        this.request = request;
        return request.toWebAuthnChallenge();
    }

    async decryptWithProof({userAddr, publicKey, signature, fullMessage}: {
        userAddr: AccountAddress,
        publicKey: PublicKey,
        signature: Signature,
        fullMessage?: string,
    }): Promise<Result<Uint8Array>> {
        if (fullMessage === undefined) fullMessage = this.request!.toPrettyMessage();
        const proof = ProofOfPermission.createAptos({userAddr, publicKey, signature, fullMessage});
        return decryptCore({
            aceDeployment: this.aceDeployment,
            networkState: this.networkState!,
            request: this.request!,
            proof,
            ephemeralDecryptionKey: this.ephemeralDecryptionKey,
            ciphertext: this.ciphertext,
        });
    }

    /**
     * One-shot submit for a WebAuthn (passkeys) assertion. Takes the three
     * byte buffers a browser returns from `navigator.credentials.get(...)`
     * verbatim — the SDK does the DER→raw r||s conversion, low-s
     * normalisation, `AnyPublicKey`/`AnySignature` wrapping, and
     * `fullMessage = hex(authenticatorData || SHA-256(clientDataJSON))`
     * construction internally.
     *
     * The wallet's WebAuthn integration shrinks to:
     *
     * ```ts
     * const challenge = await session.getRequestToSignForWebAuthn();
     * const cred = await navigator.credentials.get({ publicKey: { challenge, ... } });
     * const result = await session.decryptWithWebAuthnAssertion({
     *     userAddr,
     *     publicKey: walletSecp256r1Pk,
     *     authenticatorData: new Uint8Array(cred.response.authenticatorData),
     *     clientDataJSON:    new Uint8Array(cred.response.clientDataJSON),
     *     signature:         new Uint8Array(cred.response.signature), // DER
     * });
     * ```
     */
    async decryptWithWebAuthnAssertion({
        userAddr, publicKey, authenticatorData, clientDataJSON, signature,
    }: {
        userAddr: AccountAddress,
        publicKey: Secp256r1PublicKey,
        authenticatorData: Uint8Array,
        clientDataJSON: Uint8Array,
        signature: Uint8Array,
    }): Promise<Result<Uint8Array>> {
        const proof = this.buildWebAuthnProof({
            userAddr, publicKey, authenticatorData, clientDataJSON, signature,
        });
        return decryptCore({
            aceDeployment: this.aceDeployment,
            networkState: this.networkState!,
            request: this.request!,
            proof,
            ephemeralDecryptionKey: this.ephemeralDecryptionKey,
            ciphertext: this.ciphertext,
        });
    }

    private buildWebAuthnProof({
        userAddr, publicKey, authenticatorData, clientDataJSON, signature,
    }: {
        userAddr: AccountAddress,
        publicKey: Secp256r1PublicKey,
        authenticatorData: Uint8Array,
        clientDataJSON: Uint8Array,
        signature: Uint8Array,
    }): ProofOfPermission {
        // 1. DER-decode the browser-returned ECDSA signature, low-s
        //    normalise (the worker rejects high-s as malleable), and emit
        //    the raw 64-byte r||s the WebAuthnSignature wire shape expects.
        const sigRs = derEcdsaToRawLowS(signature);

        // 2. fullMessage = hex(authenticatorData || SHA-256(clientDataJSON))
        //    — the bytes the P-256 ECDSA actually digests.
        const cdjHash = sha256(clientDataJSON);
        const preimage = new Uint8Array(authenticatorData.length + cdjHash.length);
        preimage.set(authenticatorData, 0);
        preimage.set(cdjHash, authenticatorData.length);
        const fullMessage = bytesToHex(preimage);

        // 3. Wrap into AnyPublicKey<Secp256r1Ecdsa> + AnySignature<WebAuthn>.
        const anyPk = new AnyPublicKey(publicKey);
        const webAuthnSig = new WebAuthnSignature(sigRs, authenticatorData, clientDataJSON);
        const anySig = new AnySignature(webAuthnSig);
        return ProofOfPermission.createAptos({
            userAddr, publicKey: anyPk, signature: anySig, fullMessage,
        });
    }

    /**
     * Build the per-node POST body for ONE specific worker — does NOT
     * contact the rest of the committee, does NOT reconstruct the plaintext.
     *
     * Useful for load testing (mint one body, replay against the same node)
     * or for any flow that needs to talk to a single worker. The caller does
     * the POST itself; verification of the response is the caller's job too.
     */
    async buildPerNodeRequest({userAddr, publicKey, signature, fullMessage, targetEndpoint}: {
        userAddr: AccountAddress,
        publicKey: PublicKey,
        signature: Signature,
        fullMessage?: string,
        targetEndpoint: string,
    }): Promise<Result<{ encReqHex: string, epoch: number, sdkIdx: number }>> {
        if (fullMessage === undefined) fullMessage = this.request!.toPrettyMessage();
        const proof = ProofOfPermission.createAptos({userAddr, publicKey, signature, fullMessage});
        return buildPerNodeRequestCore({
            aceDeployment: this.aceDeployment,
            networkState: this.networkState!,
            request: this.request!,
            proof,
            ciphertext: this.ciphertext,
            targetEndpoint,
        });
    }
}

/** DER-decodes a P-256 ECDSA signature, normalises it to low-s, and returns
 *  the raw 64-byte `r || s` representation. Browsers emit DER from
 *  `navigator.credentials.get(...).response.signature`; aptos-core's
 *  `WebAuthnSignature` wire shape carries raw `r || s` with low-s enforced. */
function derEcdsaToRawLowS(der: Uint8Array): Uint8Array {
    const sig = p256.Signature.fromDER(der).normalizeS();
    return sig.toCompactRawBytes();
}
