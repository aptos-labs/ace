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
import { Result } from "../result";
import * as pke from "../pke";
import * as tibe from "../t-ibe";
import { State as NetworkState } from "../network";
import {
    AceDeployment,
    ContractID,
    FullDecryptionDomain,
    ProofOfPermission,
    DecryptionRequestPayload,
    fetchNetworkStateAndBuildRequest,
    decryptWithIdentityKeyShares,
    fetchIdentityKeySharesCore,
    buildPerNodeRequestCore,
} from "../_internal/common";

export class BasicDecryptionSession {
    aceDeployment: AceDeployment;
    fullDecryptionDomain: FullDecryptionDomain;
    ciphertext: Uint8Array | undefined;
    tibeScheme: number | undefined;
    ephemeralDecryptionKey: pke.DecryptionKey;
    ephemeralEncryptionKey: pke.EncryptionKey;
    request: DecryptionRequestPayload | undefined;
    networkState: NetworkState | undefined;

    private constructor({
        aceDeployment, keypairId, chainId, moduleAddr, moduleName, label, ciphertext, tibeScheme,
        ephemeralEncryptionKey, ephemeralDecryptionKey,
    }: {
        aceDeployment: AceDeployment,
        keypairId: AccountAddress,
        chainId: number,
        moduleAddr: AccountAddress,
        moduleName: string,
        label: Uint8Array,
        ciphertext?: Uint8Array,
        tibeScheme?: number,
        ephemeralEncryptionKey: pke.EncryptionKey,
        ephemeralDecryptionKey: pke.DecryptionKey,
    }) {
        this.aceDeployment = aceDeployment;
        const contractId = ContractID.newAptos({chainId, moduleAddr, moduleName});
        this.fullDecryptionDomain = new FullDecryptionDomain({keypairId, contractId, label});
        this.ciphertext = ciphertext;
        this.tibeScheme = tibeScheme;
        this.ephemeralEncryptionKey = ephemeralEncryptionKey;
        this.ephemeralDecryptionKey = ephemeralDecryptionKey;
    }

    static async create(params: {
        aceDeployment: AceDeployment,
        keypairId: AccountAddress,
        chainId: number,
        moduleAddr: AccountAddress,
        moduleName: string,
        label: Uint8Array,
        ciphertext?: Uint8Array,
        tibeScheme?: number,
    }): Promise<BasicDecryptionSession> {
        const {encryptionKey, decryptionKey} = await pke.keygen();
        return new BasicDecryptionSession({
            ...params,
            ephemeralEncryptionKey: encryptionKey,
            ephemeralDecryptionKey: decryptionKey,
        });
    }

    /**
     * Returns the canonical `"0x" || hex(BCS(DecryptionRequestPayload))` string
     * that the wallet's `fullMessage` must contain. Pass this as the `message`
     * field to AIP-62 `signMessage`. Use this for account types whose signature
     * scheme digests the wallet fullMessage directly:
     *
     *   - bare Ed25519              (`pk_scheme=0`)
     *   - bare Keyless              (`pk_scheme=4`)
     *   - bare FederatedKeyless     (`pk_scheme=5`)
     *   - `AnyPublicKey` wrapping any of `Ed25519`, `Secp256k1Ecdsa`,
     *     `Keyless`, or `FederatedKeyless` (`pk_scheme=1` inner 0/1/3/4)
     *
     * Hex (`[0-9a-f]`) is injection-safe — no separator, whitespace, or
     * Unicode-normalization concerns when embedded in the AIP-62 wrapper.
     *
     * For passkeys (`AnyPublicKey<Secp256r1Ecdsa>+AnySignature<WebAuthn>`),
     * use [`getRequestToSignForWebAuthn`] instead — that path signs a
     * WebAuthn-shaped challenge derived from the BCS body, not this hex.
     */
    async getRequestToSign(): Promise<string> {
        const {networkState, request} = await fetchNetworkStateAndBuildRequest(
            this.aceDeployment, this.fullDecryptionDomain, this.ephemeralEncryptionKey);
        this.networkState = networkState;
        this.request = request;
        return '0x' + bytesToHex(request.toBytes());
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

    private getCiphertext(context: string): Result<Uint8Array> {
        if (this.ciphertext === undefined) {
            return Result.Err({error: `${context}: ciphertext is required`});
        }
        return Result.Ok({value: this.ciphertext});
    }

    private getTibeScheme(): Result<number> {
        if (this.tibeScheme !== undefined) {
            return Result.Ok({value: this.tibeScheme});
        }
        if (this.ciphertext === undefined) {
            return Result.Ok({value: tibe.SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD});
        }
        const ciphertext = tibe.Ciphertext.fromBytes(this.ciphertext);
        if (!ciphertext.isOk) return Result.Err({error: ciphertext.errValue, extra: ciphertext.extra});
        return Result.Ok({value: ciphertext.okValue!.scheme, extra: ciphertext.extra});
    }

    async decryptWithProof({userAddr, publicKey, signature, fullMessage}: {
        userAddr: AccountAddress,
        publicKey: PublicKey,
        signature: Signature,
        fullMessage: string,
    }): Promise<Result<Uint8Array>> {
        const ciphertext = this.getCiphertext('ACE.IBE_Aptos.BasicDecryptionSession.decryptWithProof');
        if (!ciphertext.isOk) return Result.Err({error: ciphertext.errValue, extra: ciphertext.extra});
        const identityKeySharesResult = await this.fetchIdentityKeySharesWithProof({
            userAddr, publicKey, signature, fullMessage,
        });
        if (!identityKeySharesResult.isOk) return Result.Err({error: identityKeySharesResult.errValue, extra: identityKeySharesResult.extra});
        return decryptWithIdentityKeyShares({
            ciphertext: ciphertext.okValue!,
            identityKeyShares: identityKeySharesResult.okValue!,
        });
    }

    async fetchIdentityKeySharesWithProof({userAddr, publicKey, signature, fullMessage}: {
        userAddr: AccountAddress,
        publicKey: PublicKey,
        signature: Signature,
        fullMessage: string,
    }): Promise<Result<tibe.IdentityDecryptionKeyShare[]>> {
        const tibeScheme = this.getTibeScheme();
        if (!tibeScheme.isOk) return Result.Err({error: tibeScheme.errValue, extra: tibeScheme.extra});
        const proof = ProofOfPermission.createAptos({userAddr, publicKey, signature, fullMessage});
        return fetchIdentityKeySharesCore({
            aceDeployment: this.aceDeployment,
            networkState: this.networkState!,
            request: this.request!,
            proof,
            ephemeralDecryptionKey: this.ephemeralDecryptionKey,
            tibeScheme: tibeScheme.okValue!,
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
        const ciphertext = this.getCiphertext('ACE.IBE_Aptos.BasicDecryptionSession.decryptWithWebAuthnAssertion');
        if (!ciphertext.isOk) return Result.Err({error: ciphertext.errValue, extra: ciphertext.extra});
        const identityKeySharesResult = await this.fetchIdentityKeySharesWithWebAuthnAssertion({
            userAddr, publicKey, authenticatorData, clientDataJSON, signature,
        });
        if (!identityKeySharesResult.isOk) return Result.Err({error: identityKeySharesResult.errValue, extra: identityKeySharesResult.extra});
        return decryptWithIdentityKeyShares({
            ciphertext: ciphertext.okValue!,
            identityKeyShares: identityKeySharesResult.okValue!,
        });
    }

    async fetchIdentityKeySharesWithWebAuthnAssertion({
        userAddr, publicKey, authenticatorData, clientDataJSON, signature,
    }: {
        userAddr: AccountAddress,
        publicKey: Secp256r1PublicKey,
        authenticatorData: Uint8Array,
        clientDataJSON: Uint8Array,
        signature: Uint8Array,
    }): Promise<Result<tibe.IdentityDecryptionKeyShare[]>> {
        const tibeScheme = this.getTibeScheme();
        if (!tibeScheme.isOk) return Result.Err({error: tibeScheme.errValue, extra: tibeScheme.extra});
        const proofResult = this.buildWebAuthnProof({
            userAddr, publicKey, authenticatorData, clientDataJSON, signature,
        });
        if (!proofResult.isOk) return Result.Err({ error: proofResult.errValue });
        return fetchIdentityKeySharesCore({
            aceDeployment: this.aceDeployment,
            networkState: this.networkState!,
            request: this.request!,
            proof: proofResult.okValue!,
            ephemeralDecryptionKey: this.ephemeralDecryptionKey,
            tibeScheme: tibeScheme.okValue!,
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
    }): Result<ProofOfPermission> {
        // DER-decode the browser-returned ECDSA signature, low-s normalise
        // (the worker rejects high-s as malleable), and emit the raw 64-byte
        // r||s the WebAuthnSignature wire shape expects. Wrapped in
        // Result.capture so a malformed DER / out-of-range r||s surfaces as
        // Result.Err rather than a thrown exception — matches the never-
        // throws contract of every other `decrypt*` method on the session.
        return Result.capture({
            task: () => {
                const sigRs = derEcdsaToRawLowS(signature);
                // fullMessage = hex(authenticatorData || SHA-256(clientDataJSON))
                // — the bytes the P-256 ECDSA actually digests.
                const cdjHash = sha256(clientDataJSON);
                const preimage = new Uint8Array(authenticatorData.length + cdjHash.length);
                preimage.set(authenticatorData, 0);
                preimage.set(cdjHash, authenticatorData.length);
                const fullMessage = bytesToHex(preimage);
                // Wrap into AnyPublicKey<Secp256r1Ecdsa> + AnySignature<WebAuthn>.
                const anyPk = new AnyPublicKey(publicKey);
                const webAuthnSig = new WebAuthnSignature(sigRs, authenticatorData, clientDataJSON);
                const anySig = new AnySignature(webAuthnSig);
                return ProofOfPermission.createAptos({
                    userAddr, publicKey: anyPk, signature: anySig, fullMessage,
                });
            },
            recordsExecutionTimeMs: false,
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
        fullMessage: string,
        targetEndpoint: string,
    }): Promise<Result<{ encReqHex: string, epoch: number, sdkIdx: number }>> {
        const tibeScheme = this.getTibeScheme();
        if (!tibeScheme.isOk) return Result.Err({error: tibeScheme.errValue, extra: tibeScheme.extra});
        const proof = ProofOfPermission.createAptos({userAddr, publicKey, signature, fullMessage});
        return buildPerNodeRequestCore({
            aceDeployment: this.aceDeployment,
            networkState: this.networkState!,
            request: this.request!,
            proof,
            tibeScheme: tibeScheme.okValue!,
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
