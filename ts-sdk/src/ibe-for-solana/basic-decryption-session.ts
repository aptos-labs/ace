// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { AccountAddress, Serializer } from "@aptos-labs/ts-sdk";
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
        aceDeployment, keypairId, knownChainName, programId, label, ciphertext, tibeScheme,
        ephemeralEncryptionKey, ephemeralDecryptionKey,
    }: {
        aceDeployment: AceDeployment,
        keypairId: AccountAddress,
        knownChainName: string,
        programId: string,
        label: Uint8Array,
        ciphertext?: Uint8Array,
        tibeScheme?: number,
        ephemeralEncryptionKey: pke.EncryptionKey,
        ephemeralDecryptionKey: pke.DecryptionKey,
    }) {
        this.aceDeployment = aceDeployment;
        const contractId = ContractID.newSolana({knownChainName, programId});
        this.fullDecryptionDomain = new FullDecryptionDomain({keypairId, contractId, label});
        this.ciphertext = ciphertext;
        this.tibeScheme = tibeScheme;
        this.ephemeralEncryptionKey = ephemeralEncryptionKey;
        this.ephemeralDecryptionKey = ephemeralDecryptionKey;
    }

    static async create(params: {
        aceDeployment: AceDeployment,
        keypairId: AccountAddress,
        knownChainName: string,
        programId: string,
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

    async getRequestToSign(): Promise<Uint8Array> {
        const {networkState, request} = await fetchNetworkStateAndBuildRequest(
            this.aceDeployment, this.fullDecryptionDomain, this.ephemeralEncryptionKey);
        this.networkState = networkState;
        this.request = request;
        const s = new Serializer();
        request.keypairId.serialize(s);
        s.serializeU64(BigInt(request.epoch));
        s.serializeBytes(request.ephemeralEncKey.toBytes());
        s.serializeBytes(request.domain);
        return s.toUint8Array();
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

    async decryptWithProof({txn}: {txn: Uint8Array}): Promise<Result<Uint8Array>> {
        const ciphertext = this.getCiphertext('ACE.IBE_Solana.BasicDecryptionSession.decryptWithProof');
        if (!ciphertext.isOk) return Result.Err({error: ciphertext.errValue, extra: ciphertext.extra});
        const identityKeySharesResult = await this.fetchIdentityKeySharesWithProof({ txn });
        if (!identityKeySharesResult.isOk) return Result.Err({error: identityKeySharesResult.errValue, extra: identityKeySharesResult.extra});
        return decryptWithIdentityKeyShares({
            ciphertext: ciphertext.okValue!,
            identityKeyShares: identityKeySharesResult.okValue!,
        });
    }

    async fetchIdentityKeySharesWithProof({txn}: {txn: Uint8Array}): Promise<Result<tibe.IdentityDecryptionKeyShare[]>> {
        const tibeScheme = this.getTibeScheme();
        if (!tibeScheme.isOk) return Result.Err({error: tibeScheme.errValue, extra: tibeScheme.extra});
        const proof = ProofOfPermission.createSolana({txn});
        return fetchIdentityKeySharesCore({
            aceDeployment: this.aceDeployment,
            networkState: this.networkState!,
            request: this.request!,
            proof,
            ephemeralDecryptionKey: this.ephemeralDecryptionKey,
            tibeScheme: tibeScheme.okValue!,
        });
    }
}
