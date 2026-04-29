// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { AccountAddress, Serializer } from "@aptos-labs/ts-sdk";
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
} from "../../_internal/common";

export class DecryptionSession {
    aceDeployment: AceDeployment;
    fullDecryptionDomain: FullDecryptionDomain;
    ciphertext: Uint8Array;
    ephemeralDecryptionKey: pke.DecryptionKey;
    ephemeralEncryptionKey: pke.EncryptionKey;
    request: DecryptionRequestPayload | undefined;
    networkState: NetworkState | undefined;

    private constructor({aceDeployment, keypairId, knownChainName, programId, domain, ciphertext}: {
        aceDeployment: AceDeployment,
        keypairId: AccountAddress,
        knownChainName: string,
        programId: string,
        domain: Uint8Array,
        ciphertext: Uint8Array,
    }) {
        this.aceDeployment = aceDeployment;
        const contractId = ContractID.newSolana({knownChainName, programId});
        this.fullDecryptionDomain = new FullDecryptionDomain({keypairId, contractId, domain});
        this.ciphertext = ciphertext;
        const {encryptionKey, decryptionKey} = pke.keygen();
        this.ephemeralDecryptionKey = decryptionKey;
        this.ephemeralEncryptionKey = encryptionKey;
    }

    static create(params: {
        aceDeployment: AceDeployment,
        keypairId: AccountAddress,
        knownChainName: string,
        programId: string,
        domain: Uint8Array,
        ciphertext: Uint8Array,
    }): DecryptionSession {
        return new DecryptionSession(params);
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

    async decryptWithProof({txn}: {txn: Uint8Array}): Promise<Result<Uint8Array>> {
        const proof = ProofOfPermission.createSolana({txn});
        return decryptCore({
            aceDeployment: this.aceDeployment,
            networkState: this.networkState!,
            request: this.request!,
            proof,
            ephemeralDecryptionKey: this.ephemeralDecryptionKey,
            ciphertext: this.ciphertext,
        });
    }
}
