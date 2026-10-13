// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { AccountAddress } from "@aptos-labs/ts-sdk";
import { Result } from "../result";
import * as tibe from "../t-ibe";
import { AceDeployment, ContractID, FullDecryptionDomain, fetchTibePublicKey } from "../_internal/common";

export async function fetchPk({aceDeployment, keypairId, tibeScheme}: {
    aceDeployment: AceDeployment,
    keypairId: AccountAddress,
    tibeScheme?: number,
}): Promise<Result<tibe.MasterPublicKey>> {
    return fetchTibePublicKey({
        aceDeployment,
        keypairId,
        tibeScheme,
        context: 'AptosEncrypt.fetchPk',
    });
}

export async function encrypt({aceDeployment, keypairId, chainId, moduleAddr, moduleName, label, plaintext, tibeScheme, pk}: {
    aceDeployment: AceDeployment,
    keypairId: AccountAddress,
    chainId: number,
    moduleAddr: AccountAddress,
    moduleName: string,
    label: Uint8Array,
    plaintext: Uint8Array,
    /**
     * The t-IBE scheme to encrypt under. Defaults to the project default
     * (`bfibe-bls12381-shortsig-aead`). The on-chain keypair's DKG basepoint group is
     * validated against this — if incompatible (e.g. the keypair was set up with a
     * G1 DKG but `tibeScheme` requests shortsig-aead), encrypt fails with an
     * explicit error rather than silently using the wrong scheme.
     */
    tibeScheme?: number,
    /** Optional cached public key from `fetchPk`; avoids an Aptos view call per encryption. */
    pk?: tibe.MasterPublicKey,
}): Promise<Result<Uint8Array>> {
    const effectiveTibeScheme = tibeScheme ?? pk?.scheme ?? tibe.SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD;
    return Result.captureAsync({
        task: async (_extra) => {
            const contractId = ContractID.newAptos({chainId, moduleAddr, moduleName});
            const fdd = new FullDecryptionDomain({keypairId, contractId, label});
            let mpk = pk;
            if (mpk === undefined) {
                const fetched = await fetchPk({aceDeployment, keypairId, tibeScheme: effectiveTibeScheme});
                if (!fetched.isOk) {
                    throw new Error('AptosEncrypt: fetchPk failed', {cause: fetched.errValue});
                }
                mpk = fetched.okValue!;
            }
            if (mpk.scheme !== effectiveTibeScheme) {
                throw `AptosEncrypt: pk.scheme ${mpk.scheme} does not match tibeScheme=${effectiveTibeScheme}`;
            }

            const encrypted = tibe.encrypt({mpk, id: fdd.toBytes(), plaintext});
            if (!encrypted.isOk) {
                throw new Error('AptosEncrypt: tibe.encrypt failed', {cause: encrypted.errValue});
            }
            return encrypted.okValue!.toBytes();
        },
        recordsExecutionTimeMs: true,
    });
}
