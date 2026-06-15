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
        context: 'SolanaEncrypt.fetchPk',
    });
}

export async function encrypt({aceDeployment, keypairId, knownChainName, programId, label, plaintext, tibeScheme, pk}: {
    aceDeployment: AceDeployment,
    keypairId: AccountAddress,
    knownChainName: string,
    programId: string,
    label: Uint8Array,
    plaintext: Uint8Array,
    /**
     * The t-IBE scheme to encrypt under. Defaults to the project default
     * (`bfibe-bls12381-shortsig-aead`). The on-chain keypair's DKG basepoint group is
     * validated against this — if incompatible, encrypt fails with an explicit error
     * rather than silently using the wrong scheme.
     */
    tibeScheme?: number,
    /** Optional cached public key from `fetchPk`; avoids an Aptos view call per encryption. */
    pk?: tibe.MasterPublicKey,
}): Promise<Result<Uint8Array>> {
    const effectiveTibeScheme = tibeScheme ?? pk?.scheme ?? tibe.SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD;
    return Result.captureAsync({
        task: async (_extra) => {
            const contractId = ContractID.newSolana({knownChainName, programId});
            const fdd = new FullDecryptionDomain({keypairId, contractId, label});
            const mpk = pk ?? (await fetchPk({
                aceDeployment,
                keypairId,
                tibeScheme: effectiveTibeScheme,
            })).unwrapOrThrow('SolanaEncrypt: fetchPk failed');
            if (mpk.scheme !== effectiveTibeScheme) {
                throw `SolanaEncrypt: pk.scheme ${mpk.scheme} does not match tibeScheme=${effectiveTibeScheme}`;
            }

            return tibe.encrypt({mpk, id: fdd.toBytes(), plaintext})
                .unwrapOrThrow('SolanaEncrypt: tibe.encrypt failed')
                .toBytes();
        },
        recordsExecutionTimeMs: true,
    });
}
