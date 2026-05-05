// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { AccountAddress } from "@aptos-labs/ts-sdk";
import { hexToBytes } from "@noble/hashes/utils";
import { Result } from "../result";
import * as dkg from "../dkg";
import * as tibe from "../t-ibe";
import { AceDeployment, ContractID, FullDecryptionDomain, createAptos } from "../_internal/common";

export async function encrypt({aceDeployment, keypairId, chainId, moduleAddr, moduleName, functionName, domain, plaintext, tibeScheme}: {
    aceDeployment: AceDeployment,
    keypairId: AccountAddress,
    chainId: number,
    moduleAddr: AccountAddress,
    moduleName: string,
    functionName?: string,
    domain: Uint8Array,
    plaintext: Uint8Array,
    /**
     * The t-IBE scheme to encrypt under. Defaults to the project default
     * (`bfibe-bls12381-shortsig-aead`). The on-chain keypair's DKG basepoint group is
     * validated against this — if incompatible (e.g. the keypair was set up with a
     * G1 DKG but `tibeScheme` requests shortsig-aead), encrypt fails with an
     * explicit error rather than silently using the wrong scheme.
     */
    tibeScheme?: number,
}): Promise<Result<Uint8Array>> {
    if (functionName === undefined) functionName = 'check_permission';
    if (tibeScheme === undefined) tibeScheme = tibe.SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD;
    return Result.captureAsync({
        task: async (_extra) => {
            const aptos = createAptos(aceDeployment.apiEndpoint);
            const contractId = ContractID.newAptos({chainId, moduleAddr, moduleName, functionName: functionName!});
            const fdd = new FullDecryptionDomain({keypairId, contractId, domain});
            const aceContractAddr = aceDeployment.contractAddr.toStringLong();

            const [hexBytes] = await aptos.view({
                payload: {
                    function: `${aceContractAddr}::dkg::get_session_bcs` as `${string}::${string}::${string}`,
                    typeArguments: [],
                    functionArguments: [keypairId.toStringLong()],
                },
            });
            const sessionBytes = hexToBytes((hexBytes as string).replace(/^0x/, ''));
            const session = dkg.Session.fromBytes(sessionBytes).unwrapOrThrow('AptosEncrypt: parse DKG session');
            if (!session.resultPk) throw 'AptosEncrypt: DKG session has no resultPk (not yet finalized)';

            const mpk = tibe.MasterPublicKey.fromGroupElements(tibeScheme!, session.basePoint, session.resultPk)
                .unwrapOrThrow(`AptosEncrypt: keypairId ${keypairId.toStringLong()} is incompatible with tibeScheme=${tibeScheme}`);

            return tibe.encrypt({mpk, id: fdd.toBytes(), plaintext})
                .unwrapOrThrow('AptosEncrypt: tibe.encrypt failed')
                .toBytes();
        },
        recordsExecutionTimeMs: true,
    });
}
