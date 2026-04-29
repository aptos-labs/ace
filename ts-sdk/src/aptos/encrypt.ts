// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { AccountAddress } from "@aptos-labs/ts-sdk";
import { hexToBytes } from "@noble/hashes/utils";
import { Result } from "../result";
import * as dkg from "../dkg";
import * as tibe from "../t-ibe";
import { AceDeployment, ContractID, FullDecryptionDomain, createAptos } from "../_internal/common";

export async function encrypt({aceDeployment, keypairId, chainId, moduleAddr, moduleName, functionName, domain, plaintext}: {
    aceDeployment: AceDeployment,
    keypairId: AccountAddress,
    chainId: number,
    moduleAddr: AccountAddress,
    moduleName: string,
    functionName?: string,
    domain: Uint8Array,
    plaintext: Uint8Array,
}): Promise<Result<Uint8Array>> {
    if (functionName === undefined) functionName = 'check_permission';
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

            const mpk = tibe.MasterPublicKey.newBonehFranklinBls12381ShortPkOtpHmac(session.basePoint, session.resultPk)
                .unwrapOrThrow('AptosEncrypt: construct MPK');

            return tibe.encrypt({mpk, id: fdd.toBytes(), plaintext})
                .unwrapOrThrow('AptosEncrypt: tibe.encrypt failed')
                .toBytes();
        },
        recordsExecutionTimeMs: true,
    });
}
