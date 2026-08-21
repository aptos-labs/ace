// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { AccountAddress } from "@aptos-labs/ts-sdk";
import { Result } from "../result";
import * as tibe from "../t-ibe";
import * as tibeStream from "../t-ibe-stream";
import { AceDeployment, ContractID, FullDecryptionDomain, fetchTibePublicKey } from "../_internal/common";

type ByteChunks = AsyncIterable<Uint8Array> | Iterable<Uint8Array>;

/** Fetch the streaming master public key (the shortsig-aead G2 key — streaming reuses it). */
export async function fetchPk({ aceDeployment, keypairId }: {
    aceDeployment: AceDeployment,
    keypairId: AccountAddress,
}): Promise<Result<tibe.MasterPublicKey>> {
    return fetchTibePublicKey({
        aceDeployment,
        keypairId,
        tibeScheme: tibe.SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD,
        context: 'StreamIBE_Solana.fetchPk',
    });
}

/** Streaming, bounded-memory encryption for Solana. Yields ciphertext chunks (see Aptos equiv). */
export async function* encryptStream({
    aceDeployment, keypairId, knownChainName, programId, label, plaintext, pk, randomness, chunkSize,
}: {
    aceDeployment: AceDeployment,
    keypairId: AccountAddress,
    knownChainName: string,
    programId: string,
    label: Uint8Array,
    plaintext: ByteChunks,
    pk?: tibe.MasterPublicKey,
    randomness?: Uint8Array,
    chunkSize?: number,
}): AsyncGenerator<Uint8Array> {
    const mpk = pk ?? (await fetchPk({ aceDeployment, keypairId })).unwrapOrThrow('StreamIBE_Solana.encryptStream: fetchPk failed');
    const contractId = ContractID.newSolana({ knownChainName, programId });
    const fdd = new FullDecryptionDomain({ keypairId, contractId, label });
    yield* tibeStream.encryptStream({ mpk, id: fdd.toBytes(), plaintext, randomness, chunkSize });
}
