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
        context: 'StreamIBE_Aptos.fetchPk',
    });
}

/**
 * Streaming, bounded-memory encryption. Consumes an (async) iterable of plaintext byte chunks and
 * yields **ciphertext chunks** (a header chunk, then one 64 KiB segment chunk at a time); nothing
 * is fully buffered. There is no ciphertext object — the caller stores/uploads the chunks.
 */
export async function* encryptStream({
    aceDeployment, keypairId, chainId, moduleAddr, moduleName, label, plaintext, pk, randomness, chunkSize,
}: {
    aceDeployment: AceDeployment,
    keypairId: AccountAddress,
    chainId: number,
    moduleAddr: AccountAddress,
    moduleName: string,
    label: Uint8Array,
    /** Plaintext as an (async) iterable of byte chunks of any size. */
    plaintext: ByteChunks,
    /** Optional cached master public key from `fetchPk`. */
    pk?: tibe.MasterPublicKey,
    /** Test-only: pin the IBE randomness. Omit in production. */
    randomness?: Uint8Array,
    /** Plaintext bytes per segment; defaults to 64 KiB. Rarely overridden outside tests. */
    chunkSize?: number,
}): AsyncGenerator<Uint8Array> {
    const mpk = pk ?? (await fetchPk({ aceDeployment, keypairId })).unwrapOrThrow('StreamIBE_Aptos.encryptStream: fetchPk failed');
    const contractId = ContractID.newAptos({ chainId, moduleAddr, moduleName });
    const fdd = new FullDecryptionDomain({ keypairId, contractId, label });
    yield* tibeStream.encryptStream({ mpk, id: fdd.toBytes(), plaintext, randomness, chunkSize });
}
