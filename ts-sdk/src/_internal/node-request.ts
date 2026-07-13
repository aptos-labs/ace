// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { Deserializer, Serializer } from "@aptos-labs/ts-sdk";
import { Result } from "../result";
import * as pke from "../pke";

const NODE_REQUEST_WORKER_REQUEST = 1;
const NODE_RESPONSE_WORKER_RESPONSE = 1;

export function encodeWorkerNodeRequest(ciphertext: pke.Ciphertext): Uint8Array {
    const serializer = new Serializer();
    serializer.serializeU8(NODE_REQUEST_WORKER_REQUEST);
    ciphertext.serialize(serializer);
    return serializer.toUint8Array();
}

export function decodeWorkerNodeResponse(bytes: Uint8Array): Result<pke.Ciphertext> {
    return Result.capture({
        recordsExecutionTimeMs: false,
        task: () => {
            const deserializer = new Deserializer(bytes);
            const variant = deserializer.deserializeU8();
            if (variant !== NODE_RESPONSE_WORKER_RESPONSE) {
                throw new Error(`expected WorkerResponse, got NodeResponse variant ${variant}`);
            }
            const ciphertext = pke.Ciphertext.deserialize(deserializer)
                .unwrapOrThrow("decodeWorkerNodeResponse: parse response ciphertext");
            if (deserializer.remaining() !== 0) {
                throw new Error("decodeWorkerNodeResponse: trailing bytes after NodeResponse");
            }
            return ciphertext;
        },
    });
}

export async function buildWorkerNodeRequestBody({
    nodeEncKey,
    plaintext,
}: {
    nodeEncKey: pke.EncryptionKey;
    plaintext: Uint8Array;
}): Promise<Uint8Array> {
    const ciphertext = await pke.encrypt({ encryptionKey: nodeEncKey, plaintext });
    return encodeWorkerNodeRequest(ciphertext);
}

export async function readWorkerNodeResponseCiphertext(resp: Response): Promise<pke.Ciphertext> {
    const bytes = new Uint8Array(await resp.arrayBuffer());
    return decodeWorkerNodeResponse(bytes)
        .unwrapOrThrow("readWorkerNodeResponseCiphertext");
}
