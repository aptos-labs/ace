// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { Deserializer, Serializer } from "@aptos-labs/ts-sdk";
import { Result } from "../result";
import * as pke from "../pke";
import {
    MAX_WORKER_RESPONSE_BODY_BYTES,
    MAX_WORKER_RESPONSE_HEADER_BYTES,
} from "./worker-request-limits";

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
    const bytes = await readWorkerResponseBytes(resp);
    return decodeWorkerNodeResponse(bytes)
        .unwrapOrThrow("readWorkerNodeResponseCiphertext");
}

/**
 * Read a worker response without allowing an untrusted committee member to
 * make the client buffer an arbitrarily large body. The stream is cancelled
 * as soon as the configured limit is exceeded.
 */
export async function readWorkerResponseBytes(
    resp: Response,
    maxBytes = MAX_WORKER_RESPONSE_BODY_BYTES,
    maxHeaderBytes = MAX_WORKER_RESPONSE_HEADER_BYTES,
): Promise<Uint8Array> {
    const encoder = new TextEncoder();
    let headerBytes = 2; // final CRLF
    resp.headers.forEach((value, name) => {
        headerBytes += encoder.encode(name).byteLength
            + 2
            + encoder.encode(value).byteLength
            + 2;
    });
    if (headerBytes > maxHeaderBytes) {
        await resp.body?.cancel().catch(() => undefined);
        throw new Error(`worker response headers exceed max ${maxHeaderBytes} bytes`);
    }

    const contentLength = resp.headers.get("content-length");
    if (contentLength !== null) {
        const declaredBytes = Number(contentLength);
        if (Number.isFinite(declaredBytes) && declaredBytes > maxBytes) {
            await resp.body?.cancel().catch(() => undefined);
            throw new Error(`worker response body exceeds max ${maxBytes} bytes`);
        }
    }

    if (resp.body === null) return new Uint8Array(0);

    const reader = resp.body.getReader();
    const chunks: Uint8Array[] = [];
    let totalBytes = 0;
    try {
        while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            totalBytes += value.byteLength;
            if (totalBytes > maxBytes) {
                await reader.cancel().catch(() => undefined);
                throw new Error(`worker response body exceeds max ${maxBytes} bytes`);
            }
            chunks.push(value);
        }
    } finally {
        reader.releaseLock();
    }

    const bytes = new Uint8Array(totalBytes);
    let offset = 0;
    for (const chunk of chunks) {
        bytes.set(chunk, offset);
        offset += chunk.byteLength;
    }
    return bytes;
}

export async function readWorkerResponseText(
    resp: Response,
    maxBytes = MAX_WORKER_RESPONSE_BODY_BYTES,
): Promise<string> {
    return new TextDecoder().decode(await readWorkerResponseBytes(resp, maxBytes));
}
