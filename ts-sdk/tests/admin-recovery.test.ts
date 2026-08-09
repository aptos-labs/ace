// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { AccountAddress, Serializer } from "@aptos-labs/ts-sdk";
import { bytesToHex } from "@noble/hashes/utils";
import { bytesToNumberLE, numberToBytesLE } from "@noble/curves/utils";

import * as pke from "../src/pke";
import * as sig from "../src/sig";
import { lagrangeAtZero } from "../src/vss/dealing";
import {
    ReconstructionRequest,
    ReconstructionRequestPayload,
    parseReconstructionResponse,
} from "../src/admin-recovery";
import { WorkerRequest } from "../src/_internal/common";

// Deterministic HPKE-X25519 encryption key: scheme(01) || uleb(0x20) || 32×0x07.
const EPH_EK_HEX = "0120" + "07".repeat(32);

// Cross-language known answer: this MUST byte-match Rust
// `bcs::to_bytes(&ReconstructionRequestPayload {..})` in
// worker-components/network-node/src/http_server/tests.rs. If either side's
// field order / encoding drifts, the reconstructor signature stops verifying.
const EXPECTED_PAYLOAD_HEX =
    "04" +                       // chain_id: u8 = 4
    "09".repeat(32) +            // ace_addr: [u8; 32]
    "ab".repeat(32) +            // keypair_id: [u8; 32]
    "0500000000000000" +         // epoch: u64 LE = 5
    EPH_EK_HEX;                  // eph_pke_ek: EncryptionKey

function fixedPayload(): ReconstructionRequestPayload {
    return new ReconstructionRequestPayload(
        4,
        AccountAddress.fromString("0x" + "09".repeat(32)),
        AccountAddress.fromString("0x" + "ab".repeat(32)),
        5,
        pke.EncryptionKey.fromHex(EPH_EK_HEX).unwrapOrThrow("eph ek"),
    );
}

describe("admin-recovery reconstruction", () => {
    it("payload BCS matches the cross-language known answer", () => {
        expect(bytesToHex(fixedPayload().toBytes())).toBe(EXPECTED_PAYLOAD_HEX);
    });

    it("reconstructor signature over the payload verifies", async () => {
        const { publicKey, signingKey } = await sig.keygen();
        const payload = fixedPayload();
        const signature = signingKey.sign(payload.toBytes());
        expect(publicKey.verify(payload.toBytes(), signature)).toBe(true);
        // Tampering with the payload invalidates the signature.
        const tampered = new ReconstructionRequestPayload(
            4,
            AccountAddress.fromString("0x" + "09".repeat(32)),
            AccountAddress.fromString("0x" + "cd".repeat(32)), // different keypair
            5,
            pke.EncryptionKey.fromHex(EPH_EK_HEX).unwrapOrThrow("eph ek"),
        );
        expect(publicKey.verify(tampered.toBytes(), signature)).toBe(false);
    });

    it("WorkerRequest wraps reconstruction with discriminant 3", async () => {
        const { signingKey } = await sig.keygen();
        const payload = fixedPayload();
        const req = new ReconstructionRequest(payload, signingKey.sign(payload.toBytes()));
        const bytes = WorkerRequest.newReconstruction(req).toBytes();
        expect(bytes[0]).toBe(WorkerRequest.SCHEME_RECONSTRUCTION);
        expect(bytes[0]).toBe(3);
    });

    it("ReconstructionResponse: whole response is encrypted, then parses", async () => {
        const eph = await pke.keygen();
        const scalar = numberToBytesLE(123456789n, 32);

        // Worker builds BCS(ReconstructionResponse { eval_point, group_scheme, scalar_le32 })
        // then PKE-encrypts the WHOLE thing to the ephemeral key (nothing in the clear).
        const inner = new Serializer();
        inner.serializeU64(3n); // eval_point
        inner.serializeU8(1); // group_scheme (G2)
        inner.serializeFixedBytes(scalar); // scalar_le32: [u8; 32], no length prefix
        const ct = await pke.encrypt({ encryptionKey: eph.encryptionKey, plaintext: inner.toUint8Array() });

        // Client decrypts the whole response, then parses.
        const plain = (await pke.decrypt({ decryptionKey: eph.decryptionKey, ciphertext: ct })).okValue!;
        const parsed = parseReconstructionResponse(plain);
        expect(parsed.evalPoint).toBe(3n);
        expect(parsed.groupScheme).toBe(1);
        expect(bytesToHex(parsed.scalar)).toBe(bytesToHex(scalar));
    });

    it("lagrangeAtZero recovers the secret from t-of-n shares", () => {
        // f(x) = secret + 7x + 3x^2  (threshold 3). Shares at x = 1,2,3,4,5.
        const secret = 42n;
        const coeffs = [secret, 7n, 3n];
        const evalPoly = (x: bigint) => coeffs.reduce((acc, c, i) => acc + c * x ** BigInt(i), 0n);
        const shares = [1n, 2n, 3n, 4n, 5n].map(x => ({ x, y: evalPoly(x) }));

        // Any 3 shares recover the secret; a different 3-subset agrees.
        const s = lagrangeAtZero(shares.slice(0, 3));
        expect(s).toBe(secret);
        expect(lagrangeAtZero([shares[1]!, shares[3]!, shares[4]!])).toBe(secret);

        // Round-trip through the 32-byte LE encoding the CLI prints.
        expect(bytesToNumberLE(numberToBytesLE(s, 32))).toBe(secret);
    });
});
