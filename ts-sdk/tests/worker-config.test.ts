// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { bytesToHex } from "@noble/hashes/utils";
import * as pke from "../src/pke";
import * as sig from "../src/sig";
import * as workerConfig from "../src/worker-config";

type ElGamalEncryptionKeyInner = {
    elgamalEk: {
        encBase: { bytes: Uint8Array };
        publicPoint: { bytes: Uint8Array };
    };
};

type HpkeEncryptionKeyInner = {
    pk: Uint8Array;
};

describe("worker_config resource parsing", () => {
    it("parses HPKE PKE encryption key resources", async () => {
        const { encryptionKey } = await pke.keygen(pke.SCHEME_HPKE_X25519_HKDF_SHA256_CHACHA20POLY1305);
        const inner = encryptionKey.inner as HpkeEncryptionKeyInner;

        const parsed = workerConfig.pkeEncryptionKeyFromResource({
            ek: {
                __variant__: "HpkeX25519ChaCha20Poly1305",
                _0: {
                    pk: `0x${bytesToHex(inner.pk)}`,
                },
            },
        });

        expect(parsed.toHex()).toBe(encryptionKey.toHex());
    });

    it("parses ElGamal PKE encryption key resources", async () => {
        const { encryptionKey } = await pke.keygen(pke.SCHEME_ELGAMAL_OTP_RISTRETTO255);
        const inner = encryptionKey.inner as ElGamalEncryptionKeyInner;

        const parsed = workerConfig.pkeEncryptionKeyFromResource({
            ek: {
                __variant__: "ElGamalOtpRistretto255",
                _0: {
                    enc_base: Array.from(inner.elgamalEk.encBase.bytes),
                    public_point: { data: Array.from(inner.elgamalEk.publicPoint.bytes) },
                },
            },
        });

        expect(parsed.toHex()).toBe(encryptionKey.toHex());
    });

    it("parses signature verification key resources", async () => {
        const { publicKey } = await sig.keygen();

        const parsed = workerConfig.sigVerificationKeyFromResource({
            pk: {
                __variant__: "Ed25519",
                _0: {
                    bytes: `0x${bytesToHex(publicKey.bytes)}`,
                },
            },
        });

        expect(parsed.toHex()).toBe(publicKey.toHex());
    });
});
