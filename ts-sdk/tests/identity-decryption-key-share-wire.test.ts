import { describe, expect, it } from "vitest";
import { hexToBytes } from "@noble/hashes/utils";

import vectors from "../../test-vectors/identity-decryption-key-share.json";
import * as TIBE from "../src/t-ibe";

describe("IdentityDecryptionKeyShare cross-language wire vectors", () => {
    const cases = [
        {
            scheme: TIBE.SCHEME_BFIBE_BLS12381_SHORTPK_OTP_HMAC,
            hex: vectors.shortpk_otp_hmac_hex,
            pointBytes: 96,
            wireBytes: 131,
        },
        {
            scheme: TIBE.SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD,
            hex: vectors.shortsig_aead_hex,
            pointBytes: 48,
            wireBytes: 83,
        },
    ];

    for (const testCase of cases) {
        it(`round-trips Rust scheme ${testCase.scheme} bytes`, () => {
            const share = TIBE.IdentityDecryptionKeyShare.fromHex(testCase.hex)
                .unwrapOrThrow("decode Rust IDK share vector");

            expect(share.scheme).toBe(testCase.scheme);
            expect(testCase.hex).toHaveLength(testCase.wireBytes * 2);
            expect(share.inner.evalPoint).toBe(BigInt(vectors.eval_point));
            expect(share.inner.idkShare.toBytes()).toHaveLength(testCase.pointBytes);
            expect(share.toHex()).toBe(testCase.hex);
        });
    }

    it("parses structural bytes without decompressing the curve point", () => {
        const bytes = hexToBytes(vectors.shortsig_aead_hex);
        bytes.fill(0xff, bytes.length - 48);

        const wire = TIBE.IdentityDecryptionKeyShareWire.fromBytes(bytes)
            .unwrapOrThrow("wire parse should only validate structure");
        expect(wire.evalPoint).toBe(BigInt(vectors.eval_point));
        expect(wire.idkShareBytes).toEqual(new Uint8Array(48).fill(0xff));
        expect(wire.materialize().isOk).toBe(false);
    });
});
