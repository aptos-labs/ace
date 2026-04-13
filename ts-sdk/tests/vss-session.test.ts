// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { AccountAddress } from "@aptos-labs/ts-sdk";
import { describe, expect, it } from "vitest";
import { SCHEME_BLS12381G1, Session } from "../src/vss";

/** Shape returned by the Aptos node resource API for `ace::vss::Session`. */
const NODE_RESOURCE_SESSION_EXAMPLE = {
    deal_time_micros: "0",
    dealer: "0x9b4026268872d0ee307c6aca4562700d3344d302e51d96213c0e1663746b3444",
    dealer_contribution_0: "0x",
    dealer_contribution_1: "0x",
    secret_scheme: 0,
    share_holder_acks: [false, false, false, false],
    share_holders: [
        "0x9b4026268872d0ee307c6aca4562700d3344d302e51d96213c0e1663746b3444",
        "0xe2c4a1ba6571fdc000eee47dc5eee5404e891376093bfe7b9b07aa6580256e5",
        "0xe73b92ec1494170f9da69bf81dfd6746f0b418c41afd3fc2180e55ad14656880",
        "0x23fef4f7b1a8a745053ae0a0c9745d88c5793b893c68c96ca4eaaf3effedda03",
    ],
    state_code: 0,
    threshold: "3",
};

describe("Session.fromNodeResourceApi", () => {
    it("parses the documented node API example JSON", () => {
        const result = Session.fromNodeResourceApi(NODE_RESOURCE_SESSION_EXAMPLE);
        expect(result.isOk).toBe(true);
        const session = result.okValue!;

        expect(session.threshold).toBe(3);
        expect(session.secretScheme).toBe(SCHEME_BLS12381G1);
        expect(session.stateCode).toBe(0);
        expect(session.dealTimeMicros).toBe(0);
        expect(session.dealerContribution0.byteLength).toBe(0);
        expect(session.dealerContribution1.byteLength).toBe(0);
        expect(session.shareHolderAcks).toEqual([false, false, false, false]);
        expect(session.isCompleted()).toBe(false);

        expect(session.dealer.equals(AccountAddress.fromString(NODE_RESOURCE_SESSION_EXAMPLE.dealer))).toBe(true);
        expect(session.shareHolders).toHaveLength(4);
        NODE_RESOURCE_SESSION_EXAMPLE.share_holders.forEach((addr, i) => {
            expect(session.shareHolders[i].equals(AccountAddress.fromString(addr))).toBe(true);
        });
    });
});
