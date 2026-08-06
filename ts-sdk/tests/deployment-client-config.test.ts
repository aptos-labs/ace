// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { AccountAddress } from "@aptos-labs/ts-sdk";
import { describe, expect, it } from "vitest";
import { AceDeployment, knownDeployments } from "../src";
import { createAptos } from "../src/_internal/common";

const CONTRACT_ADDR = AccountAddress.fromString(
    "0x2a800d06b231476e045e874b5319409f80aa4449d7cabcdc68d2e0b5a66ee43d",
);
const API_ENDPOINT = "https://api.example.test/v1";

function deployment(overrides: { apiKey?: string, clientConfig?: Record<string, unknown> } = {}) {
    return new AceDeployment({ apiEndpoint: API_ENDPOINT, contractAddr: CONTRACT_ADDR, ...overrides });
}

describe("AceDeployment client configuration", () => {
    it("leaves the Aptos client at its defaults when nothing is configured", () => {
        // Callers on runtimes without HTTP/2 opt out themselves; the SDK must not
        // pick a transport on their behalf.
        expect(createAptos(deployment()).config.clientConfig).toEqual({});
    });

    it("forwards clientConfig to the Aptos client", () => {
        const { clientConfig } = createAptos(deployment({ clientConfig: { http2: false } })).config;

        expect(clientConfig?.http2).toBe(false);
    });

    it("derives the Authorization header from apiKey", () => {
        const { clientConfig } = createAptos(deployment({ apiKey: "secret" })).config;

        expect(clientConfig?.HEADERS).toEqual({ Authorization: "Bearer secret" });
    });

    it("keeps caller headers alongside the apiKey-derived Authorization header", () => {
        const { clientConfig } = createAptos(deployment({
            apiKey: "secret",
            clientConfig: { http2: false, HEADERS: { "x-custom": "kept" } },
        })).config;

        expect(clientConfig?.HEADERS).toEqual({ "x-custom": "kept", Authorization: "Bearer secret" });
        expect(clientConfig?.http2).toBe(false);
    });

    it("defaults to localnet when no endpoint is available", () => {
        expect(createAptos().config.fullnode).toBe("http://localhost:8080/v1");
    });

    it("preserves each setting when the other is overridden", () => {
        const base = deployment({ apiKey: "secret", clientConfig: { http2: false } });

        expect(base.withApiKey("rotated").clientConfig).toEqual({ http2: false });
        expect(base.withClientConfig({ http2: true }).apiKey).toBe("secret");
    });
});

describe("known deployments", () => {
    it("applies api key and client config in either order", () => {
        const known = knownDeployments["shelbynet-20260731"];

        for (const chained of [
            known.withApiKey("secret").withClientConfig({ http2: false }),
            known.withClientConfig({ http2: false }).withApiKey("secret"),
        ]) {
            expect(chained.aceDeployment.apiKey).toBe("secret");
            expect(chained.aceDeployment.clientConfig).toEqual({ http2: false });
        }
    });

    it("does not mutate the shared deployment", () => {
        const known = knownDeployments["shelbynet-20260731"];
        known.withApiKey("secret").withClientConfig({ http2: false });

        expect(known.aceDeployment.apiKey).toBeUndefined();
        expect(known.aceDeployment.clientConfig).toBeUndefined();
    });
});
