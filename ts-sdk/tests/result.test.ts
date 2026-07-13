// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { Result } from "../src/result";

describe("Result", () => {
    it("preserves the original error as cause when adding context", () => {
        const cause = new Error("HTTP 403 from worker");
        const result = Result.Err<never>({ error: cause });

        try {
            result.unwrapOrThrow("ACE decrypt failed");
            throw new Error("expected unwrapOrThrow to throw");
        } catch (error) {
            expect(error).toBeInstanceOf(Error);
            expect((error as Error).message).toBe("ACE decrypt failed");
            expect((error as Error).cause).toBe(cause);
        }
    });
});
