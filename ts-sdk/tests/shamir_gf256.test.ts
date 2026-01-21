// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from "vitest";
import { split, combine } from "../src/shamir_gf256";

describe("shamir_gf256", () => {
	describe("split then combine", () => {
		it("should reconstruct secret with exact threshold shares", () => {
			const secret = new Uint8Array([1, 2, 3, 4, 5]);
			const threshold = 3;
			const total = 5;

			const splitResult = split(secret, threshold, total);
			expect(splitResult.isOk).toBe(true);
			const shares = splitResult.okValue!;
			expect(shares).toHaveLength(total);

			// Use exactly threshold shares (indices 1, 2, 3)
			const shareMap = new Map<number, Uint8Array>([
				[1, shares[0]],
				[2, shares[1]],
				[3, shares[2]],
			]);

			const combineResult = combine(shareMap);
			expect(combineResult.isOk).toBe(true);
			expect(combineResult.okValue).toEqual(secret);
		});

		it("should reconstruct secret with more than threshold shares", () => {
			const secret = new Uint8Array([42, 123, 255, 0, 100]);
			const threshold = 2;
			const total = 5;

			const splitResult = split(secret, threshold, total);
			expect(splitResult.isOk).toBe(true);
			const shares = splitResult.okValue!;

			// Use all shares
			const shareMap = new Map<number, Uint8Array>();
			for (let i = 0; i < total; i++) {
				shareMap.set(i + 1, shares[i]);
			}

			const combineResult = combine(shareMap);
			expect(combineResult.isOk).toBe(true);
			expect(combineResult.okValue).toEqual(secret);
		});

		it("should reconstruct secret with non-consecutive share indices", () => {
			const secret = new Uint8Array([10, 20, 30]);
			const threshold = 3;
			const total = 5;

			const splitResult = split(secret, threshold, total);
			expect(splitResult.isOk).toBe(true);
			const shares = splitResult.okValue!;

			// Use shares at indices 1, 3, 5 (non-consecutive)
			const shareMap = new Map<number, Uint8Array>([
				[1, shares[0]],
				[3, shares[2]],
				[5, shares[4]],
			]);

			const combineResult = combine(shareMap);
			expect(combineResult.isOk).toBe(true);
			expect(combineResult.okValue).toEqual(secret);
		});

		it("should work with single byte secret", () => {
			const secret = new Uint8Array([42]);
			const threshold = 2;
			const total = 3;

			const splitResult = split(secret, threshold, total);
			expect(splitResult.isOk).toBe(true);
			const shares = splitResult.okValue!;

			const shareMap = new Map<number, Uint8Array>([
				[1, shares[0]],
				[3, shares[2]],
			]);

			const combineResult = combine(shareMap);
			expect(combineResult.isOk).toBe(true);
			expect(combineResult.okValue).toEqual(secret);
		});

		it("should work with threshold = 1 (no security, but valid)", () => {
			const secret = new Uint8Array([1, 2, 3]);
			const threshold = 1;
			const total = 5;

			const splitResult = split(secret, threshold, total);
			expect(splitResult.isOk).toBe(true);
			const shares = splitResult.okValue!;

			// Any single share should reconstruct the secret
			const shareMap = new Map<number, Uint8Array>([[3, shares[2]]]);

			const combineResult = combine(shareMap);
			expect(combineResult.isOk).toBe(true);
			expect(combineResult.okValue).toEqual(secret);
		});

		it("should work with threshold = total", () => {
			const secret = new Uint8Array([100, 200]);
			const threshold = 5;
			const total = 5;

			const splitResult = split(secret, threshold, total);
			expect(splitResult.isOk).toBe(true);
			const shares = splitResult.okValue!;

			// Need all shares
			const shareMap = new Map<number, Uint8Array>();
			for (let i = 0; i < total; i++) {
				shareMap.set(i + 1, shares[i]);
			}

			const combineResult = combine(shareMap);
			expect(combineResult.isOk).toBe(true);
			expect(combineResult.okValue).toEqual(secret);
		});

		it("should work with empty secret", () => {
			const secret = new Uint8Array([]);
			const threshold = 2;
			const total = 3;

			const splitResult = split(secret, threshold, total);
			expect(splitResult.isOk).toBe(true);
			const shares = splitResult.okValue!;
			expect(shares).toHaveLength(total);
			expect(shares[0]).toHaveLength(0);

			const shareMap = new Map<number, Uint8Array>([
				[1, shares[0]],
				[2, shares[1]],
			]);

			const combineResult = combine(shareMap);
			expect(combineResult.isOk).toBe(true);
			expect(combineResult.okValue).toEqual(secret);
		});

		it("should work with large secret", () => {
			const secret = new Uint8Array(256);
			for (let i = 0; i < 256; i++) {
				secret[i] = i;
			}
			const threshold = 3;
			const total = 5;

			const splitResult = split(secret, threshold, total);
			expect(splitResult.isOk).toBe(true);
			const shares = splitResult.okValue!;

			const shareMap = new Map<number, Uint8Array>([
				[2, shares[1]],
				[4, shares[3]],
				[5, shares[4]],
			]);

			const combineResult = combine(shareMap);
			expect(combineResult.isOk).toBe(true);
			expect(combineResult.okValue).toEqual(secret);
		});
	});

	describe("split validation", () => {
		it("should return Err if threshold > total", () => {
			const secret = new Uint8Array([1, 2, 3]);
			const result = split(secret, 5, 3);
			expect(result.isOk).toBe(false);
		});

		it("should return Err if threshold < 1", () => {
			const secret = new Uint8Array([1, 2, 3]);
			const result = split(secret, 0, 3);
			expect(result.isOk).toBe(false);
		});

		it("should return Err if total > 256", () => {
			const secret = new Uint8Array([1, 2, 3]);
			const result = split(secret, 3, 257);
			expect(result.isOk).toBe(false);
		});
	});

	describe("combine validation", () => {
		it("should return Err if no shares provided", () => {
			const shareMap = new Map<number, Uint8Array>();
			const result = combine(shareMap);
			expect(result.isOk).toBe(false);
		});

		it("should return Err if share index is out of range (0)", () => {
			const shareMap = new Map<number, Uint8Array>([[0, new Uint8Array([1, 2, 3])]]);
			const result = combine(shareMap);
			expect(result.isOk).toBe(false);
		});

		it("should return Err if share index is out of range (256)", () => {
			const shareMap = new Map<number, Uint8Array>([[256, new Uint8Array([1, 2, 3])]]);
			const result = combine(shareMap);
			expect(result.isOk).toBe(false);
		});

		it("should return Err if shares have different lengths", () => {
			const shareMap = new Map<number, Uint8Array>([
				[1, new Uint8Array([1, 2, 3])],
				[2, new Uint8Array([1, 2])],
			]);
			const result = combine(shareMap);
			expect(result.isOk).toBe(false);
		});
	});

	describe("randomness", () => {
		it("should produce different shares each time (randomized polynomials)", () => {
			const secret = new Uint8Array([42]);
			const threshold = 2;
			const total = 3;

			const result1 = split(secret, threshold, total);
			const result2 = split(secret, threshold, total);
			expect(result1.isOk).toBe(true);
			expect(result2.isOk).toBe(true);
			const shares1 = result1.okValue!;
			const shares2 = result2.okValue!;

			// Shares should differ (with overwhelming probability)
			const allSame = shares1.every(
				(s, i) => s.every((byte, j) => byte === shares2[i][j])
			);
			expect(allSame).toBe(false);
		});
	});
});

