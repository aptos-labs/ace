// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

// Shamir's Secret Sharing over GF(256)
// Clean-room implementation based on standard finite field mathematics.

import { Result } from "./result";

// ============================================================================
// GF(256) Finite Field Arithmetic
//
// Field: GF(2^8) defined by the irreducible polynomial x^8 + x^4 + x^3 + x + 1
// This is the same polynomial used in AES (Rijndael).
// Generator: g = 0x03 generates the multiplicative group of order 255.
// ============================================================================

const GF256_SIZE = 256;
const GF256_ORDER = GF256_SIZE - 1; // 255 = order of multiplicative group
const IRREDUCIBLE_POLY = 0x11b; // x^8 + x^4 + x^3 + x + 1
const GENERATOR = 0x03;

/**
 * Carry-less multiplication of two polynomials represented as integers.
 * This is multiplication in GF(2)[x] without reduction.
 */
function carrylessMul(a: number, b: number): number {
	let result = 0;
	let shifted = a;
	while (b > 0) {
		if (b & 1) {
			result ^= shifted;
		}
		shifted <<= 1;
		b >>>= 1;
	}
	return result;
}

/**
 * Reduce a polynomial modulo the irreducible polynomial x^8 + x^4 + x^3 + x + 1.
 */
function reduceModIrreducible(val: number): number {
	for (let bit = 15; bit >= 8; bit--) {
		if (val & (1 << bit)) {
			val ^= IRREDUCIBLE_POLY << (bit - 8);
		}
	}
	return val & 0xff;
}

/**
 * Multiply two elements in GF(256).
 */
function fieldMultiply(a: number, b: number): number {
	if (a === 0 || b === 0) return 0;
	return reduceModIrreducible(carrylessMul(a, b));
}

/**
 * Build EXP and LOG lookup tables for fast field operations.
 * EXP[i] = g^i where g = 0x03
 * LOG[v-1] = i such that g^i = v (for v ≠ 0)
 */
function buildLookupTables(): { expTable: number[]; logTable: number[] } {
	const expTable: number[] = new Array(GF256_ORDER);
	const logTable: number[] = new Array(GF256_ORDER);

	let power = 1; // g^0 = 1
	for (let i = 0; i < GF256_ORDER; i++) {
		expTable[i] = power;
		logTable[power - 1] = i;
		power = fieldMultiply(power, GENERATOR);
	}

	return { expTable, logTable };
}

const { expTable: EXP, logTable: LOG } = buildLookupTables();

// ============================================================================
// Helper functions
// ============================================================================

function hasDuplicates(array: number[]): boolean {
	return new Set(array).size !== array.length;
}

function allEqual(array: number[]): boolean {
	if (array.length === 0) {
		return true;
	}
	return array.every((item) => item === array[0]);
}

// ============================================================================
// GF256 Class - Element of GF(2^8)
// ============================================================================

class GF256 {
	value: number;

	private constructor(value: number) {
		this.value = value;
	}

	static new(value: number): Result<GF256> {
		const task = (_extra: Record<string, any>) => {
			if (value < 0 || value >= GF256_SIZE) {
				throw 'invalid value for GF256';
			}
			return new GF256(value);
		};
		return Result.capture({ task, recordsExecutionTimeMs: false });
	}

	/**
	 * Discrete logarithm base g=0x03.
	 * Returns i such that g^i = this.value.
	 */
	log(): number {
		if (this.value === 0) {
			throw new Error("Invalid value");
		}
		return LOG[this.value - 1];
	}

	/**
	 * Exponentiation: returns g^x where g=0x03 is the generator.
	 */
	static exp(x: number): GF256 {
		// Ensure x is in valid range using modular arithmetic
		return new GF256(EXP[((x % GF256_ORDER) + GF256_ORDER) % GF256_ORDER]);
	}

	/**
	 * Addition in GF(2^8) is XOR.
	 */
	add(other: GF256): GF256 {
		return new GF256(this.value ^ other.value);
	}

	/**
	 * Subtraction in GF(2^8) is the same as addition (XOR).
	 * In characteristic 2: a - b = a + (-b) = a + b.
	 */
	sub(other: GF256): GF256 {
		return this.add(other);
	}

	/**
	 * Negation in GF(2^8) is identity.
	 * In characteristic 2: -a = a.
	 */
	neg(): GF256 {
		return this;
	}

	/**
	 * Multiplication using logarithm tables.
	 * a * b = g^(log(a) + log(b))
	 */
	mul(other: GF256): GF256 {
		if (this.value === 0 || other.value === 0) {
			return new GF256(0);
		}
		return GF256.exp(this.log() + other.log());
	}

	/**
	 * Division: a / b = a * b^(-1) = g^(log(a) - log(b))
	 */
	div(other: GF256): GF256 {
		if (other.value === 0) {
			throw new Error("Division by zero");
		}
		if (this.value === 0) {
			return new GF256(0);
		}
		return GF256.exp(this.log() - other.log() + GF256_ORDER);
	}

	equals(other: GF256): boolean {
		return this.value === other.value;
	}

	static zero(): GF256 {
		return new GF256(0);
	}

	static one(): GF256 {
		return new GF256(1);
	}
}

// ============================================================================
// Polynomial Class - Polynomial over GF(256)
// ============================================================================

class Polynomial {
	coefficients: GF256[];

	/**
	 * Construct a polynomial from coefficients.
	 * coefficients[0] is the constant term, coefficients[i] is the x^i coefficient.
	 */
	constructor(coefficients: GF256[]) {
		this.coefficients = coefficients.slice();

		// Remove leading zeros (highest degree coefficients that are zero)
		while (
			this.coefficients.length > 0 &&
			this.coefficients[this.coefficients.length - 1].value === 0
		) {
			this.coefficients.pop();
		}
	}

	static fromBytes(bytes: Uint8Array): Result<Polynomial> {
		const task = (extra: Record<string, any>) => {
			extra['input_bytes'] = bytes;
			return new Polynomial(Array.from(bytes, (b) => GF256.new(b).unwrapOrThrow('some byte is not in GF256')));
		};
		return Result.capture({ task, recordsExecutionTimeMs: false });
	}

	degree(): number {
		if (this.coefficients.length === 0) {
			return 0;
		}
		return this.coefficients.length - 1;
	}

	getCoefficient(index: number): GF256 {
		if (index >= this.coefficients.length) {
			return GF256.zero();
		}
		return this.coefficients[index];
	}

	/**
	 * Add two polynomials.
	 */
	add(other: Polynomial): Polynomial {
		const maxDegree = Math.max(this.degree(), other.degree());
		return new Polynomial(
			Array.from({ length: maxDegree + 1 }, (_, i) =>
				this.getCoefficient(i).add(other.getCoefficient(i))
			)
		);
	}

	/**
	 * Multiply two polynomials using convolution.
	 */
	mul(other: Polynomial): Polynomial {
		const resultDegree = this.degree() + other.degree();
		return new Polynomial(
			Array.from({ length: resultDegree + 1 }, (_, i) => {
				let sum = GF256.zero();
				for (let j = 0; j <= i; j++) {
					if (j <= this.degree() && i - j <= other.degree()) {
						sum = sum.add(this.getCoefficient(j).mul(other.getCoefficient(i - j)));
					}
				}
				return sum;
			})
		);
	}

	/**
	 * Multiply polynomial by a scalar.
	 */
	scale(s: GF256): Polynomial {
		return new Polynomial(this.coefficients.map((c) => c.mul(s)));
	}

	/**
	 * Divide polynomial by a scalar.
	 */
	div(s: GF256): Polynomial {
		return this.scale(GF256.one().div(s));
	}

	/**
	 * Create the monic linear polynomial (x + c).
	 */
	static monic_linear(c: GF256): Polynomial {
		return new Polynomial([c, GF256.one()]);
	}

	static zero(): Polynomial {
		return new Polynomial([]);
	}

	static one(): Polynomial {
		return new Polynomial([GF256.one()]);
	}

	/**
	 * Lagrange interpolation: find the unique polynomial of degree < n
	 * that passes through the given n points.
	 */
	static interpolate(coordinates: { x: GF256; y: GF256 }[]): Polynomial {
		if (coordinates.length < 1) {
			throw new Error("At least one coefficient is required");
		}

		if (hasDuplicates(coordinates.map(({ x }) => x.value))) {
			throw new Error("Coefficients must have unique x values");
		}

		// Lagrange interpolation: P(x) = Σ y_j * L_j(x)
		// where L_j(x) = Π_{i≠j} (x - x_i) / (x_j - x_i)
		return coordinates.reduce(
			(sum, { x: x_j, y: y_j }, j) =>
				sum.add(
					coordinates
						.filter((_, i) => i !== j)
						.reduce(
							(product, { x: x_i }) =>
								product.mul(Polynomial.monic_linear(x_i.neg()).div(x_j.sub(x_i))),
							Polynomial.one()
						)
						.scale(y_j)
				),
			Polynomial.zero()
		);
	}

	/**
	 * Optimized interpolation that only computes P(0).
	 * This is what we need for secret reconstruction.
	 */
	static combine(coordinates: { x: GF256; y: GF256 }[]): GF256 {
		if (coordinates.length < 1) {
			throw new Error("At least one coefficient is required");
		}

		const xValues = coordinates.map(({ x }) => x.value);
		if (hasDuplicates(xValues)) {
			throw new Error(
				`Coefficients must have unique x values. Found duplicates: ${xValues.join(", ")}`
			);
		}

		// P(0) = Σ y_j * L_j(0) where L_j(0) = Π_{i≠j} (-x_i) / (x_j - x_i)
		// Since we're in characteristic 2, -x_i = x_i, so:
		// L_j(0) = Π_{i≠j} x_i / (x_j - x_i)
		//
		// Rearranging: P(0) = (Π x_i) * Σ (y_j / (x_j * Π_{i≠j}(x_i - x_j)))

		const quotient: GF256 = coordinates.reduce((sum, { x: x_j, y: y_j }, j) => {
			const denominator = x_j.mul(
				coordinates
					.filter((_, i) => i !== j)
					.reduce((product, { x: x_i }) => {
						const diff = x_i.sub(x_j);
						if (diff.value === 0) {
							throw new Error(
								`Duplicate x values detected: x_i=${x_i.value}, x_j=${x_j.value}`
							);
						}
						return product.mul(diff);
					}, GF256.one())
			);
			return sum.add(y_j.div(denominator));
		}, GF256.zero());

		const xProduct = coordinates.reduce((product, { x }) => product.mul(x), GF256.one());
		return xProduct.mul(quotient);
	}

	/**
	 * Evaluate polynomial at point x using Horner's method.
	 */
	evaluate(x: GF256): GF256 {
		return this.coefficients
			.slice()
			.reverse()
			.reduce((acc, coeff) => acc.mul(x).add(coeff), GF256.zero());
	}

	equals(other: Polynomial): boolean {
		if (this.coefficients.length !== other.coefficients.length) {
			return false;
		}
		return this.coefficients.every((c, i) => c.equals(other.getCoefficient(i)));
	}
}

// ============================================================================
// Internal helpers for secret sharing
// ============================================================================

/**
 * Sample a random polynomial with the given constant term.
 * The polynomial will have degree = degree parameter.
 */
function sampleRandomPolynomial(constant: GF256, degree: number): Result<Polynomial> {
	const task = (extra: Record<string, any>) => {
		extra['constant'] = constant.value;
		extra['degree'] = degree;
		const randomCoefficients = new Uint8Array(degree);
		crypto.getRandomValues(randomCoefficients);
		return Polynomial.fromBytes(new Uint8Array([constant.value, ...randomCoefficients])).unwrapOrThrow('polynomial deserialization failed');
	};
	return Result.capture({ task, recordsExecutionTimeMs: false });
} 

// ============================================================================
// Public API: split and combine
// ============================================================================

/**
 * Split a secret into shares using Shamir's Secret Sharing.
 *
 * @param secret - The secret bytes to split
 * @param threshold - Minimum number of shares required to reconstruct (k)
 * @param total - Total number of shares to generate (n)
 * @returns Result containing array of share payloads (index i contains the share evaluated at x = i + 1)
 */
export function split(secret: Uint8Array, threshold: number, total: number): Result<Uint8Array[]> {
	const task = (extra: Record<string, any>) => {
		extra['threshold'] = threshold;
		extra['total'] = total;
		if (threshold > total || threshold < 1 || total > GF256_SIZE) {
			throw 'invalid threshold or total';
		}

		// For each byte of the secret, create a random polynomial where the constant term is that byte
		const polynomials = Array.from(secret, (s) => {
			const constant = GF256.new(s).unwrapOrThrow('constant object creation failed');
			return sampleRandomPolynomial(constant, threshold - 1).unwrapOrThrow('polynomial sampling failed');
		});

		// Evaluate each polynomial at x = 1, 2, ..., total
		return Array.from({ length: total }, (_, i) => {
			// Indices start at 1 because x=0 is the secret itself
			const index = GF256.new(i + 1).unwrapOrThrow('index object creation failed');
			const payload = polynomials.map((p) => p.evaluate(index));
			return new Uint8Array(payload.map((byte) => byte.value));
		});
	};
	return Result.capture({ task, recordsExecutionTimeMs: false });
}

/**
 * Combine shares to reconstruct the original secret.
 * Requires at least threshold shares to correctly reconstruct.
 *
 * @param shares - Map from share index (1-255) to payload
 * @returns Result containing the reconstructed secret
 */
export function combine(shares: Map<number, Uint8Array>): Result<Uint8Array> {
	const task = (extra: Record<string, any>) => {
		if (shares.size < 1) {
			throw "at least one share is required";
		}

		const entries = Array.from(shares.entries());
		const indices = entries.map(([index]) => index);
		const payloads = entries.map(([, payload]) => payload);
		extra['indices'] = indices;

		// Validate indices
		for (const index of indices) {
			if (index < 1 || index > 255) {
				throw `some share indices are invalid`;
			}
		}

		if (!allEqual(payloads.map((p) => p.length))) {
			throw "all shares must have the same length";
		}

		const length = payloads[0].length;
		extra['secret_length'] = length;

		// For each byte position, perform Lagrange interpolation to find the constant term
		return new Uint8Array(
			Array.from(
				{ length },
				(_, i) =>
					Polynomial.combine(
						entries.map(([index, payload]) => ({
							x: GF256.new(index).unwrapOrThrow('index object creation failed'),
							y: GF256.new(payload[i]).unwrapOrThrow('payload object creation failed'),
						}))
					).value
			)
		);
	};
	return Result.capture({ task, recordsExecutionTimeMs: false });
}
