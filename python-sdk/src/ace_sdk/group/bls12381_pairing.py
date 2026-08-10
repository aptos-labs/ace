# Copyright (c) Aptos Labs
# SPDX-License-Identifier: Apache-2.0
"""
Pure-Python re-implementation of the BLS12-381 optimal-ate pairing and its
Gt (Fp12) tower-field arithmetic, built to match @noble/curves/bls12-381's
`pairing()` / `fields.Fp12.toBytes()` byte-for-byte (which is itself the
representation Aptos's on-chain `bls12381_algebra.move` Gt format derives
from, modulo a documented per-48-byte-limb endianness flip -- see
`fp12_to_aptos_gt_bytes` below).

`py_ecc`'s optimized_bls12_381 module computes a *mathematically equivalent*
pairing (same abstract value) but is built on a different Fp12 tower/basis,
so its pairing()/FQ12 cannot be used directly to reproduce noble's byte
encoding -- this module exists to close that gap. G1/G2 point arithmetic
still goes through py_ecc (already verified byte-identical to noble for
point encoding); only the pairing (Miller loop + final exponentiation) and
the Fp12 tower are reimplemented here, ported line-for-line from
@noble/curves' `abstract/tower.js` + `abstract/bls.js` + `bls12-381.js`
(MIT licensed, Paul Miller, https://paulmillr.com).
"""

from __future__ import annotations

# == Base field Fp =============================================================

P = 0x1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFAAAB


def fp_add(a: int, b: int) -> int:
    return (a + b) % P


def fp_sub(a: int, b: int) -> int:
    return (a - b) % P


def fp_mul(a: int, b: int) -> int:
    return (a * b) % P


def fp_neg(a: int) -> int:
    return (-a) % P


def fp_pow(a: int, e: int) -> int:
    return pow(a, e, P)


def fp_inv(a: int) -> int:
    return pow(a, P - 2, P)


def fp_to_bytes(a: int) -> bytes:
    return (a % P).to_bytes(48, "big")


def fp_from_bytes(b: bytes) -> int:
    if len(b) != 48:
        raise ValueError("expected 48 bytes")
    return int.from_bytes(b, "big") % P


# == Fp2 tower: Fp2 = Fp[u] / (u^2 - NONRESIDUE), NONRESIDUE = -1 ============
# Element represented as (c0, c1) meaning c0 + c1*u.

Fp2 = tuple[int, int]

_FP2_NONRESIDUE = fp_neg(1)  # -1, per noble's `NONRESIDUE: BigInt(-1)` default


def fp2_add(a: Fp2, b: Fp2) -> Fp2:
    return (fp_add(a[0], b[0]), fp_add(a[1], b[1]))


def fp2_sub(a: Fp2, b: Fp2) -> Fp2:
    return (fp_sub(a[0], b[0]), fp_sub(a[1], b[1]))


def fp2_neg(a: Fp2) -> Fp2:
    return (fp_neg(a[0]), fp_neg(a[1]))


def fp2_mul(a: Fp2, b: Fp2 | int) -> Fp2:
    if isinstance(b, int):
        return (fp_mul(a[0], b), fp_mul(a[1], b))
    c0, c1 = a
    r0, r1 = b
    t1 = fp_mul(c0, r0)
    t2 = fp_mul(c1, r1)
    o0 = fp_sub(t1, t2)
    o1 = fp_sub(fp_mul(fp_add(c0, c1), fp_add(r0, r1)), fp_add(t1, t2))
    return (o0, o1)


def fp2_sqr(a: Fp2) -> Fp2:
    c0, c1 = a
    aa = fp_add(c0, c1)
    bb = fp_sub(c0, c1)
    cc = fp_add(c0, c0)
    return (fp_mul(aa, bb), fp_mul(cc, c1))


def fp2_mul_by_nonresidue(a: Fp2) -> Fp2:
    """Multiply by u + 1 (noble's NONRESIDUE for the Fp6 tower is (1,1))."""
    return fp2_mul(a, (1, 1))


def fp2_inv(a: Fp2) -> Fp2:
    aa, bb = a
    factor = fp_inv(fp_add(fp_mul(aa, aa), fp_mul(bb, bb)))
    return (fp_mul(factor, aa), fp_mul(factor, fp_neg(bb)))


def fp2_is0(a: Fp2) -> bool:
    return a[0] == 0 and a[1] == 0


def fp2_eq(a: Fp2, b: Fp2) -> bool:
    return a[0] == b[0] and a[1] == b[1]


def fp2_to_bytes(a: Fp2) -> bytes:
    return fp_to_bytes(a[0]) + fp_to_bytes(a[1])


def fp2_from_bytes(b: bytes) -> Fp2:
    if len(b) != 96:
        raise ValueError("expected 96 bytes")
    return (fp_from_bytes(b[:48]), fp_from_bytes(b[48:]))


# == Fp6 tower: Fp6 = Fp2[v] / (v^3 - NONRESIDUE), NONRESIDUE = u+1 ==========
# Element represented as (c0, c1, c2) meaning c0 + c1*v + c2*v^2.

Fp6 = tuple[Fp2, Fp2, Fp2]

_FP6_ZERO: Fp2 = (0, 0)
_FP6_ONE: Fp2 = (1, 0)


def fp6_add(a: Fp6, b: Fp6) -> Fp6:
    return (fp2_add(a[0], b[0]), fp2_add(a[1], b[1]), fp2_add(a[2], b[2]))


def fp6_sub(a: Fp6, b: Fp6) -> Fp6:
    return (fp2_sub(a[0], b[0]), fp2_sub(a[1], b[1]), fp2_sub(a[2], b[2]))


def fp6_neg(a: Fp6) -> Fp6:
    return (fp2_neg(a[0]), fp2_neg(a[1]), fp2_neg(a[2]))


def fp6_mul_by_nonresidue(a: Fp6) -> Fp6:
    c0, c1, c2 = a
    return (fp2_mul_by_nonresidue(c2), c0, c1)


def fp6_mul(a: Fp6, b: Fp6 | int) -> Fp6:
    if isinstance(b, int):
        return (fp2_mul(a[0], b), fp2_mul(a[1], b), fp2_mul(a[2], b))
    c0, c1, c2 = a
    r0, r1, r2 = b
    t0 = fp2_mul(c0, r0)
    t1 = fp2_mul(c1, r1)
    t2 = fp2_mul(c2, r2)
    o0 = fp2_add(t0, fp2_mul_by_nonresidue(fp2_sub(fp2_mul(fp2_add(c1, c2), fp2_add(r1, r2)), fp2_add(t1, t2))))
    o1 = fp2_add(
        fp2_sub(fp2_mul(fp2_add(c0, c1), fp2_add(r0, r1)), fp2_add(t0, t1)),
        fp2_mul_by_nonresidue(t2),
    )
    o2 = fp2_sub(fp2_add(t1, fp2_mul(fp2_add(c0, c2), fp2_add(r0, r2))), fp2_add(t0, t2))
    return (o0, o1, o2)


def fp6_sqr(a: Fp6) -> Fp6:
    c0, c1, c2 = a
    t0 = fp2_sqr(c0)
    t1 = fp2_mul(fp2_mul(c0, c1), 2)
    t3 = fp2_mul(fp2_mul(c1, c2), 2)
    t4 = fp2_sqr(c2)
    o0 = fp2_add(fp2_mul_by_nonresidue(t3), t0)
    o1 = fp2_add(fp2_mul_by_nonresidue(t4), t1)
    o2 = fp2_sub(fp2_sub(fp2_add(fp2_add(t1, fp2_sqr(fp2_add(fp2_sub(c0, c1), c2))), t3), t0), t4)
    return (o0, o1, o2)


def fp6_inv(a: Fp6) -> Fp6:
    c0, c1, c2 = a
    t0 = fp2_sub(fp2_sqr(c0), fp2_mul_by_nonresidue(fp2_mul(c2, c1)))
    t1 = fp2_sub(fp2_mul_by_nonresidue(fp2_sqr(c2)), fp2_mul(c0, c1))
    t2 = fp2_sub(fp2_sqr(c1), fp2_mul(c0, c2))
    t4 = fp2_inv(
        fp2_add(fp2_mul_by_nonresidue(fp2_add(fp2_mul(c2, t1), fp2_mul(c1, t2))), fp2_mul(c0, t0))
    )
    return (fp2_mul(t4, t0), fp2_mul(t4, t1), fp2_mul(t4, t2))


def fp6_mul_by_fp2(a: Fp6, rhs: Fp2) -> Fp6:
    c0, c1, c2 = a
    return (fp2_mul(c0, rhs), fp2_mul(c1, rhs), fp2_mul(c2, rhs))


def fp6_mul1(a: Fp6, b1: Fp2) -> Fp6:
    """Sparse multiplication by (0, b1, 0)."""
    c0, c1, c2 = a
    return (fp2_mul_by_nonresidue(fp2_mul(c2, b1)), fp2_mul(c0, b1), fp2_mul(c1, b1))


def fp6_mul01(a: Fp6, b0: Fp2, b1: Fp2) -> Fp6:
    """Sparse multiplication by (b0, b1, 0)."""
    c0, c1, c2 = a
    t0 = fp2_mul(c0, b0)
    t1 = fp2_mul(c1, b1)
    o0 = fp2_add(fp2_mul_by_nonresidue(fp2_sub(fp2_mul(fp2_add(c1, c2), b1), t1)), t0)
    o1 = fp2_sub(fp2_sub(fp2_mul(fp2_add(b0, b1), fp2_add(c0, c1)), t0), t1)
    o2 = fp2_add(fp2_sub(fp2_mul(fp2_add(c0, c2), b0), t0), t1)
    return (o0, o1, o2)


def fp6_eq(a: Fp6, b: Fp6) -> bool:
    return fp2_eq(a[0], b[0]) and fp2_eq(a[1], b[1]) and fp2_eq(a[2], b[2])


def fp6_to_bytes(a: Fp6) -> bytes:
    return fp2_to_bytes(a[0]) + fp2_to_bytes(a[1]) + fp2_to_bytes(a[2])


# == Fp12 tower: Fp12 = Fp6[w] / (w^2 - v) ====================================
# Element represented as (c0, c1) meaning c0 + c1*w.

Fp12 = tuple[Fp6, Fp6]

_FP6_ZERO3: Fp6 = (_FP6_ZERO, _FP6_ZERO, _FP6_ZERO)
_FP6_ONE3: Fp6 = (_FP6_ONE, _FP6_ZERO, _FP6_ZERO)

FP12_ZERO: Fp12 = (_FP6_ZERO3, _FP6_ZERO3)
FP12_ONE: Fp12 = (_FP6_ONE3, _FP6_ZERO3)


def fp12_add(a: Fp12, b: Fp12) -> Fp12:
    return (fp6_add(a[0], b[0]), fp6_add(a[1], b[1]))


def fp12_sub(a: Fp12, b: Fp12) -> Fp12:
    return (fp6_sub(a[0], b[0]), fp6_sub(a[1], b[1]))


def fp12_neg(a: Fp12) -> Fp12:
    return (fp6_neg(a[0]), fp6_neg(a[1]))


def fp12_mul(a: Fp12, b: Fp12 | int) -> Fp12:
    if isinstance(b, int):
        return (fp6_mul(a[0], b), fp6_mul(a[1], b))
    c0, c1 = a
    r0, r1 = b
    t1 = fp6_mul(c0, r0)
    t2 = fp6_mul(c1, r1)
    o0 = fp6_add(t1, fp6_mul_by_nonresidue(t2))
    o1 = fp6_sub(fp6_mul(fp6_add(c0, c1), fp6_add(r0, r1)), fp6_add(t1, t2))
    return (o0, o1)


def fp12_sqr(a: Fp12) -> Fp12:
    c0, c1 = a
    ab = fp6_mul(c0, c1)
    o0 = fp6_sub(
        fp6_sub(fp6_mul(fp6_add(fp6_mul_by_nonresidue(c1), c0), fp6_add(c0, c1)), ab),
        fp6_mul_by_nonresidue(ab),
    )
    o1 = fp6_add(ab, ab)
    return (o0, o1)


def fp12_inv(a: Fp12) -> Fp12:
    c0, c1 = a
    t = fp6_inv(fp6_sub(fp6_sqr(c0), fp6_mul_by_nonresidue(fp6_sqr(c1))))
    return (fp6_mul(c0, t), fp6_neg(fp6_mul(c1, t)))


def fp12_conjugate(a: Fp12) -> Fp12:
    c0, c1 = a
    return (c0, fp6_neg(c1))


def fp12_pow(a: Fp12, power: int) -> Fp12:
    result = FP12_ONE
    base = a
    e = power
    while e > 0:
        if e & 1:
            result = fp12_mul(result, base)
        base = fp12_sqr(base)
        e >>= 1
    return result


def fp12_eq(a: Fp12, b: Fp12) -> bool:
    return fp6_eq(a[0], b[0]) and fp6_eq(a[1], b[1])


def fp12_to_bytes(a: Fp12) -> bytes:
    return fp6_to_bytes(a[0]) + fp6_to_bytes(a[1])


def fp12_mul_by_fp2(a: Fp12, rhs: Fp2) -> Fp12:
    c0, c1 = a
    return (fp6_mul_by_fp2(c0, rhs), fp6_mul_by_fp2(c1, rhs))


# == Frobenius coefficients ====================================================
# Ported from noble's calcFrobeniusCoefficients (abstract/tower.js).


def fp2_pow(a: Fp2, power: int) -> Fp2:
    result: Fp2 = (1, 0)
    base = a
    e = power
    while e > 0:
        if e & 1:
            result = fp2_mul(result, base)
        base = fp2_sqr(base)
        e >>= 1
    return result


def _calc_frobenius_coefficients_fp(nonresidue: int, modulus: int, degree: int, divisor: int) -> list[int]:
    tower_modulus = modulus**degree
    powers = []
    q_power = 1
    a = 1
    for _ in range(degree):
        power = ((a * q_power - a) // divisor) % tower_modulus
        powers.append(fp_pow(nonresidue, power))
        q_power *= modulus
    return powers


def _calc_frobenius_coefficients_fp2(
    nonresidue: Fp2, modulus: int, degree: int, num: int, divisor: int
) -> list[list[Fp2]]:
    tower_modulus = modulus**degree
    result: list[list[Fp2]] = []
    for i in range(num):
        a = i + 1
        powers = []
        q_power = 1
        for _ in range(degree):
            power = ((a * q_power - a) // divisor) % tower_modulus
            powers.append(fp2_pow(nonresidue, power))
            q_power *= modulus
        result.append(powers)
    return result


_FP2_FROBENIUS_COEFFICIENTS = _calc_frobenius_coefficients_fp(_FP2_NONRESIDUE, P, 2, 2)

_FP6_NONRESIDUE: Fp2 = (1, 1)  # u + 1
_fp6_frob = _calc_frobenius_coefficients_fp2(_FP6_NONRESIDUE, P, 6, 2, 3)
_FP6_FROBENIUS_COEFFICIENTS_1 = _fp6_frob[0]
_FP6_FROBENIUS_COEFFICIENTS_2 = _fp6_frob[1]

_FP12_FROBENIUS_COEFFICIENTS = _calc_frobenius_coefficients_fp2(_FP6_NONRESIDUE, P, 12, 1, 6)[0]


def fp2_frobenius_map(a: Fp2, power: int) -> Fp2:
    c0, c1 = a
    return (c0, fp_mul(c1, _FP2_FROBENIUS_COEFFICIENTS[power % 2]))


def fp6_frobenius_map(a: Fp6, power: int) -> Fp6:
    c0, c1, c2 = a
    return (
        fp2_frobenius_map(c0, power),
        fp2_mul(fp2_frobenius_map(c1, power), _FP6_FROBENIUS_COEFFICIENTS_1[power % 6]),
        fp2_mul(fp2_frobenius_map(c2, power), _FP6_FROBENIUS_COEFFICIENTS_2[power % 6]),
    )


def fp12_frobenius_map(a: Fp12, power: int) -> Fp12:
    c0, c1 = a
    fc0, fc1, fc2 = fp6_frobenius_map(c1, power)
    coeff = _FP12_FROBENIUS_COEFFICIENTS[power % 12]
    new_c1: Fp6 = (fp2_mul(fc0, coeff), fp2_mul(fc1, coeff), fp2_mul(fc2, coeff))
    new_c0 = fp6_frobenius_map(c0, power)
    return (new_c0, new_c1)


# == Cyclotomic subgroup operations (used by final exponentiation) ===========
# Ported from noble's _Field12._cyclotomicSquare / _cyclotomicExp.

_BLS_X = 0xD201000000010000  # |x| for BLS12-381 (x itself is negative)
_BLS_X_LEN = _BLS_X.bit_length()


def _fp4_square(a: Fp2, b: Fp2) -> tuple[Fp2, Fp2]:
    a2 = fp2_sqr(a)
    b2 = fp2_sqr(b)
    first = fp2_add(fp2_mul_by_nonresidue(b2), a2)
    second = fp2_sub(fp2_sub(fp2_sqr(fp2_add(a, b)), a2), b2)
    return first, second


def _cyclotomic_square(a: Fp12) -> Fp12:
    c0, c1 = a
    c0c0, c0c1, c0c2 = c0
    c1c0, c1c1, c1c2 = c1
    t3, t4 = _fp4_square(c0c0, c1c1)
    t5, t6 = _fp4_square(c1c0, c0c2)
    t7, t8 = _fp4_square(c0c1, c1c2)
    t9 = fp2_mul_by_nonresidue(t8)

    new_c0: Fp6 = (
        fp2_add(fp2_mul(fp2_sub(t3, c0c0), 2), t3),
        fp2_add(fp2_mul(fp2_sub(t5, c0c1), 2), t5),
        fp2_add(fp2_mul(fp2_sub(t7, c0c2), 2), t7),
    )
    new_c1: Fp6 = (
        fp2_add(fp2_mul(fp2_add(t9, c1c0), 2), t9),
        fp2_add(fp2_mul(fp2_add(t4, c1c1), 2), t4),
        fp2_add(fp2_mul(fp2_add(t6, c1c2), 2), t6),
    )
    return (new_c0, new_c1)


def _cyclotomic_exp(a: Fp12, n: int) -> Fp12:
    z = FP12_ONE
    for i in range(_BLS_X_LEN - 1, -1, -1):
        z = _cyclotomic_square(z)
        if (n >> i) & 1:
            z = fp12_mul(z, a)
    return z


def final_exponentiate(num: Fp12) -> Fp12:
    """Ported from noble's Fp12finalExponentiate for BLS12-381."""
    x = _BLS_X
    t0 = fp12_mul(fp12_frobenius_map(num, 6), fp12_inv(num))  # this^(q^6) / this
    t1 = fp12_mul(fp12_frobenius_map(t0, 2), t0)  # t0^(q^2) * t0
    t2 = fp12_conjugate(_cyclotomic_exp(t1, x))
    t3 = fp12_mul(fp12_conjugate(_cyclotomic_square(t1)), t2)
    t4 = fp12_conjugate(_cyclotomic_exp(t3, x))
    t5 = fp12_conjugate(_cyclotomic_exp(t4, x))
    t6 = fp12_mul(fp12_conjugate(_cyclotomic_exp(t5, x)), _cyclotomic_square(t2))
    t7 = fp12_conjugate(_cyclotomic_exp(t6, x))
    t2_t5_pow_q2 = fp12_frobenius_map(fp12_mul(t2, t5), 2)
    t4_t1_pow_q3 = fp12_frobenius_map(fp12_mul(t4, t1), 3)
    t6_t1c_pow_q1 = fp12_frobenius_map(fp12_mul(t6, fp12_conjugate(t1)), 1)
    t7_t3c_t1 = fp12_mul(fp12_mul(t7, fp12_conjugate(t3)), t1)
    return fp12_mul(fp12_mul(fp12_mul(t2_t5_pow_q2, t4_t1_pow_q3), t6_t1c_pow_q1), t7_t3c_t1)


# == Sparse Fp12 multiplication (used by the Miller loop line functions) =====


def fp12_mul014(a: Fp12, o0: Fp2, o1: Fp2, o4: Fp2) -> Fp12:
    c0, c1 = a
    t0 = fp6_mul01(c0, o0, o1)
    t1 = fp6_mul1(c1, o4)
    new_c0 = fp6_add(fp6_mul_by_nonresidue(t1), t0)
    new_c1 = fp6_sub(fp6_sub(fp6_mul01(fp6_add(c1, c0), o0, fp2_add(o1, o4)), t0), t1)
    return (new_c0, new_c1)


def fp12_mul034(a: Fp12, o0: Fp2, o3: Fp2, o4: Fp2) -> Fp12:
    c0, c1 = a
    c0c0, c0c1, c0c2 = c0
    aa: Fp6 = (fp2_mul(c0c0, o0), fp2_mul(c0c1, o0), fp2_mul(c0c2, o0))
    bb = fp6_mul01(c1, o3, o4)
    ee = fp6_mul01(fp6_add(c0, c1), fp2_add(o0, o3), o4)
    new_c0 = fp6_add(fp6_mul_by_nonresidue(bb), aa)
    new_c1 = fp6_sub(ee, fp6_add(aa, bb))
    return (new_c0, new_c1)


# == Miller loop (Fp2-affine points, G1 affine points) ========================
# Ported from noble's createBlsPairing (abstract/bls.js): pointDouble,
# pointAdd, calcPairingPrecomputes, millerLoopBatch. twistType='multiplicative'
# for BLS12-381, so lineFunction uses mul014.

_ATE_LOOP_SIZE = _BLS_X  # BLS_X = 0xd201000000010000 (the ate loop size magnitude)


def _naf_decomposition(a: int) -> list[int]:
    """Non-adjacent form decomposition, matching noble's NAfDecomposition."""
    res: list[int] = []
    while a > 1:
        if a & 1 == 0:
            res.insert(0, 0)
        elif a & 3 == 3:
            res.insert(0, -1)
            a += 1
        else:
            res.insert(0, 1)
        a >>= 1
    return res


_ATE_NAF = _naf_decomposition(_ATE_LOOP_SIZE)

_FP2_DIV2 = fp2_mul((1, 0), fp_inv(2))


def _fp2_mul_by_b(a: Fp2) -> Fp2:
    """Fp2mulByB for BLS12-381: (c0,c1) -> (4*c0 - 4*c1, 4*c0 + 4*c1)."""
    c0, c1 = a
    t0 = fp_mul(c0, 4)
    t1 = fp_mul(c1, 4)
    return (fp_sub(t0, t1), fp_add(t0, t1))


def _point_double(rx: Fp2, ry: Fp2, rz: Fp2) -> tuple[Fp2, Fp2, Fp2, tuple[Fp2, Fp2, Fp2]]:
    t0 = fp2_sqr(ry)
    t1 = fp2_sqr(rz)
    # t2 = mulByB(3 * t1), per noble: const t2 = Fp2.mulByB(Fp2.mul(t1, _3n));
    t2 = _fp2_mul_by_b(fp2_mul(t1, 3))
    t3 = fp2_mul(t2, 3)
    t4 = fp2_sub(fp2_sub(fp2_sqr(fp2_add(ry, rz)), t1), t0)
    c0 = fp2_sub(t2, t0)
    c1 = fp2_mul(fp2_sqr(rx), 3)
    c2 = fp2_neg(t4)
    new_rx = fp2_mul(fp2_mul(fp2_mul(fp2_sub(t0, t3), rx), ry), _FP2_DIV2)
    new_ry = fp2_sub(fp2_sqr(fp2_mul(fp2_add(t0, t3), _FP2_DIV2)), fp2_mul(fp2_sqr(t2), 3))
    new_rz = fp2_mul(t0, t4)
    return new_rx, new_ry, new_rz, (c0, c1, c2)


def _point_add(
    rx: Fp2, ry: Fp2, rz: Fp2, qx: Fp2, qy: Fp2
) -> tuple[Fp2, Fp2, Fp2, tuple[Fp2, Fp2, Fp2]]:
    t0 = fp2_sub(ry, fp2_mul(qy, rz))
    t1 = fp2_sub(rx, fp2_mul(qx, rz))
    c0 = fp2_sub(fp2_mul(t0, qx), fp2_mul(t1, qy))
    c1 = fp2_neg(t0)
    c2 = t1
    t2 = fp2_sqr(t1)
    t3 = fp2_mul(t2, t1)
    t4 = fp2_mul(t2, rx)
    t5 = fp2_add(fp2_sub(t3, fp2_mul(t4, 2)), fp2_mul(fp2_sqr(t0), rz))
    new_rx = fp2_mul(t1, t5)
    new_ry = fp2_sub(fp2_mul(fp2_sub(t4, t5), t0), fp2_mul(t3, ry))
    new_rz = fp2_mul(rz, t3)
    return new_rx, new_ry, new_rz, (c0, c1, c2)


def _calc_pairing_precomputes(qx: Fp2, qy: Fp2) -> list[list[tuple[Fp2, Fp2, Fp2]]]:
    """Precompute the line-function coefficients for a fixed G2 point (Qx, Qy),
    matching noble's calcPairingPrecomputes (memoized per-point in JS; here
    we simply compute fresh each call, which is fine for our usage patterns).
    """
    neg_qy = fp2_neg(qy)
    rx, ry, rz = qx, qy, (1, 0)
    ell: list[list[tuple[Fp2, Fp2, Fp2]]] = []
    for bit in _ATE_NAF:
        cur: list[tuple[Fp2, Fp2, Fp2]] = []
        rx, ry, rz, coeffs = _point_double(rx, ry, rz)
        cur.append(coeffs)
        if bit:
            rx, ry, rz, coeffs2 = _point_add(rx, ry, rz, qx, neg_qy if bit == -1 else qy)
            cur.append(coeffs2)
        ell.append(cur)
    return ell


def _miller_loop_batch(
    pairs: list[tuple[list[list[tuple[Fp2, Fp2, Fp2]]], int, int]],
) -> Fp12:
    """pairs: list of (ell, Px, Py) where Px, Py are Fp (int) affine coords of
    the G1 point. Returns f12 (Fp12), BEFORE final exponentiation, matching
    noble's millerLoopBatch(pairs, withFinalExponent=False), including the
    xNegative conjugate step (BLS12-381's x is negative).
    """
    f12 = FP12_ONE
    if pairs:
        ell_len = len(pairs[0][0])
        for i in range(ell_len):
            f12 = fp12_sqr(f12)
            for ell, px, py in pairs:
                for c0, c1, c2 in ell[i]:
                    # twistType == 'multiplicative': mul014(f, c0, c1*Px, c2*Py)
                    f12 = fp12_mul014(f12, c0, fp2_mul(c1, px), fp2_mul(c2, py))
        # xNegative = True for BLS12-381
        f12 = fp12_conjugate(f12)
    return f12


def pairing(g1_affine: tuple[int, int], g2_affine: tuple[Fp2, Fp2]) -> Fp12:
    """Computes e(G1_point, G2_point) with final exponentiation applied,
    matching noble's `bls12_381.pairing(g1Point, g2Point)`. Both points must
    already be in affine coordinates: g1_affine=(x,y) with x,y as plain ints
    (Fp elements); g2_affine=(x,y) with x,y as Fp2 tuples.
    """
    px, py = g1_affine
    qx, qy = g2_affine
    ell = _calc_pairing_precomputes(qx, qy)
    f12 = _miller_loop_batch([(ell, px, py)])
    return final_exponentiate(f12)


# == Convenience: py_ecc Jacobian point -> affine coordinates for pairing() ===


def g1_jacobian_to_affine(pt) -> tuple[int, int]:
    """pt: a py_ecc.optimized_bls12_381 G1 Jacobian point (FQ, FQ, FQ)."""
    import py_ecc.optimized_bls12_381 as ob

    x, y = ob.normalize(pt)
    return (int(x), int(y))


def g2_jacobian_to_affine(pt) -> tuple[Fp2, Fp2]:
    """pt: a py_ecc.optimized_bls12_381 G2 Jacobian point (FQ2, FQ2, FQ2)."""
    import py_ecc.optimized_bls12_381 as ob

    x, y = ob.normalize(pt)
    return (
        (int(x.coeffs[0]), int(x.coeffs[1])),
        (int(y.coeffs[0]), int(y.coeffs[1])),
    )


def pairing_from_jacobian(g1_pt, g2_pt) -> Fp12:
    """e(g1_pt, g2_pt) where g1_pt/g2_pt are py_ecc Jacobian points."""
    return pairing(g1_jacobian_to_affine(g1_pt), g2_jacobian_to_affine(g2_pt))


# == Aptos Gt wire format ======================================================
# Aptos's on-chain Gt representation (bls12381_algebra.move) is noble's Fp12
# byte layout with each of the 12 constituent 48-byte Fp limbs individually
# byte-reversed (i.e. noble's per-limb big-endian becomes little-endian, in
# limb order). Mirrors bls12381GtReprNobleToAptos() in t-ibe/*.ts.


def fp12_to_aptos_gt_bytes(a: Fp12) -> bytes:
    noble_bytes = fp12_to_bytes(a)
    if len(noble_bytes) != 576:
        raise ValueError("expected 576 bytes")
    chunks = [noble_bytes[i : i + 48][::-1] for i in range(0, 576, 48)]
    return b"".join(chunks)
