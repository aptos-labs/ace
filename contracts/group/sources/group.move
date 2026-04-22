// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/// Abstract group layer: scheme-dispatched `Scalar` and `Element` types,
/// arithmetic, and BCS serialization.
///
/// Supported schemes:
///   0 = BLS12-381 G1 (with Fr scalars)
module ace::group {
    use std::error;
    use aptos_std::bcs_stream::{Self, BCSStream};
    use ace::group_bls12381_g1;

    // ── Error codes ──────────────────────────────────────────────────────────

    const E_UNSUPPORTED_SCHEME: u64 = 1;
    const E_INVALID_MSM: u64 = 2;
    const E_INVALID_ELEMENT_SUM: u64 = 3;

    // ── Scheme constants ─────────────────────────────────────────────────────

    const SCHEME__BLS12381G1: u8 = 0;

    // ── Types ────────────────────────────────────────────────────────────────

    enum Scalar has copy, drop, store {
        Bls12381G1(group_bls12381_g1::PrivateScalar),
    }

    enum Element has copy, drop, store {
        Bls12381G1(group_bls12381_g1::PublicPoint),
    }

    // ── Scheme accessors ─────────────────────────────────────────────────────

    public fun scalar_scheme(s: &Scalar): u8 {
        match (s) {
            Scalar::Bls12381G1(_) => SCHEME__BLS12381G1,
        }
    }

    public fun element_scheme(e: &Element): u8 {
        match (e) {
            Element::Bls12381G1(_) => SCHEME__BLS12381G1,
        }
    }

    // ── Serde ────────────────────────────────────────────────────────────────

    public fun element_from_bytes(bytes: vector<u8>): Element {
        let stream = bcs_stream::new(bytes);
        deserialize_element(&mut stream)
    }

    public fun deserialize_scalar(stream: &mut BCSStream): Scalar {
        let scheme = bcs_stream::deserialize_u8(stream);
        if (scheme == SCHEME__BLS12381G1) {
            let inner = group_bls12381_g1::deserialize_private_scalar(stream);
            Scalar::Bls12381G1(inner)
        } else {
            abort error::invalid_argument(E_UNSUPPORTED_SCHEME)
        }
    }

    public fun deserialize_element(stream: &mut BCSStream): Element {
        let scheme = bcs_stream::deserialize_u8(stream);
        if (scheme == SCHEME__BLS12381G1) {
            let inner = group_bls12381_g1::deserialize_public_point(stream);
            Element::Bls12381G1(inner)
        } else {
            abort error::invalid_argument(E_UNSUPPORTED_SCHEME)
        }
    }

    // ── Arithmetic ───────────────────────────────────────────────────────────

    public fun element_sum(elements: &vector<Element>): Element {
        assert!(elements.length() > 0, error::invalid_argument(E_INVALID_ELEMENT_SUM));
        let scheme = element_scheme(&elements[0]);
        assert!(elements.all(|e| element_scheme(e) == scheme), error::invalid_argument(E_UNSUPPORTED_SCHEME));
        if (scheme == SCHEME__BLS12381G1) {
            let inner = group_bls12381_g1::point_sum(&elements.map_ref(|e| *to_bls12381g1_element(e)));
            Element::Bls12381G1(inner)
        } else {
            abort error::invalid_argument(E_UNSUPPORTED_SCHEME)
        }
    }

    public fun element_add(a: &Element, b: &Element): Element {
        let scheme = element_scheme(a);
        assert!(scheme == element_scheme(b), error::invalid_argument(E_UNSUPPORTED_SCHEME));
        if (scheme == SCHEME__BLS12381G1) {
            Element::Bls12381G1(group_bls12381_g1::element_add(
                to_bls12381g1_element(a),
                to_bls12381g1_element(b),
            ))
        } else {
            abort error::invalid_argument(E_UNSUPPORTED_SCHEME)
        }
    }

    public fun element_eq(a: &Element, b: &Element): bool {
        let scheme = element_scheme(a);
        assert!(scheme == element_scheme(b), error::invalid_argument(E_UNSUPPORTED_SCHEME));
        if (scheme == SCHEME__BLS12381G1) {
            group_bls12381_g1::point_eq(to_bls12381g1_element(a), to_bls12381g1_element(b))
        } else {
            abort error::invalid_argument(E_UNSUPPORTED_SCHEME)
        }
    }

    public fun scale_element(element: &Element, scalar: &Scalar): Element {
        let scheme = element_scheme(element);
        assert!(scheme == scalar_scheme(scalar), error::invalid_argument(E_UNSUPPORTED_SCHEME));
        if (scheme == SCHEME__BLS12381G1) {
            Element::Bls12381G1(group_bls12381_g1::scale_point(
                to_bls12381g1_element(element),
                to_bls12381g1_scalar(scalar),
            ))
        } else {
            abort error::invalid_argument(E_UNSUPPORTED_SCHEME)
        }
    }

    public fun scalar_add(a: &Scalar, b: &Scalar): Scalar {
        let scheme = scalar_scheme(a);
        assert!(scheme == scalar_scheme(b), error::invalid_argument(E_UNSUPPORTED_SCHEME));
        if (scheme == SCHEME__BLS12381G1) {
            Scalar::Bls12381G1(group_bls12381_g1::scalar_add(
                to_bls12381g1_scalar(a),
                to_bls12381g1_scalar(b),
            ))
        } else {
            abort error::invalid_argument(E_UNSUPPORTED_SCHEME)
        }
    }

    public fun scalar_mul(a: &Scalar, b: &Scalar): Scalar {
        let scheme = scalar_scheme(a);
        assert!(scheme == scalar_scheme(b), error::invalid_argument(E_UNSUPPORTED_SCHEME));
        if (scheme == SCHEME__BLS12381G1) {
            let inner = group_bls12381_g1::scalar_mul(
                to_bls12381g1_scalar(a),
                to_bls12381g1_scalar(b),
            );
            Scalar::Bls12381G1(inner)
        } else {
            abort error::invalid_argument(E_UNSUPPORTED_SCHEME)
        }
    }

    public fun scalar_neg(a: &Scalar): Scalar {
        if (scalar_scheme(a) == SCHEME__BLS12381G1) {
            Scalar::Bls12381G1(group_bls12381_g1::scalar_neg(to_bls12381g1_scalar(a)))
        } else {
            abort error::invalid_argument(E_UNSUPPORTED_SCHEME)
        }
    }

    public fun scalar_inv(a: &Scalar): Scalar {
        if (scalar_scheme(a) == SCHEME__BLS12381G1) {
            Scalar::Bls12381G1(group_bls12381_g1::scalar_inv(to_bls12381g1_scalar(a)))
        } else {
            abort error::invalid_argument(E_UNSUPPORTED_SCHEME)
        }
    }

    public fun scalar_eq(a: &Scalar, b: &Scalar): bool {
        let scheme = scalar_scheme(a);
        assert!(scheme == scalar_scheme(b), error::invalid_argument(E_UNSUPPORTED_SCHEME));
        if (scheme == SCHEME__BLS12381G1) {
            group_bls12381_g1::scalar_eq(to_bls12381g1_scalar(a), to_bls12381g1_scalar(b))
        } else {
            abort error::invalid_argument(E_UNSUPPORTED_SCHEME)
        }
    }

    public fun scalar_from_u64(scheme: u8, x: u64): Scalar {
        if (scheme == SCHEME__BLS12381G1) {
            Scalar::Bls12381G1(group_bls12381_g1::scalar_from_u64(x))
        } else {
            abort error::invalid_argument(E_UNSUPPORTED_SCHEME)
        }
    }

    public fun msm(elements: vector<Element>, scalars: vector<Scalar>): Element {
        let size = elements.length();
        assert!(size == scalars.length(), error::invalid_argument(E_INVALID_MSM));
        assert!(size > 0, error::invalid_argument(E_INVALID_MSM));
        let element_schemes = elements.map_ref(|e| element_scheme(e));
        let scalar_schemes = scalars.map_ref(|s| scalar_scheme(s));
        let scheme = element_schemes[0];
        assert!(element_schemes.all(|s| *s == scheme), error::invalid_argument(E_UNSUPPORTED_SCHEME));
        assert!(scalar_schemes.all(|s| *s == scheme), error::invalid_argument(E_UNSUPPORTED_SCHEME));

        if (scheme == SCHEME__BLS12381G1) {
            let inner = group_bls12381_g1::msm(
                elements.map_ref(|e| *to_bls12381g1_element(e)),
                scalars.map_ref(|s| *to_bls12381g1_scalar(s)),
            );
            Element::Bls12381G1(inner)
        } else {
            abort error::invalid_argument(E_UNSUPPORTED_SCHEME)
        }
    }

    public fun scheme_bls12381_g1(): u8 { SCHEME__BLS12381G1 }

    public fun hash_to_scalar(scheme: u8, msg: vector<u8>): Scalar {
        if (scheme == SCHEME__BLS12381G1) {
            Scalar::Bls12381G1(group_bls12381_g1::hash_to_scalar(&msg))
        } else {
            abort error::invalid_argument(E_UNSUPPORTED_SCHEME)
        }
    }

    #[lint::allow_unsafe_randomness]
    public fun rand_scalar(scheme: u8): Scalar {
        if (scheme == SCHEME__BLS12381G1) {
            Scalar::Bls12381G1(group_bls12381_g1::rand_scalar())
        } else {
            abort error::invalid_argument(E_UNSUPPORTED_SCHEME)
        }
    }

    #[lint::allow_unsafe_randomness]
    public fun rand_element(scheme: u8): Element {
        if (scheme == SCHEME__BLS12381G1) {
            Element::Bls12381G1(group_bls12381_g1::rand_element())
        } else {
            abort error::invalid_argument(E_UNSUPPORTED_SCHEME)
        }
    }

    public fun element_from_hash(scheme: u8, msg: &vector<u8>): Element {
        if (scheme == SCHEME__BLS12381G1) {
            Element::Bls12381G1(group_bls12381_g1::element_from_hash(msg))
        } else {
            abort error::invalid_argument(E_UNSUPPORTED_SCHEME)
        }
    }

    // ── Private unwrap helpers ───────────────────────────────────────────────

    fun to_bls12381g1_scalar(s: &Scalar): &group_bls12381_g1::PrivateScalar {
        match (s) {
            Scalar::Bls12381G1(inner) => inner,
        }
    }

    fun to_bls12381g1_element(e: &Element): &group_bls12381_g1::PublicPoint {
        match (e) {
            Element::Bls12381G1(inner) => inner,
        }
    }
}
