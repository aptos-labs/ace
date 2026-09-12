// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Mirrors `ts-sdk/src/group/bls12381g1.ts`: Feldman VSS types over BLS12-381 G1.

crate::group::curve_macro::define_bls12381_group!(
    ark_bls12_381::G1Projective,
    ark_bls12_381::G1Affine,
    48,
    "G1"
);
