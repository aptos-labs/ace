// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Mirrors `ts-sdk/src/group/bls12381g2.ts`: Feldman VSS types over BLS12-381 G2.

crate::group::curve_macro::define_bls12381_group!(
    ark_bls12_381::G2Projective,
    ark_bls12_381::G2Affine,
    96,
    "G2"
);
