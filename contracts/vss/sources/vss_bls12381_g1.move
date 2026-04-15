module ace::vss_bls12381_g1 {
    use aptos_std::bcs_stream::{Self, BCSStream};
    use aptos_std::crypto_algebra::{Self, Element};
    use aptos_std::bls12381_algebra::{G1, FormatG1Compr, Fr, FormatFrLsb};

    // ── Error codes ──────────────────────────────────────────────────────────

    const E_INVALID: u64 = 1;

    // ── Constants ────────────────────────────────────────────────────────────

    const G1_COMPRESSED_BYTES: u64 = 48;
    const FR_SCALAR_BYTES: u64 = 32;

    struct PrivateScalar has copy, drop, store {
        scalar: vector<u8>,
    }

    struct PublicPoint has copy, drop, store {
        point: vector<u8>,
    }

    public fun point_sum(pks: &vector<PublicPoint>): PublicPoint {
        let accumulator = crypto_algebra::zero<G1>();
        pks.for_each_ref(|pk| {
            accumulator = crypto_algebra::add(&accumulator, &to_inner_element(pk));
        });
        from_inner_element(&accumulator)
    }

    public fun point_eq(a: &PublicPoint, b: &PublicPoint): bool {
        crypto_algebra::eq(&to_inner_element(a), &to_inner_element(b))
    }

    public fun scale_point(point: &PublicPoint, scalar: &PrivateScalar): PublicPoint {
        from_inner_element(&crypto_algebra::scalar_mul(
            &to_inner_element(point),
            &to_inner_scalar(scalar),
        ))
    }

    public fun msm(points: vector<PublicPoint>, scalars: vector<PrivateScalar>): PublicPoint {
        let point = crypto_algebra::multi_scalar_mul<G1, Fr>(
            &points.map_ref(|p| to_inner_element(p)),
            &scalars.map_ref(|s| to_inner_scalar(s)),
        );
        from_inner_element(&point)
    }

    public fun scalar_mul(a: &PrivateScalar, b: &PrivateScalar): PrivateScalar {
        from_inner_scalar(&crypto_algebra::mul(&to_inner_scalar(a), &to_inner_scalar(b)))
    }

    public fun scalar_from_u64(x: u64): PrivateScalar {
        from_inner_scalar(&crypto_algebra::from_u64(x))
    }

    public fun deserialize_private_scalar(stream: &mut BCSStream): PrivateScalar {
        let scalar = deserialize_fr_scalar(stream);
        from_inner_scalar(&scalar)
    }

    public fun deserialize_public_point(stream: &mut BCSStream): PublicPoint {
        let point = deserialize_g1_point(stream);
        from_inner_element(&point)
    }
    
    fun to_inner_element(element: &PublicPoint): Element<G1> {
        crypto_algebra::deserialize<G1, FormatG1Compr>(&element.point).destroy_some()
    }

    fun to_inner_scalar(scalar: &PrivateScalar): Element<Fr> {
        crypto_algebra::deserialize<Fr, FormatFrLsb>(&scalar.scalar).destroy_some()
    }

    fun from_inner_element(element: &Element<G1>): PublicPoint {
        PublicPoint { point: crypto_algebra::serialize<G1, FormatG1Compr>(element) }
    }

    fun from_inner_scalar(scalar: &Element<Fr>): PrivateScalar {
        PrivateScalar { scalar: crypto_algebra::serialize<Fr, FormatFrLsb>(scalar) }
    }

    fun deserialize_bytes_field(stream: &mut BCSStream): vector<u8> {
        bcs_stream::deserialize_vector(stream, |s| bcs_stream::deserialize_u8(s))
    }

    fun deserialize_g1_point(stream: &mut BCSStream): Element<G1> {
        let bytes = deserialize_bytes_field(stream);
        let opt = crypto_algebra::deserialize<G1, FormatG1Compr>(&bytes);
        opt.destroy_some()
    }

    fun deserialize_fr_scalar(stream: &mut BCSStream): Element<Fr> {
        let bytes = deserialize_bytes_field(stream);
        let opt = crypto_algebra::deserialize<Fr, FormatFrLsb>(&bytes);
        opt.destroy_some()
    }
}
