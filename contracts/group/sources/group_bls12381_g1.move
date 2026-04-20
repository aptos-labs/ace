module ace::group_bls12381_g1 {
    use aptos_std::aptos_hash;
    use aptos_std::bcs_stream::{Self, BCSStream};
    use aptos_std::crypto_algebra::{Self, Element};
    use aptos_std::bls12381_algebra::{G1, FormatG1Compr, Fr, FormatFrLsb, HashG1XmdSha256SswuRo};
    use aptos_framework::randomness;

    // ── Error codes ──────────────────────────────────────────────────────────

    const E_INVALID: u64 = 1;

    // ── Constants ────────────────────────────────────────────────────────────

    const G1_COMPRESSED_BYTES: u64 = 48;
    const FR_SCALAR_BYTES: u64 = 32;
    const DST: vector<u8> = b"ace::group_bls12381_g1";

    // r = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    const FR_ORDER: u256 = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001;
    // 2^256 mod r (= pow(2, 256, r))
    const TWO_256_MOD_FR: u256 = 0x1824b159acc5056f998c4fefecbc4ff55884b7fa0003480200000001fffffffe;

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

    public fun scalar_add(a: &PrivateScalar, b: &PrivateScalar): PrivateScalar {
        from_inner_scalar(&crypto_algebra::add(&to_inner_scalar(a), &to_inner_scalar(b)))
    }

    public fun scalar_mul(a: &PrivateScalar, b: &PrivateScalar): PrivateScalar {
        from_inner_scalar(&crypto_algebra::mul(&to_inner_scalar(a), &to_inner_scalar(b)))
    }

    public fun scalar_neg(a: &PrivateScalar): PrivateScalar {
        from_inner_scalar(&crypto_algebra::neg(&to_inner_scalar(a)))
    }

    public fun scalar_inv(a: &PrivateScalar): PrivateScalar {
        from_inner_scalar(&crypto_algebra::inv(&to_inner_scalar(a)).destroy_some())
    }

    public fun scalar_eq(a: &PrivateScalar, b: &PrivateScalar): bool {
        crypto_algebra::eq(&to_inner_scalar(a), &to_inner_scalar(b))
    }

    public fun element_add(a: &PublicPoint, b: &PublicPoint): PublicPoint {
        from_inner_element(&crypto_algebra::add(&to_inner_element(a), &to_inner_element(b)))
    }

    #[lint::allow_unsafe_randomness]
    public fun rand_scalar(): PrivateScalar {
        hash_to_scalar(&randomness::bytes(64))
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

    #[lint::allow_unsafe_randomness]
    public fun rand_element(): PublicPoint {
        from_inner_element(&crypto_algebra::hash_to<G1, HashG1XmdSha256SswuRo>(&DST, &randomness::bytes(32)))
    }

    public fun element_from_hash(msg: &vector<u8>): PublicPoint {
        from_inner_element(&crypto_algebra::hash_to<G1, HashG1XmdSha256SswuRo>(&DST, msg))
    }

    /// Hash arbitrary bytes to a BLS12-381 Fr scalar via SHA2-512.
    /// The 512-bit digest is split into (hi_256 || lo_256):
    ///   lo contribution = lo_256 % r  (direct u256 mod)
    ///   hi contribution = hi_256 * 2^256 mod r  (left-to-right binary method, 256 iters)
    /// No overflow: r < 2^255 guarantees acc*2 < 2^256 and acc+R < 2^256 at every step.
    public fun hash_to_scalar(msg: &vector<u8>): PrivateScalar {
        let hash = aptos_hash::sha2_512(*msg);

        let hi: u256 = 0;
        let lo: u256 = 0;
        let i = 0u64;
        while (i < 32) {
            hi = (hi << 8) | (*hash.borrow(i) as u256);
            lo = (lo << 8) | (*hash.borrow(i + 32) as u256);
            i = i + 1;
        };

        let lo_mod = lo % FR_ORDER;

        let hi_cont: u256 = 0;
        let j = 255u64;
        loop {
            hi_cont = (hi_cont * 2) % FR_ORDER;
            if (((hi >> (j as u8)) & 1u256) == 1u256) {
                hi_cont = (hi_cont + TWO_256_MOD_FR) % FR_ORDER;
            };
            if (j == 0) { break; };
            j = j - 1;
        };

        let result = (lo_mod + hi_cont) % FR_ORDER;
        let bytes = vector[];
        let k = 0u64;
        while (k < 32) {
            bytes.push_back(((result >> ((8 * k) as u8)) & 0xffu256) as u8);
            k = k + 1;
        };
        PrivateScalar { scalar: bytes }
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
