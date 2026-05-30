module ace::pedersen_polynomial_commitment {
    use std::bcs;
    use std::error;
    use std::vector::range;
    use aptos_std::bcs_stream::{Self, BCSStream};
    use ace::group;
    #[test_only]
    use aptos_framework::randomness;

    const E_INVALID_DIMENSIONS: u64 = 1;
    const E_INCONSISTENT_SCHEME: u64 = 2;
    const E_INVALID_EVALUATION_POSITION: u64 = 3;

    /// Public parameters pp = (G, F, g, h) from Appendix A.2.
    ///
    /// `generator_g` and `generator_h` must be independent generators in the same
    /// group. This module can check same-scheme consistency, but it cannot check
    /// that nobody knows log_g(h).
    struct PublicParams has copy, drop, store {
        generator_g: group::Element,
        generator_h: group::Element,
    }

    /// Pedersen polynomial commitment over the ACE domain {0, 1, ..., n}.
    ///
    /// points[0] = p(0) * g + r(0) * h.
    /// points[i] = p(i) * g + r(i) * h for worker positions i in {1, ..., n}.
    struct Commitment has copy, drop, store {
        points: vector<group::Element>,
    }

    /// Opening at one evaluation position i.
    ///
    /// In the paper's notation, `eval_value_p` is u = p(i), and
    /// `eval_value_r` is pi = r(i).
    struct Opening has copy, drop, store {
        eval_position: u64,
        eval_value_p: group::Scalar,
        eval_value_r: group::Scalar,
    }

    /// Batch opening for a set I of evaluation positions.
    struct BatchOpening has copy, drop, store {
        eval_positions: vector<u64>,
        eval_values_p: vector<group::Scalar>,
        eval_values_r: vector<group::Scalar>,
    }

    /// Test-only prover state. Production dealers should compute commitments and
    /// openings off-chain and submit the resulting public data.
    struct ProverState has copy, drop, store {
        poly_p: vector<group::Scalar>,
        poly_r: vector<group::Scalar>,
    }

    #[lint::allow_unsafe_randomness]
    public fun new_context(scheme: u8): PublicParams {
        PublicParams {
            generator_g: group::rand_element(scheme),
            generator_h: group::rand_element(scheme),
        }
    }

    public fun commitment_len(commitment: &Commitment): u64 {
        let raw_len = commitment.points.length();
        if (raw_len == 0) 0 else raw_len - 1
    }

    public fun new_context_from_generators(generator_g: group::Element, generator_h: group::Element): PublicParams {
        assert!(
            group::element_scheme(&generator_g) == group::element_scheme(&generator_h),
            error::invalid_argument(E_INCONSISTENT_SCHEME),
        );
        PublicParams { generator_g, generator_h }
    }

    public fun commitment_from_points(points: vector<group::Element>): Commitment {
        assert!(points.length() > 1, error::invalid_argument(E_INVALID_DIMENSIONS));
        let scheme = group::element_scheme(&points[0]);
        assert!(elements_have_scheme(&points, scheme), error::invalid_argument(E_INCONSISTENT_SCHEME));
        Commitment { points }
    }

    public fun commitment_points(commitment: &Commitment): vector<group::Element> {
        commitment.points
    }

    public fun degree_check_num_points(commitment: &Commitment): u64 {
        commitment.points.length()
    }

    public fun commitment_point(commitment: &Commitment, eval_position: u64): group::Element {
        assert!(
            valid_commitment_position(commitment, eval_position),
            error::invalid_argument(E_INVALID_EVALUATION_POSITION),
        );
        commitment.points[eval_position]
    }

    public fun worker_commitment_point(commitment: &Commitment, worker_position: u64): group::Element {
        assert!(
            valid_position(commitment, worker_position),
            error::invalid_argument(E_INVALID_EVALUATION_POSITION),
        );
        commitment.points[worker_position]
    }

    public fun generator_g(context: &PublicParams): group::Element {
        context.generator_g
    }

    public fun generator_h(context: &PublicParams): group::Element {
        context.generator_h
    }

    public fun deserialize_commitment(stream: &mut BCSStream): Commitment {
        let points = bcs_stream::deserialize_vector(stream, |s| group::deserialize_element(s));
        commitment_from_points(points)
    }

    public fun deserialize_opening(stream: &mut BCSStream): Opening {
        Opening {
            eval_position: bcs_stream::deserialize_u64(stream),
            eval_value_p: group::deserialize_scalar(stream),
            eval_value_r: group::deserialize_scalar(stream),
        }
    }

    public fun opening_eval_position(opening: &Opening): u64 {
        opening.eval_position
    }

    public fun opening_eval_value_p(opening: &Opening): group::Scalar {
        opening.eval_value_p
    }

    #[test_only]
    public fun new_prover_state(poly_p: vector<group::Scalar>, poly_r: vector<group::Scalar>): ProverState {
        ProverState { poly_p, poly_r }
    }

    #[lint::allow_unsafe_randomness]
    #[test_only]
    public fun commit(context: &PublicParams, prover_state: &mut ProverState, n: u64): Commitment {
        assert!(n > 0 && prover_state.poly_p.length() > 0, error::invalid_argument(E_INVALID_DIMENSIONS));
        let scheme = context_scheme(context);
        assert_poly_scheme(&prover_state.poly_p, scheme);
        if (prover_state.poly_r.length() == 0) {
            prover_state.poly_r = random_poly(scheme, prover_state.poly_p.length());
        } else {
            assert!(
                prover_state.poly_r.length() == prover_state.poly_p.length(),
                error::invalid_argument(E_INVALID_DIMENSIONS),
            );
            assert_poly_scheme(&prover_state.poly_r, scheme);
        };

        let points = vector[];
        range(0, n + 1).for_each(|i| {
            let x = group::scalar_from_u64(scheme, i);
            let p_i = eval_poly(&prover_state.poly_p, &x);
            let r_i = eval_poly(&prover_state.poly_r, &x);
            points.push_back(commit_value(context, &p_i, &r_i));
        });
        Commitment { points }
    }

    // SCRAPE-style low-degree check from Appendix A.2 / Figure 7.
    //
    // For N commitment points over x = 0..N-1 and degree bound d, sample a random
    // polynomial z with deg(z) <= N - d - 2 and check:
    //
    //     sum_i z(i) * lambda_i * V_i == 0_G
    //
    // where lambda_i = 1 / prod_{j != i}(i - j).
    //
    // Since this consumes Aptos on-chain randomness, any production entry function
    // that calls it must be a private entry annotated with `#[randomness]`.
    #[lint::allow_unsafe_randomness]
    public fun degree_check(context: &PublicParams, commitment: &Commitment, d: u64): bool {
        let n = commitment.points.length();
        if (n <= 1) return false;
        let scheme = context_scheme(context);
        if (!elements_have_scheme(&commitment.points, scheme)) return false;
        if (d + 1 >= n) return true;

        let z_degree = n - d - 2;
        let z_poly = random_poly(scheme, z_degree + 1);
        let scalars = range(0, n).map(|i| {
            let x = group::scalar_from_u64(scheme, i);
            let z_i = eval_poly(&z_poly, &x);
            let lambda_i = lagrange_denominator_inverse(scheme, i, n);
            group::scalar_mul(&z_i, &lambda_i)
        });
        let check = group::msm(commitment.points, scalars);
        group::element_eq(&check, &group::identity(scheme))
    }

    #[lint::allow_unsafe_randomness]
    public fun degree_check_z_poly(context: &PublicParams, commitment: &Commitment, d: u64): vector<group::Scalar> {
        let n = commitment.points.length();
        assert!(n > 1, error::invalid_argument(E_INVALID_DIMENSIONS));
        let scheme = context_scheme(context);
        assert!(elements_have_scheme(&commitment.points, scheme), error::invalid_argument(E_INCONSISTENT_SCHEME));
        if (d + 1 >= n) {
            vector[]
        } else {
            random_poly(scheme, n - d - 1)
        }
    }

    public fun degree_check_initial_accumulator(context: &PublicParams): group::Element {
        group::identity(context_scheme(context))
    }

    public fun degree_check_step(
        context: &PublicParams,
        commitment: &Commitment,
        z_poly: &vector<group::Scalar>,
        eval_position: u64,
        accumulator: &group::Element,
    ): group::Element {
        let n = commitment.points.length();
        assert!(eval_position < n, error::invalid_argument(E_INVALID_EVALUATION_POSITION));
        assert!(z_poly.length() > 0, error::invalid_argument(E_INVALID_DIMENSIONS));
        let scheme = context_scheme(context);
        assert!(elements_have_scheme(&commitment.points, scheme), error::invalid_argument(E_INCONSISTENT_SCHEME));
        assert!(group::element_scheme(accumulator) == scheme, error::invalid_argument(E_INCONSISTENT_SCHEME));

        let x = group::scalar_from_u64(scheme, eval_position);
        let z_i = eval_poly(z_poly, &x);
        let lambda_i = lagrange_denominator_inverse(scheme, eval_position, n);
        let scalar = group::scalar_mul(&z_i, &lambda_i);
        group::element_add(accumulator, &group::scale_element(&commitment.points[eval_position], &scalar))
    }

    public fun degree_check_accepts(context: &PublicParams, accumulator: &group::Element): bool {
        let scheme = context_scheme(context);
        group::element_scheme(accumulator) == scheme && group::element_eq(accumulator, &group::identity(scheme))
    }

    #[test_only]
    public fun open(context: &PublicParams, prover_state: &ProverState, eval_position: u64): Opening {
        assert!(eval_position > 0, error::invalid_argument(E_INVALID_EVALUATION_POSITION));
        let scheme = context_scheme(context);
        assert_poly_scheme(&prover_state.poly_p, scheme);
        assert_poly_scheme(&prover_state.poly_r, scheme);
        assert!(
            prover_state.poly_p.length() == prover_state.poly_r.length(),
            error::invalid_argument(E_INVALID_DIMENSIONS),
        );
        let x = group::scalar_from_u64(scheme, eval_position);
        Opening {
            eval_position,
            eval_value_p: eval_poly(&prover_state.poly_p, &x),
            eval_value_r: eval_poly(&prover_state.poly_r, &x),
        }
    }

    public fun verify(
        context: &PublicParams,
        commitment: &Commitment,
        opening: &Opening,
    ): bool {
        if (!valid_position(commitment, opening.eval_position)) return false;
        let scheme = context_scheme(context);
        if (!elements_have_scheme(&commitment.points, scheme)) return false;
        if (group::scalar_scheme(&opening.eval_value_p) != scheme) return false;
        if (group::scalar_scheme(&opening.eval_value_r) != scheme) return false;

        let expected = commit_value(context, &opening.eval_value_p, &opening.eval_value_r);
        group::element_eq(&commitment.points[opening.eval_position], &expected)
    }

    #[test_only]
    public fun batch_open(
        context: &PublicParams,
        prover_state: &ProverState,
        eval_positions: &vector<u64>,
    ): BatchOpening {
        let eval_values_p = vector[];
        let eval_values_r = vector[];
        eval_positions.for_each_ref(|pos| {
            let opening = open(context, prover_state, *pos);
            eval_values_p.push_back(opening.eval_value_p);
            eval_values_r.push_back(opening.eval_value_r);
        });
        BatchOpening { eval_positions: *eval_positions, eval_values_p, eval_values_r }
    }

    /// Batched verification from Figure 8, with verifier randomness derived by
    /// Fiat-Shamir from the context, commitment, and claimed openings.
    public fun batch_verify(
        context: &PublicParams,
        commitment: &Commitment,
        openings: &BatchOpening,
    ): bool {
        let k = openings.eval_positions.length();
        if (k == 0) return false;
        if (openings.eval_values_p.length() != k || openings.eval_values_r.length() != k) return false;
        if (has_duplicate_positions(&openings.eval_positions)) return false;

        let scheme = context_scheme(context);
        if (!elements_have_scheme(&commitment.points, scheme)) return false;
        if (!scalars_have_scheme(&openings.eval_values_p, scheme)) return false;
        if (!scalars_have_scheme(&openings.eval_values_r, scheme)) return false;
        if (!openings.eval_positions.all(|pos| valid_position(commitment, *pos))) return false;

        let gammas = derive_batch_gammas(context, commitment, openings);
        let points = openings.eval_positions.map_ref(|pos| commitment.points[*pos]);
        let claimed_points = range(0, k).map(|i| {
            commit_value(context, &openings.eval_values_p[i], &openings.eval_values_r[i])
        });
        let neg_gammas = gammas.map_ref(|gamma| group::scalar_neg(gamma));
        let scalars = gammas;
        points.append(claimed_points);
        scalars.append(neg_gammas);

        let check = group::msm(points, scalars);
        group::element_eq(&check, &group::identity(scheme))
    }

    fun context_scheme(context: &PublicParams): u8 {
        let scheme = group::element_scheme(&context.generator_g);
        assert!(
            scheme == group::element_scheme(&context.generator_h),
            error::invalid_argument(E_INCONSISTENT_SCHEME),
        );
        scheme
    }

    fun commit_value(context: &PublicParams, p: &group::Scalar, r: &group::Scalar): group::Element {
        group::element_add(
            &group::scale_element(&context.generator_g, p),
            &group::scale_element(&context.generator_h, r),
        )
    }

    fun eval_poly(poly: &vector<group::Scalar>, x: &group::Scalar): group::Scalar {
        let scheme = group::scalar_scheme(x);
        assert!(poly.length() > 0, error::invalid_argument(E_INVALID_DIMENSIONS));
        let result = group::scalar_from_u64(scheme, 0);
        let power = group::scalar_from_u64(scheme, 1);
        poly.for_each_ref(|coef| {
            result = group::scalar_add(&result, &group::scalar_mul(coef, &power));
            power = group::scalar_mul(&power, x);
        });
        result
    }

    fun random_poly(scheme: u8, len: u64): vector<group::Scalar> {
        range(0, len).map(|_| group::rand_scalar(scheme))
    }

    fun lagrange_denominator_inverse(scheme: u8, i: u64, n: u64): group::Scalar {
        let x_i = group::scalar_from_u64(scheme, i);
        let denominator = group::scalar_from_u64(scheme, 1);
        range(0, n).for_each(|j| {
            if (j != i) {
                let x_j = group::scalar_from_u64(scheme, j);
                denominator = group::scalar_mul(
                    &denominator,
                    &group::scalar_add(&x_i, &group::scalar_neg(&x_j)),
                );
            }
        });
        group::scalar_inv(&denominator)
    }

    fun derive_batch_gammas(
        context: &PublicParams,
        commitment: &Commitment,
        openings: &BatchOpening,
    ): vector<group::Scalar> {
        let scheme = context_scheme(context);
        let seed = b"ace::pedersen-polynomial-commitment::batch-verify-v1";
        seed.append(bcs::to_bytes(context));
        seed.append(bcs::to_bytes(commitment));
        seed.append(bcs::to_bytes(openings));
        range(0, openings.eval_positions.length()).map(|idx| {
            let msg = seed;
            msg.append(bcs::to_bytes(&idx));
            group::hash_to_scalar(scheme, msg)
        })
    }

    fun valid_position(commitment: &Commitment, eval_position: u64): bool {
        eval_position > 0 && valid_commitment_position(commitment, eval_position)
    }

    fun valid_commitment_position(commitment: &Commitment, eval_position: u64): bool {
        commitment.points.length() > 0 && eval_position < commitment.points.length()
    }

    fun has_duplicate_positions(positions: &vector<u64>): bool {
        range(0, positions.length()).any(|i| {
            range(*i + 1, positions.length()).any(|j| positions[*i] == positions[*j])
        })
    }

    fun elements_have_scheme(elements: &vector<group::Element>, scheme: u8): bool {
        elements.length() > 0 && elements.map_ref(|e| group::element_scheme(e)).all(|s| *s == scheme)
    }

    fun scalars_have_scheme(scalars: &vector<group::Scalar>, scheme: u8): bool {
        scalars.length() > 0 && scalars.map_ref(|s| group::scalar_scheme(s)).all(|s| *s == scheme)
    }

    fun assert_poly_scheme(poly: &vector<group::Scalar>, scheme: u8) {
        assert!(scalars_have_scheme(poly, scheme), error::invalid_argument(E_INCONSISTENT_SCHEME));
    }

    #[test(framework = @0x1)]
    fun single_opening_round_trip(framework: signer) {
        randomness::initialize_for_testing(&framework);
        let scheme = group::scheme_bls12381_g1();
        let context = new_context(scheme);
        let prover_state = ProverState {
            poly_p: vector[
                group::scalar_from_u64(scheme, 7),
                group::scalar_from_u64(scheme, 3),
                group::scalar_from_u64(scheme, 2),
            ],
            poly_r: vector[],
        };
        let commitment = commit(&context, &mut prover_state, 8);
        assert!(degree_check(&context, &commitment, 2), 0);
        let opening = open(&context, &prover_state, 4);
        assert!(verify(&context, &commitment, &opening), 1);
    }

    #[test(framework = @0x1)]
    fun single_opening_wrong_value_fails(framework: signer) {
        randomness::initialize_for_testing(&framework);
        let scheme = group::scheme_bls12381_g1();
        let context = new_context(scheme);
        let prover_state = ProverState {
            poly_p: vector[group::scalar_from_u64(scheme, 1), group::scalar_from_u64(scheme, 2)],
            poly_r: vector[],
        };
        let commitment = commit(&context, &mut prover_state, 5);
        let opening = open(&context, &prover_state, 2);
        opening.eval_value_p = group::scalar_add(&opening.eval_value_p, &group::scalar_from_u64(scheme, 1));
        assert!(!verify(&context, &commitment, &opening), 0);
    }

    #[test(framework = @0x1)]
    fun batch_opening_round_trip(framework: signer) {
        randomness::initialize_for_testing(&framework);
        let scheme = group::scheme_bls12381_g1();
        let context = new_context(scheme);
        let prover_state = ProverState {
            poly_p: vector[
                group::scalar_from_u64(scheme, 5),
                group::scalar_from_u64(scheme, 8),
                group::scalar_from_u64(scheme, 13),
            ],
            poly_r: vector[],
        };
        let commitment = commit(&context, &mut prover_state, 7);
        let openings = batch_open(&context, &prover_state, &vector[1, 3, 7]);
        assert!(batch_verify(&context, &commitment, &openings), 0);
    }

    #[test(framework = @0x1)]
    fun batch_opening_wrong_value_fails(framework: signer) {
        randomness::initialize_for_testing(&framework);
        let scheme = group::scheme_bls12381_g1();
        let context = new_context(scheme);
        let prover_state = ProverState {
            poly_p: vector[group::scalar_from_u64(scheme, 9), group::scalar_from_u64(scheme, 4)],
            poly_r: vector[],
        };
        let commitment = commit(&context, &mut prover_state, 6);
        let openings = batch_open(&context, &prover_state, &vector[2, 5]);
        openings.eval_values_p[1] = group::scalar_add(&openings.eval_values_p[1], &group::scalar_from_u64(scheme, 1));
        assert!(!batch_verify(&context, &commitment, &openings), 0);
    }

    #[test(framework = @0x1)]
    fun degree_check_rejects_higher_degree_commitment(framework: signer) {
        randomness::initialize_for_testing(&framework);
        let scheme = group::scheme_bls12381_g1();
        let context = new_context(scheme);
        let prover_state = ProverState {
            poly_p: vector[
                group::scalar_from_u64(scheme, 1),
                group::scalar_from_u64(scheme, 2),
                group::scalar_from_u64(scheme, 3),
            ],
            poly_r: vector[
                group::scalar_from_u64(scheme, 4),
                group::scalar_from_u64(scheme, 5),
                group::scalar_from_u64(scheme, 6),
            ],
        };
        let commitment = commit(&context, &mut prover_state, 6);
        assert!(!degree_check(&context, &commitment, 1), 0);
    }

    #[test(framework = @0x1)]
    fun batch_opening_rejects_duplicate_positions(framework: signer) {
        randomness::initialize_for_testing(&framework);
        let scheme = group::scheme_bls12381_g1();
        let context = new_context(scheme);
        let prover_state = ProverState {
            poly_p: vector[group::scalar_from_u64(scheme, 1), group::scalar_from_u64(scheme, 2)],
            poly_r: vector[],
        };
        let commitment = commit(&context, &mut prover_state, 4);
        let openings = batch_open(&context, &prover_state, &vector[2, 2]);
        assert!(!batch_verify(&context, &commitment, &openings), 0);
    }

    #[test(framework = @0x1)]
    fun accessors_expose_generators_and_points(framework: signer) {
        randomness::initialize_for_testing(&framework);
        let scheme = group::scheme_bls12381_g1();
        let context = new_context(scheme);
        let prover_state = ProverState {
            poly_p: vector[group::scalar_from_u64(scheme, 3), group::scalar_from_u64(scheme, 4)],
            poly_r: vector[],
        };
        let commitment = commit(&context, &mut prover_state, 3);

        assert!(commitment_len(&commitment) == 3, 0);
        assert!(group::element_eq(&commitment_point(&commitment, 0), &commitment.points[0]), 1);
        assert!(group::element_eq(&commitment_point(&commitment, 2), &commitment.points[2]), 2);
        assert!(group::element_eq(&worker_commitment_point(&commitment, 2), &commitment.points[2]), 3);

        let g = generator_g(&context);
        let h = generator_h(&context);
        assert!(group::element_eq(&g, &context.generator_g), 4);
        assert!(group::element_eq(&h, &context.generator_h), 5);
    }
}
