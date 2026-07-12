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
    const E_UNSUPPORTED_DEGREE_CHECK_SIZE: u64 = 4;

    /// Degree-check lambda lookup supports ACE committees up to 64 workers.
    /// The PCS commitment then has points over {0, 1, ..., 64}.
    const MAX_DEGREE_CHECK_LAST_INDEX: u64 = 64;

    /// Bound each touch transaction while avoiding one transaction per point.
    const MAX_DEGREE_CHECK_POINTS_PER_TOUCH: u64 = 8;

    /// Little-endian BLS12-381 Fr encodings of F(t) = 1 / t!, for t = 0..64.
    const BLS12381_FR_FACTORIAL_INVERSES_LSB: vector<u8> = x"0100000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000001000080ffffff7fff2dff7f01d2dea902ecd00404ec9c19a4bece94a9d3f63901000080545555d5a94ca92aad081e1bafde06085c8905801193584dc5609b6001000060545555b52918a98a2dbd95c5af193b095dc46c86ba428cb2af15196fcdccccacddddddbd6e9eee4e3c8cb75a5638729b12f44881580d1c8a8937381623222272f9a44f4abc11d137b74ae7d412e899cc09b29195f53f5de4066a4f64987229c7d9a99d0ad1688a2cd37fa83574bbd291e2fcf4397b1910accecf2261532ee5383bb553211a4d9165fa0fb5866e573a529c9f3e672f0382d5f959240c43cc6ecdccbe2520c9768099e5e84a92f457964a8a4373557ee1b63c4982656807ae242e1493d09ce08dbf75b1fb5941cdfc25d729e11c4b22bcf478d3d8372dd30fecec00999e82138f9bad5820e3977438226222f01f1eb96ba576ea08806d520169fe14e237e0eb9c21f95d9c8cef0bf4308c5bc3dad782123adb20b16d399162f43a6311534c11d0d92631be0da8b63f2ac4d2c5412847f53aaa97c2826679e2ec711838984e0052a0b9e1a555fe9128d0cd28b24c69da053b0ed84df872f7ec31a101482cf4ee7cd7838682d2ee3c8bb80d58836b6dec889dab5227aa07d01e138a7fc4425f8e8b3c186ad407ce36924606ba41a763076f22f29350b041c1f2d3bc52cfe550087703983325939812d93a4ced6a3a63b9e0a10177f0ae0a61c60b6ef5a745f69ba4feeb136402f4be02558d86358f600711f30a0ed6146e2e911b6427678ae4b641c94f5396160c1a23516afdb98eb1ecdd64deae09b53c43c767ab2785a03e15eac810537a9fa15ebfdb181f3a89f997afd9c1cf682f54046ba3a625fa5c1b7a0cfc0cb110de632dc41f525d1f66f8d330df675906db61811093878cc5b2d2617a7e2396126b3d4cc528ba2db21c58d045221b48664c63fb1697960583f14b89f2734fc5775c2eb8f33f18546d1fa47cf6c20b5b3acd40f6a09b5b1f102a83ef0f4e83d5c98900d7f11a349541a9b339ed918f2c2a2368b8e74d74e20a91bd13b62180273ed78bf41abc7d81adec7b6e653b653194700d9b9cdb2b1c9485381426b2d3da801640e33285e9c1e9f83781b4e1b4ed04451be0df8c27692b930b0ae3d6074bd75c1ba1ae94bee2be7244d930d03d056b7a16b675202fb18ad75bd27dd964fa119e4687686a404132391a8a25626033d8ec21f5a2e6594cea2138f5ce70385924c0d232672f29d94ad12eeb918e62b784242df88d65e945ffde01c36a24469fe1fd6b755fb534caa2545ad128bd28041bd7697480ea93e09cb494c31d00faa3a2e5c538a7fa495e8817a87fbd8ca8b1e8344e04549fa4e6a4a5bc6d63cf3f964a96c53b86ecf5456d7610e774dfbc04c6ea2da45f33de6ab7ce6221ff3a380fa995eac8cd6d9cd3f352cd732f69833989ce712bdd5bd9be5f51ecf8fb1efa72811d15e370e0b6c6b546bfc7d230e5da98b8407ec44b65f6aa7ee9ae18a1ccac429bf83b3b9c267ecf1a1400cee5520562883304a9255886f65f3f3d52ae851422e337fd4255a28ee32b1a2476aaba2948653be5e8b4e610e4936292d5a9a9dfbe1e2a9bc180d2e51f6ee683e211faf80667438d2e2d50caf1e8e0fc72c762728319c4ade0587a7ac13f77cad28a5a64ff3a1d741b2f0fafd18fbdd79abb4a9c78d2f88bec8287096f50c9860604fc30cde55c4afa2dada3cb567e11f1a9ced2353d07549054dd65804a4fdc576ea30ee77853d031b610235621d1da0687111213cc95fcb83277cbf0672248dc9ce4954300137993d35b31cb8066e089f061501b3885d63746cec9a02856eed910fd7eec0d1c3f1bed9c71286efccee5d4ba0f9b943fa3b7110b7b07f158cfc17edf5601244cce7a62498d0c31970938262743ffd6c3a507ddd478491ee66ad04fbd662dc16dbb022a8a74d817bf93627df557a4da0100e069be607505fc7206547a93f03b2e47bd9c6102f4fa9f88b13f53a9a77a1d70b6dd1bc6eb8823c5180962bc77a51264457043efb8779628aa628f92cf8dbed338062b49192de1f86e201a96ca3134c85612bcd9d3779835195178ff93d1848734d98b8bae92a2648b7ca3d355b644b674bc18774db9856ecc838f6e2779a2235e718db1edbf3b0cd3c1d5e750862223cfda0f3ac931ee9058779c988d715237ba64ef92d1d1c566d4442ef276e24a5c4f09ba8c9fa6ff1f5a978ab0f53f7f51f11531a1c95471564a397e2cb7d970fda3e2efe90c4dece2cff8ee7e7b199ef3a045cca6c2fb4e2ab7c0cd435d0114e3412165e7097fcabbfddddddbfee09b2645efb66d6c150dd811182c7d8ac004be77cc27f5f1d2ddea5c072a499ef2a84cc5208c97a9a654a4af6485524048696135c76be3c798ab3b14f6333f9368405c86be4c30088d01576fc2f42be29b36f520c8386cbaa2a724367ea54868ae059036f9532d0be97608ddab081756d5720029b79049fac35c2d208db649846fb6b20f3a39416db5921213cccd5c0263189254fa9cdd340cd1b9ef97d2e75043adf70c46b98cc3f386bced1ad4ce4f652851a63cbd3b0571b5f5e91ba457b3edacaf2771b0b7f61359cf4e9e40ad8dce31b5f1af8bc06a4ac7e586cc138708d5ecde6135360fa1dead9fe8efb50e74ff3496e6edcffec63742d1e5133b241417cd3671a749befc07edc5b566a46416f91145b5ff9703bd5baabce42ce81a59452694f9cd9a93f37c85ea8dc6acb0b51f3cf1068288288d87371b0a6671a3275c6b913a6e2024e5b9a8adb84083300d5b131c082266341ede30b835c5410fe34d858ba7c3723676a4a23feccd3f6c1f791b";

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

    struct DegreeCheckState has copy, drop, store {
        z_poly: vector<group::Scalar>,
        accumulator: group::Element,
        next_eval_position: u64,
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

    public fun public_params_from_generators(generator_g: group::Element, generator_h: group::Element): PublicParams {
        assert!(
            group::element_scheme(&generator_g) == group::element_scheme(&generator_h),
            error::invalid_argument(E_INCONSISTENT_SCHEME),
        );
        PublicParams { generator_g, generator_h }
    }

    public fun public_params_from_bytes(bytes: vector<u8>): PublicParams {
        let stream = bcs_stream::new(bytes);
        let params = deserialize_public_params(&mut stream);
        assert!(!bcs_stream::has_remaining(&mut stream), error::invalid_argument(E_INVALID_DIMENSIONS));
        params
    }

    public fun deserialize_public_params(stream: &mut BCSStream): PublicParams {
        public_params_from_generators(
            group::deserialize_element(stream),
            group::deserialize_element(stream),
        )
    }

    public fun commitment_len(commitment: &Commitment): u64 {
        let raw_len = commitment.points.length();
        if (raw_len == 0) 0 else raw_len - 1
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
        if (n - 1 > MAX_DEGREE_CHECK_LAST_INDEX) return false;

        let state = degree_check_start(context, commitment, d);
        while (!degree_check_finished(commitment, &state)) {
            degree_check_touch(context, commitment, &mut state);
        };
        degree_check_accepts(context, commitment, &state)
    }

    public fun empty_degree_check_state(context: &PublicParams): DegreeCheckState {
        DegreeCheckState {
            z_poly: vector[],
            accumulator: group::identity(context_scheme(context)),
            next_eval_position: 0,
        }
    }

    #[lint::allow_unsafe_randomness]
    public fun degree_check_start(
        context: &PublicParams,
        commitment: &Commitment,
        d: u64,
    ): DegreeCheckState {
        let n = commitment.points.length();
        assert!(n > 1, error::invalid_argument(E_INVALID_DIMENSIONS));
        assert!(n - 1 <= MAX_DEGREE_CHECK_LAST_INDEX, error::invalid_argument(E_UNSUPPORTED_DEGREE_CHECK_SIZE));
        let scheme = context_scheme(context);
        assert!(elements_have_scheme(&commitment.points, scheme), error::invalid_argument(E_INCONSISTENT_SCHEME));

        let z_poly = if (d + 1 >= n) {
            vector[]
        } else {
            random_poly(scheme, n - d - 1)
        };
        DegreeCheckState {
            z_poly,
            accumulator: group::identity(scheme),
            next_eval_position: if (d + 1 >= n) n else 0,
        }
    }

    public fun degree_check_finished(commitment: &Commitment, state: &DegreeCheckState): bool {
        state.next_eval_position >= commitment.points.length()
    }

    public fun degree_check_touch(
        context: &PublicParams,
        commitment: &Commitment,
        state: &mut DegreeCheckState,
    ): bool {
        let n = commitment.points.length();
        if (state.next_eval_position >= n) return true;
        assert!(n > 1, error::invalid_argument(E_INVALID_DIMENSIONS));
        assert!(n - 1 <= MAX_DEGREE_CHECK_LAST_INDEX, error::invalid_argument(E_UNSUPPORTED_DEGREE_CHECK_SIZE));
        assert!(state.z_poly.length() > 0, error::invalid_argument(E_INVALID_DIMENSIONS));

        let scheme = context_scheme(context);
        assert!(elements_have_scheme(&commitment.points, scheme), error::invalid_argument(E_INCONSISTENT_SCHEME));
        assert!(group::element_scheme(&state.accumulator) == scheme, error::invalid_argument(E_INCONSISTENT_SCHEME));
        assert_poly_scheme(&state.z_poly, scheme);

        let points = vector[];
        let scalars = vector[];
        let processed = 0;
        while (state.next_eval_position < n && processed < MAX_DEGREE_CHECK_POINTS_PER_TOUCH) {
            let eval_position = state.next_eval_position;
            let x = group::scalar_from_u64(scheme, eval_position);
            let z_i = eval_poly(&state.z_poly, &x);
            let lambda_i = lagrange_denominator_inverse(scheme, eval_position, n);
            scalars.push_back(group::scalar_mul(&z_i, &lambda_i));
            points.push_back(commitment.points[eval_position]);
            state.next_eval_position = eval_position + 1;
            processed = processed + 1;
        };
        state.accumulator = group::element_add(
            &state.accumulator,
            &group::msm(points, scalars),
        );
        state.next_eval_position >= n
    }

    public fun degree_check_accepts(
        context: &PublicParams,
        commitment: &Commitment,
        state: &DegreeCheckState,
    ): bool {
        let scheme = context_scheme(context);
        degree_check_finished(commitment, state)
            && group::element_scheme(&state.accumulator) == scheme
            && group::element_eq(&state.accumulator, &group::identity(scheme))
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

    /// For domain {0, ..., last}, lambda_k = 1 / prod_{j != k}(k - j).
    /// Since prod_{j != k}(k - j) = k! * (-1)^{last-k} * (last-k)!,
    /// lambda_k = (-1)^{last-k} * F(k) * F(last-k), where F(t) = 1 / t!.
    fun lagrange_denominator_inverse(scheme: u8, i: u64, n: u64): group::Scalar {
        assert!(n > 0 && i < n, error::invalid_argument(E_INVALID_EVALUATION_POSITION));
        let last = n - 1;
        let lambda = group::scalar_mul(
            &factorial_inverse(scheme, i),
            &factorial_inverse(scheme, last - i),
        );
        if ((last - i) % 2 == 1) {
            group::scalar_neg(&lambda)
        } else {
            lambda
        }
    }

    fun factorial_inverse(scheme: u8, t: u64): group::Scalar {
        assert!(t <= MAX_DEGREE_CHECK_LAST_INDEX, error::invalid_argument(E_UNSUPPORTED_DEGREE_CHECK_SIZE));
        let start = t * 32;
        group::scalar_from_lsb_bytes(
            scheme,
            BLS12381_FR_FACTORIAL_INVERSES_LSB.slice(start, start + 32),
        )
    }

    #[test_only]
    fun lagrange_denominator_inverse_slow(scheme: u8, i: u64, n: u64): group::Scalar {
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
    fun degree_check_state_round_trip(framework: signer) {
        randomness::initialize_for_testing(&framework);
        let scheme = group::scheme_bls12381_g1();
        let context = new_context(scheme);
        let prover_state = ProverState {
            poly_p: vector[
                group::scalar_from_u64(scheme, 7),
                group::scalar_from_u64(scheme, 11),
                group::scalar_from_u64(scheme, 13),
            ],
            poly_r: vector[],
        };
        let commitment = commit(&context, &mut prover_state, 8);
        let state = degree_check_start(&context, &commitment, 2);
        let touched = 0;
        while (!degree_check_finished(&commitment, &state)) {
            assert!(!degree_check_accepts(&context, &commitment, &state), 0);
            degree_check_touch(&context, &commitment, &mut state);
            touched = touched + 1;
        };
        let expected_touches = (commitment.points.length() + MAX_DEGREE_CHECK_POINTS_PER_TOUCH - 1)
            / MAX_DEGREE_CHECK_POINTS_PER_TOUCH;
        assert!(touched == expected_touches, 1);
        assert!(degree_check_accepts(&context, &commitment, &state), 2);
    }

    #[test]
    fun lagrange_table_matches_direct_computation() {
        assert_lagrange_table_matches_direct_computation(group::scheme_bls12381_g1());
        assert_lagrange_table_matches_direct_computation(group::scheme_bls12381_g2());
    }

    #[test_only]
    fun assert_lagrange_table_matches_direct_computation(scheme: u8) {
        range(2, 12).for_each(|n| {
            range(0, n).for_each(|i| {
                let fast = lagrange_denominator_inverse(scheme, i, n);
                let slow = lagrange_denominator_inverse_slow(scheme, i, n);
                assert!(group::scalar_eq(&fast, &slow), 1000 + n * 100 + i);
            });
        });
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
