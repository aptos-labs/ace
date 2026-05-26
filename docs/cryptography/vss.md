# Verifiable Secret Sharing (VSS)

ACE uses a Feldman-style polynomial commitment scheme (PCS) over an abstract `group::Element` (BLS12-381 G1 or G2). The core building block is a single dealer-driven VSS session; [`dkg.md`](./dkg.md) composes `n` VSS sessions in parallel, [`dkr.md`](./dkr.md) composes them with a resharing-dealer challenge.

## 1. Origin and modifications

ACE's VSS implements the **synchronous VSS** of Algorithm 1, §5 in:

> Sourav Das, Zhuolun Xiang, Alin Tomescu, Alexander Spiegelman, Benny Pinkas, Ling Ren. **"Verifiable Secret Sharing Simplified."** IACR ePrint 2023/1196. <https://eprint.iacr.org/2023/1196>

The paper presents a publicly-verifiable, complete, t-resilient VSS for `n ≥ 2t+1` synchronous nodes assuming a polynomial commitment scheme `PC`, signatures, and a Byzantine broadcast channel. ACE preserves the protocol skeleton — single-round dealer share-out, ACK collection, second-round reveal of unacked shares — and inherits the paper's correctness, completeness, and termination properties modulo the modifications below. The *secrecy* property is the one place where ACE diverges from the paper meaningfully; the replacement is **Theorem 1** in §4 below.

The asynchronous variant (Algorithm 2) and the dual-threshold extension (§7) are NOT adapted; ACE relies on synchrony.

**Modifications relative to Algorithm 1.** Auditors should re-check the security argument against each:

1. **Polynomial commitment scheme = Feldman.** The paper's `PC` is generic; its formal hiding requirement (§4.2 of the paper) is satisfied by the Pedersen-style PCS in their Appendix A.2 (`v_k = g^{a_k} · h^{r_k}`). ACE pins `PC` to **Feldman commitments over BLS12-381 G1 or G2** (the dealer publishes `v_k = a_k · basePoint`, no `h`-blinding). Consequence: `PC.Open` is trivial — the share `y_i` *is* the witness, and `PC.Verify` is the equation `y_i · basePoint == Σ_k (i+1)^k · v_k`. The paper's `PC.BatchOpen` collapses to "publish the missing scalar shares directly". See §2 below.

    **Security argument: computational reduction, not hiding-based simulation.** Feldman is *not* a hiding commitment — `v_0 = s · basePoint` publicly determines `g^s`. So paper's information-theoretic Lemma 1 (App. C) does NOT carry over: paper's simulator uses the Pedersen blinding factor `r(·)` to "rebind" the commitment to any candidate secret, which has no Feldman analogue. We instead prove **Theorem 1 (§4)** — a game-based reduction showing that any PPT adversary's chance of recovering the secret from the sharing-phase view is bounded by `Adv_DLog + n · Adv_PKE-IND-CPA + 1/|Fr|`. The game samples `s ←$ Fr` uniformly; auditors should verify that every VSS call site supplies a uniformly random secret (see §3 for the two ACE derivations, both uniform).

    **Why not Pedersen (the paper's choice).** Adopting Pedersen would force `v_0 = s · basePoint + r_0 · H`, which deliberately hides `g^s` from any public observer. ACE's DKR resharing-soundness check (see [`dkr.md`](./dkr.md), `vss.move:201`) is `element_eq(v_0, s_j · B_old)` — a one-line group equality against the *publicly pre-published* `s_j · B_old` carried over from the parent committee's DKG. That check requires `v_0` to *equal* `g^{s_j}`, not to be a Pedersen commitment that hides it. With Pedersen we would need either an additional NIZK proof of opening (more transcript, more verification cost, no extra real safety beyond what `element_eq` already provides) or to publish `r_0` (which destroys hiding for `coefs[0]` and brings us back to Feldman for that coefficient anyway). Since ACE applications (DKG output `g^{MSK}` and DKR's pre-published `g^{s_j}`) make `g^s` public anyway, the hiding property buys nothing operational. Feldman is the natural fit.

2. **Private authenticated channel = PKE.** The paper assumes private authenticated channels between dealer and each node. ACE realizes this by **PKE-encrypting each share to the recipient's registered `pke_enc_key`**, with the resulting ciphertext riding the public broadcast channel. Confidentiality reduces to PKE security ([`pke.md`](./pke.md)). The auth side is provided by the chain layer: the share ciphertext is bound to the dealer's account by virtue of the `on_dealer_contribution_0` signed transaction.

3. **Byzantine broadcast channel = the L1 chain.** Total ordering, immutability, and authentication of the transcript come from the Aptos L1 (Aptos's BFT consensus replaces the abstract `BB` channel). Trust assumption shifts from "broadcast channel exists" to "Aptos validator quorum is honest". Documented in [`../trust-model.md`](../trust-model.md) §5.

4. **Signed `ACK` = on-chain transaction.** The paper has nodes send `⟨ACK, σ_i⟩` over the broadcast channel, where `σ_i = sign(sk_i, v)`. ACE has them call `on_share_holder_ack(session_addr)` on-chain; the Aptos transaction signature *is* `σ_i`, and the chain naturally rejects `(t)` ACKs from any node that already ACKed. The authenticated-tally property the paper needs is provided by the L1.

5. **Selective reveal of missing shares.** The paper's second round does `(s, π) := PC.BatchOpen(p, I, w)` and broadcasts `(v, I, σ, s, π)`. ACE's equivalent reveals only the scalar shares of non-ackers as a vector of optional scalars (one slot per holder; `None` if they acked, `Some(y_j)` otherwise). With Feldman the proof drops out (modification 1), so the second-round message carries scalars only — the verifier (an on-chain incremental computation) re-runs the Feldman MSM check on each revealed share.

6. **Lazy `touch()` progression.** Move's per-transaction gas budget forces splitting the second-round verification across multiple `touch()` calls (one share-PK MSM per call). The paper's protocol is single-shot. This is a realization detail, not a security modification — `touch()` only ratchets state forward and is monotonic.

7. **Resharing-dealer challenge.** ACE adds an *optional* challenge $(P, H)$ plus a Sigma-DLog-Eq proof (see [`sigma-dlog-eq.md`](./sigma-dlog-eq.md)) that pins the dealer's polynomial constant term $a_0$ to a previously-known share $s_j$ (where $P = s_j \cdot B_{\text{old}}$ from the parent DKG/DKR, and $H$ is an independent base derived from $P$). Used by Distributed Key Resharing (see [`dkr.md`](./dkr.md)) to prevent a dealer from substituting a fresh secret. **This is outside the paper's scope.** Audit hook: the soundness of resharing reduces to the soundness of Sigma-DLog-Eq.

8. **Dealer-state crash recovery.** ACE encrypts the dealer's own polynomial coefficients to itself (via PKE) so a crashed dealer can resume. Not in the paper. Encrypted with the dealer's own `pke_enc_key`; no other recipient ever decrypts it. Pure operational add-on; doesn't affect any security claim.

9. **Single threshold only.** ACE uses `secrecy threshold = reconstruction threshold = t`; the paper's dual-threshold variant (`ℓ ∈ [t, n-t]`) and the verifiable-encryption-of-Pedersen-commitment scheme of §7 are NOT used.

10. **Synchrony bound.** The paper's $2\Delta$ round timer becomes ACE's `ACK_WINDOW_MICROS = 10s` (`vss.move:47`). The chain's clock (`timestamp::now_microseconds`) provides $\Delta$-monotonicity; honest dealers and honest nodes are assumed to submit their next-round transactions within that window. Audit hook: under chain-level liveness pauses (Aptos BFT halt), the timer can lapse without genuine asynchrony being the cause; this is a *liveness* concern, not a *safety* concern (a halt cannot manufacture false ACKs).

## 2. Polynomial commitment

Given a polynomial `f(x) = a_0 + a_1·x + … + a_{t-1}·x^{t-1}` over `Fr`, the dealer publishes a commitment vector
```
v_k = a_k · basePoint ∈ G   for k = 0..t-1
```
where `basePoint` is the `public_base_element` of the VSS session. Verifying a share `y_i = f(i+1)` against the commitment amounts to checking
```
y_i · basePoint == Σ_{k=0}^{t-1} ((i+1)^k mod r) · v_k
```
(Multi-scalar multiplication on-chain.) Implemented in `worker-components/vss-common/src/vss_types.rs::feldman_verify` (Rust) and `contracts/vss/sources/vss.move::touch` (Move).

## 3. Share derivation

VSS shares are encrypted to recipients with the per-recipient PKE encryption key registered in `worker_config`. Each recipient's plaintext is a single `Fr` scalar serialized as `[scheme_byte u8][ULEB128(32) = 0x20][32B y_LE]`.

The dealer's polynomial coefficients are **deterministically derived** from its PKE decryption key:
```
a_0 := if secret_override.is_some() { Fr::from_le_bytes_mod_order(secret_override) } else { fr_from_dk_bytes(pke_dk_bytes, 0) }
a_k := fr_from_dk_bytes(pke_dk_bytes, k)    for k = 1..t-1
where
  fr_from_dk_bytes(dk, idx) := Fr::from_le_bytes_mod_order(SHA3-256("vss-coef-v1/" || dk || LE64(idx)))
```
(Source: `worker-components/vss-common/src/crypto.rs::fr_from_dk_bytes` + `worker-components/vss-dealer/src/lib.rs:198-208`.)

Both call paths supply a uniform `Fr` secret (required by **Theorem 1**, §4 below):
- `fr_from_dk_bytes(pke_dk_bytes, 0)` — derived from a freshly-generated PKE decryption key (uniform `Fr` at node init).
- `secret_override` — documented contract is "a DKG/DKR share", a Lagrange evaluation of a uniform-random DKG polynomial, itself uniform in `Fr`.

**Audit note.** Determinism is intentional: it lets a dealer recover its own contribution after a crash, and lets failed recipients have their share revealed by `on_dealer_open` without re-running the whole VSS. The downside is that **anyone who learns a dealer's PKE decryption key learns every secret that dealer has ever contributed to**. The `worker-config` registration step therefore commits the dealer to a single PKE key per `account_addr` for the duration of its membership.

## 4. Sharing-phase secrecy theorem

Replacing the paper's Pedersen PCS with Feldman (§1 modification 1) requires a new security argument: paper's Lemma 1 leans on the Pedersen blinding `r(·)` to absorb arbitrary secret choices, which has no Feldman analogue. We state the resulting Feldman-based secrecy as a game-based reduction to DLog and PKE IND-CPA.

**Game `VSS-OW`** (one-wayness of the sharing-phase secret).

```
1. A picks corruption set J ⊆ [n] with |J| ≤ t.
2. Challenger generates (sk_i, dk_i, pk_i, ek_i) for each i ∈ [n];
   hands (sk_j, dk_j) for j ∈ J to A; publishes all (pk_i, ek_i).
3. Challenger samples s ←$ Fr uniformly.
4. Challenger plays the honest dealer with secret s and runs the full
   sharing phase (including round-2 reveal of any non-ACKed share).
   A controls the corrupted parties' protocol behaviour.
5. A outputs s' ∈ Fr.
6. A wins iff s' = s.
```

Define `Adv_VSS-OW(A) := Pr[A wins]`.

**Theorem 1 (Sharing-phase one-wayness).** Assuming

- (H1) `n ≥ 2t + 1`; polynomial degree `t`; reconstruction threshold `t + 1`;
- (H2) DLog is hard in the BLS12-381 group (`G1` or `G2`, whichever the session uses);
- (H3) the PKE scheme that encrypts shares ([`pke.md`](./pke.md)) is IND-CPA-secure;
- (H4) the signature scheme used for ACK messages is EUF-CMA-secure;
- (H5) the Aptos L1 provides Byzantine broadcast and monotonic timestamps within the `ACK_WINDOW_MICROS` bound;
- (H6) static corruption: `|J| ≤ t` and the dealer `L ∉ J`;

for any PPT adversary `A` there exist PPT algorithms `B` (DLog solver) and `C` (PKE IND-CPA distinguisher) such that

```
Adv_VSS-OW(A)  ≤  Adv_DLog(B)  +  n · Adv_IND-CPA(C)  +  1/|Fr|.
```

In particular, under (H2)+(H3), `Adv_VSS-OW(A) ≤ negl(κ)`.

**Reduction sketch (`B`'s construction).** On DLog challenge `(g, P)` where the goal is to recover `x` with `P = g^x`:

1. Accept `A`'s corruption set `J`. Generate all node keys honestly and hand `(sk_j, dk_j)_{j ∈ J}` to `A`.
2. Set `v_0 := P` (i.e., implicitly let the latent secret be `s = log_g P`, unknown to `B`).
3. Sample `{y_j : j ∈ J} ←$ Fr` uniformly — these will play the role of the corrupted parties' shares.
4. Sample `t − |J|` uniformly random group elements `u_h ←$ G` for "honest-holder placeholder" evaluations at fresh free indices outside `J ∪ {0}`.
5. Compute `v_1, ..., v_t` via Lagrange interpolation **in the exponent** over the `t + 1` group points `(v_0, {g^{y_j}}_{j ∈ J}, {u_h})`, using inverse-Vandermonde coefficients.
6. Encrypt `0` under each honest holder's `ek_i` (dummy ciphertext); encrypt `y_j` under each corrupted holder's `ek_j` (so `A`'s decryption recovers the prepared `y_j`).
7. Publish `(v_0, ..., v_t)` and the ciphertexts as the dealer's first-round contribution on the simulated chain.
8. Sign ACK messages on behalf of each honest holder using its real signing key. For any corrupted holder `A` chooses not to ACK, perform the round-2 reveal by publishing `y_j`; on-chain Feldman verification accepts because `v` was constructed to satisfy `g^{y_j} = MSM(v, powers_of_(j+1))` by step 5.
9. `A` outputs `s'`. `B` outputs `s'` as its DLog answer.

**Correctness.** The view `B` presents to `A` is computationally indistinguishable from the real `VSS-OW` game conditioned on `s = log_g P`. Two ingredients carry the argument:

- *PKE step (computational gap, `n · Adv_IND-CPA`).* The only real-vs-simulated mismatch is that honest holders' ciphertexts are `Enc(ek_i, 0)` in `B`'s simulation but `Enc(ek_i, real y_i)` in the real game. A hybrid over the `≤ n` honest holders bridges this by IND-CPA; the corrupted holders' decryption keys do not leak the honest holders' plaintexts because `A` does not hold `(sk_i, dk_i)` for `i ∉ J`.
- *Commitment-vector distribution (perfect equality).* Conditional on `(s, {y_j}_{j ∈ J})`, the real dealer's polynomial `a(·)` is uniform over the `(t − |J|)`-dimensional affine subspace of degree-`t` polynomials with `a(0) = s` and `a(j+1) = y_j` for `j ∈ J`. Therefore `a(i_h + 1)` for each free index `i_h` is uniform in `Fr`, hence `g^{a(i_h + 1)}` is uniform in `G` — matching `B`'s choice `u_h ←$ G`. The inverse-Vandermonde map from `t + 1` group evaluation points to `(v_0, ..., v_t)` is a deterministic bijection, so `v`'s joint distribution is identical in the two worlds.

ACK signatures use real honest signing keys in both worlds (bit-identical); round-2 reveals are a subset of `{y_j : j ∈ J}` in both worlds (bit-identical).

**Scope.** Theorem 1 covers only the **sharing phase** of a single VSS instance — from the dealer's first on-chain contribution through VSS reaching the qualifying state. Downstream uses (DKG aggregation, DKR resharing, threshold decryption) require independent theorems composed with this one; see [`dkg.md`](./dkg.md), [`dkr.md`](./dkr.md), and [`t-ibe.md`](./t-ibe.md).

**References.** The reduction structure is standard Feldman'87 / Pedersen'91 secrecy analysis under DLog, applied to the DAS 2023/1196 synchronous-VSS protocol skeleton with Feldman PCS substituted in. The PKE IND-CPA hybrid technique is standard Goldwasser–Micali. See [`references.md`](./references.md).
