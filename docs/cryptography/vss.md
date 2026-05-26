# Verifiable Secret Sharing (VSS)

ACE uses a Feldman-style polynomial commitment scheme (PCS) over an abstract `group::Element` (BLS12-381 $\mathbb{G}_1$ or $\mathbb{G}_2$). The core building block is a single dealer-driven VSS session; [`dkg.md`](./dkg.md) composes $n$ VSS sessions in parallel, [`dkr.md`](./dkr.md) composes them with a resharing-dealer challenge.

Throughout this file we write the group multiplicatively: $g$ denotes the session base point (`public_base_element` on chain), $g^x$ denotes scalar exponentiation, and $\mathbb{F}_r$ is the scalar field of BLS12-381.

## 1. Construction

ACE's VSS is the **synchronous VSS** of Algorithm 1, §5 in:

> Sourav Das, Zhuolun Xiang, Alin Tomescu, Alexander Spiegelman, Benny Pinkas, Ling Ren. **"Verifiable Secret Sharing Simplified."** IACR ePrint 2023/1196. <https://eprint.iacr.org/2023/1196>

The paper presents a publicly-verifiable, complete, $t$-resilient VSS for $n \geq 2t + 1$ synchronous nodes assuming a polynomial commitment scheme `PC`, signatures, and a Byzantine broadcast channel. ACE preserves the protocol skeleton — single-round dealer share-out, ACK collection, second-round reveal of unacked shares — and inherits the paper's correctness, completeness, and termination properties. Secrecy needs a fresh argument tailored to ACE's PCS choice; see §2 below.

### 1.1 Implementation choices

Where the paper's protocol uses abstract primitives, ACE pins concrete ones. Auditors should re-check the security argument against each:

1. **Polynomial commitment scheme = Feldman.** The paper's `PC` is generic; its formal hiding requirement (§4.2 of the paper) is satisfied by the Pedersen-style PCS in their Appendix A.2 ($v_k = g^{a_k} h^{r_k}$). ACE pins `PC` to **Feldman commitments over BLS12-381 $\mathbb{G}_1$ or $\mathbb{G}_2$** (the dealer publishes $v_k = g^{a_k}$, no $h$-blinding). Consequence: `PC.Open` is trivial — the share $y_i$ *is* the witness, and `PC.Verify` is the equation $g^{y_i} = \prod_{k=0}^{t-1} v_k^{(i+1)^k}$. The paper's `PC.BatchOpen` collapses to "publish the missing scalar shares directly". See §1.2 below for the formula.

    **Security argument: computational reduction, not hiding-based simulation.** Feldman is *not* a hiding commitment — $v_0 = g^s$ publicly determines $g^s$. So paper's information-theoretic Lemma 1 (App. C) does NOT carry over: paper's simulator uses the Pedersen blinding factor $r(\cdot)$ to "rebind" the commitment to any candidate secret, which has no Feldman analogue. We instead prove **Theorem 1 (§2)** — a game-based reduction showing that any PPT adversary's chance of recovering the secret from the sharing-phase view is bounded by $\mathsf{Adv}_{\text{DLog}} + n \cdot \mathsf{Adv}_{\text{IND-CPA}} + 1/|\mathbb{F}_r|$. The game samples $s \in_R \mathbb{F}_r$ uniformly; auditors should verify that every VSS call site supplies a uniformly random secret (see §1.3 for the two ACE derivations, both uniform).

    **Why Feldman, not Pedersen.** Two ACE-specific consumers of the VSS output make Pedersen awkward:

    - t-IBE decryption ([`t-ibe.md`](./t-ibe.md) §1) verifies each share-PK via the pairing equation $e(\mathsf{idk\_share}_i,\, g) = e(Q_{\mathsf{id}},\, \mathsf{share\_pk}_i)$, which holds only when $\mathsf{share\_pk}_i = g^{s_i}$ is in unblinded Feldman form. A Pedersen-VSS share-PK is $g^{s_i} h^{r(i)}$ and does not satisfy this equation. The known workarounds (GJKR'99 dual commitment — publish a Feldman commitment alongside Pedersen and prove they're consistent; or reveal $r(\cdot)$ at VSS end) all expose $g^{f(i+1)}$ publicly anyway, dropping Pedersen's hiding back to DLog-level secrecy.
    - DKR's resharing-soundness check (see [`dkr.md`](./dkr.md), `vss.move:201`) is $\mathsf{element\_eq}(v_0,\, g_{\text{old}}^{s_j})$, a one-line group equality against the publicly pre-published $g_{\text{old}}^{s_j}$ from the parent committee. Under Pedersen, $v_0 = g^{s_j} h^{r_0}$ does not satisfy that equation; replacing it with a NIZK opening proof is possible but adds transcript size and verifier cost.

    This is **not** a claim that Pedersen is structurally impossible — only that we don't know how to keep t-IBE and DKR as simple as the Feldman case while paying for Pedersen's blinding. Since ACE's end-to-end secrecy is bounded by DLog regardless (downstream applications publish $g^{\mathsf{MSK}}$ and the per-recipient $g^{s_i}$), Feldman achieves the same security floor with strictly less machinery.

2. **Private authenticated channel = PKE.** The paper assumes private authenticated channels between dealer and each node. ACE realizes this by **PKE-encrypting each share to the recipient's registered `pke_enc_key`**, with the resulting ciphertext riding the public broadcast channel. Confidentiality reduces to PKE security ([`pke.md`](./pke.md)). The auth side is provided by the chain layer: the share ciphertext is bound to the dealer's account by virtue of the `on_dealer_contribution_0` signed transaction.

3. **Byzantine broadcast channel = the L1 chain.** Total ordering, immutability, and authentication of the transcript come from the Aptos L1 (Aptos's BFT consensus replaces the abstract `BB` channel). Trust assumption shifts from "broadcast channel exists" to "Aptos validator quorum is honest". Documented in [`../trust-model.md`](../trust-model.md) §5.

4. **Signed `ACK` = on-chain transaction.** The paper has nodes send $\langle \mathsf{ACK},\, \sigma_i \rangle$ over the broadcast channel, where $\sigma_i = \mathsf{sign}(\mathsf{sk}_i,\, v)$. ACE has them call `on_share_holder_ack(session_addr)` on-chain; the Aptos transaction signature *is* $\sigma_i$, and the chain naturally rejects $(t)$ ACKs from any node that already ACKed. The authenticated-tally property the paper needs is provided by the L1.

5. **Selective reveal of missing shares.** The paper's second round does $(s, \pi) := \mathsf{PC.BatchOpen}(p, I, w)$ and broadcasts $(v, I, \sigma, s, \pi)$. ACE's equivalent reveals only the scalar shares of non-ackers as a vector of optional scalars (one slot per holder; `None` if they acked, `Some(y_j)` otherwise). With Feldman the proof drops out (item 1), so the second-round message carries scalars only — the verifier (an on-chain incremental computation) re-runs the Feldman MSM check on each revealed share.

6. **Lazy `touch()` progression.** Move's per-transaction gas budget forces splitting the second-round verification across multiple `touch()` calls (one share-PK MSM per call). The paper's protocol is single-shot. This is a realization detail, not a security modification — `touch()` only ratchets state forward and is monotonic.

7. **Resharing-dealer challenge.** ACE adds an *optional* challenge $(P, H)$ plus a Sigma-DLog-Eq proof (see [`sigma-dlog-eq.md`](./sigma-dlog-eq.md)) that pins the dealer's polynomial constant term $a_0$ to a previously-known share $s_j$ (where $P = g_{\text{old}}^{s_j}$ from the parent DKG/DKR, and $H$ is an independent base derived from $P$). Used by Distributed Key Resharing (see [`dkr.md`](./dkr.md)) to prevent a dealer from substituting a fresh secret. **This is outside the paper's scope.** Audit hook: the soundness of resharing reduces to the soundness of Sigma-DLog-Eq.

8. **Dealer-state crash recovery.** ACE encrypts the dealer's own polynomial coefficients to itself (via PKE) so a crashed dealer can resume. Not in the paper. Encrypted with the dealer's own `pke_enc_key`; no other recipient ever decrypts it. Pure operational add-on; doesn't affect any security claim.

9. **Single threshold only.** ACE uses $\text{secrecy threshold} = \text{reconstruction threshold} = t$; the paper's dual-threshold variant ($\ell \in [t, n - t]$) and the verifiable-encryption-of-Pedersen-commitment scheme of §7 are NOT used.

10. **Synchrony bound.** The paper's $2\Delta$ round timer becomes ACE's `ACK_WINDOW_MICROS = 10s` (`vss.move:47`). The chain's clock (`timestamp::now_microseconds`) provides $\Delta$-monotonicity; honest dealers and honest nodes are assumed to submit their next-round transactions within that window. Audit hook: under chain-level liveness pauses (Aptos BFT halt), the timer can lapse without genuine asynchrony being the cause; this is a *liveness* concern, not a *safety* concern (a halt cannot manufacture false ACKs).

### 1.2 Polynomial commitment

Given a polynomial $f(x) = a_0 + a_1 x + \cdots + a_{t-1} x^{t-1}$ over $\mathbb{F}_r$, the dealer publishes a commitment vector

$$v_k = g^{a_k} \in \mathbb{G}, \qquad k = 0, 1, \dots, t-1$$

where $g$ is the session's `public_base_element`. Verifying a share $y_i = f(i+1)$ against the commitment amounts to checking

$$g^{y_i} \;=\; \prod_{k=0}^{t-1} v_k^{(i+1)^k \bmod r}.$$

(Multi-scalar multiplication on-chain.) Implemented in `worker-components/vss-common/src/vss_types.rs::feldman_verify` (Rust) and `contracts/vss/sources/vss.move::touch` (Move).

### 1.3 Share derivation

VSS shares are encrypted to recipients with the per-recipient PKE encryption key registered in `worker_config`. Each recipient's plaintext is a single $\mathbb{F}_r$ scalar serialized as `[scheme_byte u8][ULEB128(32) = 0x20][32B y_LE]`.

The dealer's polynomial coefficients are **deterministically derived** from its PKE decryption key:

$$
\begin{aligned}
a_0 &:= \begin{cases}
   \mathsf{Fr\_from\_LE}(\mathsf{secret\_override}) & \text{if } \mathsf{secret\_override}\ \text{is set}\\
   \mathsf{fr\_from\_dk\_bytes}(\mathsf{dk},\, 0) & \text{otherwise}
\end{cases} \\
a_k &:= \mathsf{fr\_from\_dk\_bytes}(\mathsf{dk},\, k) \qquad \text{for } k = 1, \dots, t-1 \\
\mathsf{fr\_from\_dk\_bytes}(\mathsf{dk},\, i) &:= \mathsf{Fr\_from\_LE}\bigl(\text{SHA3-256}(\text{``vss-coef-v1/''} \,\|\, \mathsf{dk} \,\|\, \mathsf{LE64}(i))\bigr)
\end{aligned}
$$

(Source: `worker-components/vss-common/src/crypto.rs::fr_from_dk_bytes` + `worker-components/vss-dealer/src/lib.rs:198-208`.)

Both call paths supply a uniform $\mathbb{F}_r$ secret (required by **Theorem 1**, §2 below):

- `fr_from_dk_bytes(pke_dk_bytes, 0)` — derived from a freshly-generated PKE decryption key (uniform $\mathbb{F}_r$ at node init).
- `secret_override` — documented contract is "a DKG/DKR share", a Lagrange evaluation of a uniform-random DKG polynomial, itself uniform in $\mathbb{F}_r$.

**Audit note.** Determinism is intentional: it lets a dealer recover its own contribution after a crash, and lets failed recipients have their share revealed by `on_dealer_open` without re-running the whole VSS. The downside is that **anyone who learns a dealer's PKE decryption key learns every secret that dealer has ever contributed to**. The `worker-config` registration step therefore commits the dealer to a single PKE key per `account_addr` for the duration of its membership.

## 2. Security

Replacing the paper's Pedersen PCS with Feldman (§1.1 item 1) requires a new security argument: paper's Lemma 1 leans on the Pedersen blinding $r(\cdot)$ to absorb arbitrary secret choices, which has no Feldman analogue. We state the resulting Feldman-based secrecy as a game-based reduction to DLog and PKE IND-CPA.

**Game $\text{VSS-OW}$** (one-wayness of the sharing-phase secret).

1. $\mathcal{A}$ picks corruption set $J \subseteq [n]$ with $|J| \leq t$.
2. The challenger generates $(\mathsf{sk}_i, \mathsf{dk}_i, \mathsf{pk}_i, \mathsf{ek}_i)$ for each $i \in [n]$; hands $(\mathsf{sk}_j, \mathsf{dk}_j)_{j \in J}$ to $\mathcal{A}$; publishes all $(\mathsf{pk}_i, \mathsf{ek}_i)$.
3. The challenger samples $s \in_R \mathbb{F}_r$ uniformly.
4. The challenger plays the honest dealer with secret $s$ and runs the full sharing phase (including round-2 reveal of any non-ACKed share). $\mathcal{A}$ controls the corrupted parties' protocol behaviour.
5. $\mathcal{A}$ outputs $s' \in \mathbb{F}_r$.
6. $\mathcal{A}$ wins iff $s' = s$.

Define $\mathsf{Adv}_{\text{VSS-OW}}(\mathcal{A}) := \Pr[\mathcal{A}\ \text{wins}]$.

**Theorem 1 (Sharing-phase one-wayness).** Assuming

- (H1) $n \geq 2t + 1$; polynomial degree $t$; reconstruction threshold $t + 1$;
- (H2) DLog is hard in the BLS12-381 group ($\mathbb{G}_1$ or $\mathbb{G}_2$, whichever the session uses);
- (H3) the PKE scheme that encrypts shares ([`pke.md`](./pke.md)) is IND-CPA-secure;
- (H4) the signature scheme used for ACK messages is EUF-CMA-secure;
- (H5) the Aptos L1 provides Byzantine broadcast and monotonic timestamps within the `ACK_WINDOW_MICROS` bound;
- (H6) static corruption: $|J| \leq t$ and the dealer $L \notin J$;

for any PPT adversary $\mathcal{A}$ there exist PPT algorithms $\mathcal{B}$ (DLog solver) and $\mathcal{C}$ (PKE IND-CPA distinguisher) such that

$$\mathsf{Adv}_{\text{VSS-OW}}(\mathcal{A}) \;\leq\; \mathsf{Adv}_{\text{DLog}}(\mathcal{B}) \;+\; n \cdot \mathsf{Adv}_{\text{IND-CPA}}(\mathcal{C}) \;+\; \frac{1}{|\mathbb{F}_r|}.$$

In particular, under (H2)+(H3), $\mathsf{Adv}_{\text{VSS-OW}}(\mathcal{A}) \leq \mathsf{negl}(\kappa)$.

**Reduction sketch ($\mathcal{B}$'s construction).** On DLog challenge $(g, P)$ where the goal is to recover $x$ with $P = g^x$:

1. Accept $\mathcal{A}$'s corruption set $J$. Generate all node keys honestly and hand $(\mathsf{sk}_j, \mathsf{dk}_j)_{j \in J}$ to $\mathcal{A}$.
2. Set $v_0 := P$ (i.e., implicitly let the latent secret be $s = \log_g P$, unknown to $\mathcal{B}$).
3. Sample $\{y_j : j \in J\} \in_R \mathbb{F}_r$ uniformly — these will play the role of the corrupted parties' shares.
4. Sample $t - |J|$ uniformly random group elements $u_h \in_R \mathbb{G}$ for "honest-holder placeholder" evaluations at fresh free indices outside $J \cup \{0\}$.
5. Compute $v_1, \dots, v_{t-1}$ via Lagrange interpolation **in the exponent** over the $t + 1$ group points $(v_0,\, \{g^{y_j}\}_{j \in J},\, \{u_h\})$, using inverse-Vandermonde coefficients.
6. Encrypt $0$ under each honest holder's $\mathsf{ek}_i$ (dummy ciphertext); encrypt $y_j$ under each corrupted holder's $\mathsf{ek}_j$ (so $\mathcal{A}$'s decryption recovers the prepared $y_j$).
7. Publish $(v_0, \dots, v_{t-1})$ and the ciphertexts as the dealer's first-round contribution on the simulated chain.
8. Sign ACK messages on behalf of each honest holder using its real signing key. For any corrupted holder $\mathcal{A}$ chooses not to ACK, perform the round-2 reveal by publishing $y_j$; on-chain Feldman verification accepts because $v$ was constructed to satisfy $g^{y_j} = \prod_k v_k^{(j+1)^k}$ by step 5.
9. $\mathcal{A}$ outputs $s'$. $\mathcal{B}$ outputs $s'$ as its DLog answer.

**Correctness.** The view $\mathcal{B}$ presents to $\mathcal{A}$ is computationally indistinguishable from the real $\text{VSS-OW}$ game conditioned on $s = \log_g P$. Two ingredients carry the argument:

- *PKE step (computational gap, $n \cdot \mathsf{Adv}_{\text{IND-CPA}}$).* The only real-vs-simulated mismatch is that honest holders' ciphertexts are $\mathsf{Enc}(\mathsf{ek}_i,\, 0)$ in $\mathcal{B}$'s simulation but $\mathsf{Enc}(\mathsf{ek}_i,\, y_i)$ in the real game. A hybrid over the $\leq n$ honest holders bridges this by IND-CPA; the corrupted holders' decryption keys do not leak the honest holders' plaintexts because $\mathcal{A}$ does not hold $(\mathsf{sk}_i, \mathsf{dk}_i)$ for $i \notin J$.
- *Commitment-vector distribution (perfect equality).* Conditional on $(s,\, \{y_j\}_{j \in J})$, the real dealer's polynomial $a(\cdot)$ is uniform over the $(t - |J|)$-dimensional affine subspace of degree-$t$ polynomials with $a(0) = s$ and $a(j+1) = y_j$ for $j \in J$. Therefore $a(i_h + 1)$ for each free index $i_h$ is uniform in $\mathbb{F}_r$, hence $g^{a(i_h + 1)}$ is uniform in $\mathbb{G}$ — matching $\mathcal{B}$'s choice $u_h \in_R \mathbb{G}$. The inverse-Vandermonde map from $t + 1$ group evaluation points to $(v_0, \dots, v_{t-1})$ is a deterministic bijection, so $v$'s joint distribution is identical in the two worlds.

ACK signatures use real honest signing keys in both worlds (bit-identical); round-2 reveals are a subset of $\{y_j : j \in J\}$ in both worlds (bit-identical).

**Scope.** Theorem 1 covers only the **sharing phase** of a single VSS instance — from the dealer's first on-chain contribution through VSS reaching the qualifying state. Downstream uses (DKG aggregation, DKR resharing, threshold decryption) require independent theorems composed with this one; see [`dkg.md`](./dkg.md), [`dkr.md`](./dkr.md), and [`t-ibe.md`](./t-ibe.md).

**References.** The reduction structure is standard Feldman'87 / Pedersen'91 secrecy analysis under DLog, applied to the DAS 2023/1196 synchronous-VSS protocol skeleton with Feldman PCS substituted in. The PKE IND-CPA hybrid technique is standard Goldwasser–Micali. See [`references.md`](./references.md).
