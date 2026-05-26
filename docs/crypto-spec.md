# ACE Cryptographic Specification

This document specifies the cryptographic primitives used in ACE — exact constructions, parameters, domain-separation tags, and security assumptions. It is the canonical reference for auditors and for future implementations.

For the higher-level protocol (DKG / DKR / decryption-request flow), see [`protocols.md`](./protocols.md). For the on-the-wire byte layouts, see [`wire-formats.md`](./wire-formats.md). For terms used without definition (`keypair_id`, `epoch`, `share-PK`, `t`, `n`, $Q_{\text{id}}$, etc.), see [`glossary.md`](./glossary.md).

> All byte-counts below assume the wire/BCS encoding shipped today. ULEB128 length prefixes for `Vec<u8>` fields are noted explicitly. Citations are `path:line` against the repository at the doc-PR commit.

---

## 1. Notation and conventions

- `Fr` — scalar field of BLS12-381, prime order `r ≈ 2²⁵²`.
- `G1`, `G2` — the two pairing-friendly subgroups of BLS12-381 (cofactor-cleared).
- `Gt` — target group, `Fp¹²` in BLS12-381.
- `Ristretto255` — prime-order group derived from Ed25519 (RFC 9496 candidate).
- `||` denotes byte concatenation. `LE64(x)` means 8-byte little-endian. `BCS(·)` is Aptos's Binary Canonical Serialization (`Vec<u8>` ⇒ `ULEB128(len) || bytes`).
- All hash-to-curve uses RFC 9380 (`hash_to_curve`) with the per-suite DST listed below.
- Random sampling uses each platform's CSPRNG (`OsRng` in Rust, `crypto.getRandomValues` / Web Crypto in TS).

---

## 2. Public-Key Encryption (`pke::*`)

The PKE layer is used to encrypt **VSS share messages** (dealer → recipient) and **decryption-request bodies** (client ↔ worker). Two schemes exist in the codebase, selected by a 1-byte scheme tag:

| Scheme | Tag | Status | Defined |
|--------|-----|--------|---------|
| ElGamal-OTP-Ristretto255 | `0x00` | **test-only** (see below) | `ts-sdk/src/pke/elgamal_otp_ristretto255.ts`, `worker-components/vss-common/src/{pke.rs,crypto.rs}`, `contracts/pke/sources/pke_elgamal_otp_ristretto255.move` |
| HPKE-X25519-HKDF-SHA256-ChaCha20Poly1305 | `0x01` | **production, default** | `ts-sdk/src/pke/hpke_x25519_chacha20poly1305.ts`, `worker-components/vss-common/src/pke_hpke_x25519_chacha20poly1305.rs`, `contracts/pke/sources/pke_hpke_x25519_chacha20poly1305.move` |

> **Audit scope.** Only **scheme `0x01`** is audited. Scheme `0x00` is **test-only** — a hand-rolled ElGamal-in-the-exponent + custom OTP/HMAC DEM construction that has no formal security proof and uses non-standard primitives (notably the 64-byte-block HMAC-SHA3-256 of §6.2). It is the default of nothing today, used by no example, and referenced only by the regression scenario `scenarios/test-network-protocol-shortpk.ts` and an internal SDK test. Production deployments must use scheme `0x01`. A follow-up PR may delete scheme `0x00` from the codebase; until then, the BCS decoder still recognizes the discriminant — see [`wire-formats.md`](./wire-formats.md) §1.1 / §1.2.

### 2.1 HPKE-X25519-HKDF-SHA256-ChaCha20Poly1305 (scheme `0x01`, default)

[RFC 9180](https://www.rfc-editor.org/rfc/rfc9180) HPKE in **base mode** (no PSK, no auth).

**Ciphersuite.**
```
KemId  = 0x0020   (DHKEM(X25519, HKDF-SHA256))
KdfId  = 0x0001   (HKDF-SHA256)
AeadId = 0x0003   (ChaCha20-Poly1305)
info   = b""       (empty)
aad    = b""       (empty by default; callers do NOT pass AAD)
```

**TS implementation** uses [`@hpke/core`](https://www.npmjs.com/package/@hpke/core) for browser+node WebCrypto-backed primitives (`ts-sdk/src/pke/hpke_x25519_chacha20poly1305.ts`). **Rust implementation** uses [`hpke`](https://docs.rs/hpke/latest/hpke/) crate (`worker-components/vss-common/src/pke_hpke_x25519_chacha20poly1305.rs:19-23`). **Move implementation** is decoder-only (`contracts/pke/sources/pke_hpke_x25519_chacha20poly1305.move`); no on-chain encrypt/decrypt is needed.

**Wire shapes.** Byte layouts for `EncryptionKey`, `DecryptionKey`, and `Ciphertext` (HPKE rows) live in [`wire-formats.md`](./wire-formats.md) §1.1-§1.3.

**Security.** RFC 9180 base mode is IND-CCA2 under the X25519 GapDH assumption (or qDHI per the analysis in the HPKE RFC) and HKDF/ChaCha20-Poly1305 standard assumptions. ~128-bit security level.

**Caveats / audit notes.**
- AAD is hardcoded empty; callers cannot bind external context to a ciphertext via this layer. The application layer (Sigma-DLog-Eq, Aptos full-message signature, Solana txn simulation) provides binding instead.
- Implementations across TS/Rust/Move use **independent** HPKE libraries — wire-compatibility is verified by the round-trip tests in `worker-components/vss-common/src/pke_hpke_x25519_chacha20poly1305.rs:166-307` and `contracts/pke/tests/`.

---

## 3. Threshold Identity-Based Encryption (`t-ibe::*`)

t-IBE is the layer the **end-user** sees: encryption is to a "keypair-id" (an on-chain DKG session address) and an "identity" (the BCS bytes of `(keypair_id, contract_id, label)`, where `label` is the app-specific scoping bytes); decryption requires t-of-n workers to each release a partial extraction of the IBE identity decryption key (IDK). Each worker holds a Shamir share of the master secret $s$; the master public key $\mathsf{mpk}$ is the joint DKG output (constant-term commitment of the joint polynomial over $\mathbb{F}_r$).

| Scheme | Tag | Status | Defined |
|--------|-----|--------|---------|
| BFIBE-BLS12381-ShortPK-OTP-HMAC | `0x00` | **test-only** (see below) | `ts-sdk/src/t-ibe/bfibe-bls12381-shortpk-otp-hmac.ts`, `worker-components/network-node/src/crypto.rs:34` |
| BFIBE-BLS12381-ShortSig-AEAD | `0x01` | **production, default** | `ts-sdk/src/t-ibe/bfibe-bls12381-shortsig-aead.ts`, `worker-components/network-node/src/crypto.rs:35` |

> **Audit scope.** Only **scheme `0x01`** is audited. Scheme `0x00` is **test-only** — Boneh–Franklin in G1 with the same hand-rolled OTP + custom-HMAC-SHA3-256 DEM as PKE scheme `0x00` (§2). It is selected only when the underlying DKG uses a G1 basepoint, which today happens only in the regression scenario `scenarios/test-network-protocol-shortpk.ts` and an internal SDK test. Production deployments use a G2 basepoint and therefore scheme `0x01`. A follow-up PR may delete scheme `0x00` from the codebase. The remainder of §3 describes scheme `0x01` only.

The runtime choice between schemes is a static dispatch on the underlying DKG basepoint group, in `worker-components/network-node/src/crypto.rs::tibe_scheme_for_group`: G1 → scheme `0x00` (test-only), G2 → scheme `0x01` (production).

### 3.1 BFIBE-BLS12381-ShortSig-AEAD (scheme `0x01`, default)

A Boneh–Franklin t-IBE (BasicIdent extended to threshold via Shamir over $\mathbb{F}_r$) with a [Fujisaki–Okamoto](https://link.springer.com/chapter/10.1007/3-540-48405-1_34)-style DEM on top.

- **Master public key** lives in **G2** (96-byte compressed).
- **Identity hash** maps to **G1** via RFC 9380 hash-to-curve.
- **IDK share** lives in **G1** (48-byte compressed) — hence "short sig". This matches `draft-irtf-cfrg-bls-signature` "minimal-signature-size", and the share is computationally a [BLS](https://www.iacr.org/archive/asiacrypt2001/22480516.pdf) signature on the identity.
- **DEM** is `HKDF-SHA256` keying `ChaCha20-Poly1305` — the same primitive set as the HPKE-X25519 PKE, with a single derived (key, nonce) pair.

**DSTs** (`ts-sdk/src/t-ibe/bfibe-bls12381-shortsig-aead.ts:38-42`):
```
DST_HASH_ID_TO_CURVE = "BONEH_FRANKLIN_BLS12381_SHORTSIG_AEAD/HASH_ID_TO_CURVE"
DST_KDF              = "BONEH_FRANKLIN_BLS12381_SHORTSIG_AEAD/KDF"
```

**Hash-to-curve suite.** `BLS12381G1_XMD:SHA-256_SSWU_RO_` (RFC 9380 §8.8.1) with the DST above.

**Master keypair.**
```
basePoint ← G2                                 # 96B compressed
s         ← Fr (committee-jointly via DKG)
pk        := s · basePoint                      ∈ G2
MasterPublicKey  = (basePoint ∈ G2, pk ∈ G2)
```

**Encrypt** `(MasterPublicKey, identity_bytes, plaintext)`:
```
r       ← Fr
c0      := r · basePoint                       ∈ G2                          # 96B compressed
Q_id    := hash_to_curve_G1(identity_bytes, DST_HASH_ID_TO_CURVE)             ∈ G1
seed_gt := pairing(Q_id, r · pk)               ∈ Gt
seed    := bls12381_gt_repr_to_bytes(seed_gt)                                 # 576 bytes; canonical Aptos LE-per-limb form (§3.2)
okm     := HKDF-SHA256(IKM=seed, salt=∅, info=DST_KDF, L=32+12)               # = 44 bytes
key     := okm[0..32]                                                         # ChaCha20 key
nonce   := okm[32..44]                                                        # 12B nonce
aead_ct := ChaCha20-Poly1305(key, nonce, AAD=∅).encrypt(plaintext)
                                                                              # ciphertext || 16B Poly1305 tag
Ciphertext = (c0, aead_ct)                     # 96 + |plaintext| + 16 bytes (excluding wire ULEBs)
```

**Decrypt** with t-of-n IDK shares:
```
For each share i:
  share_i = (eval_point_i, idk_share_i)  where idk_share_i = s_i · Q_id  ∈ G1
  s_i     = Shamir share of master secret at x = eval_point_i

Verify share i (enforced by SDK):
  pairing(idk_share_i, basePoint) == pairing(Q_id, share_pk_i)              # share_pk_i is on-chain
  where share_pk_i = s_i · basePoint                       (read from VSS::share_pks)

Reconstruct full IDK:
  λ_i := ∏_{j ≠ i} (0 - x_j) / (x_i - x_j)   in Fr        (Lagrange basis at x=0)
  idk := Σ_i λ_i · idk_share_i                ∈ G1         # = s · Q_id

Recover seed and decrypt:
  seed_gt := pairing(idk, c0)                 ∈ Gt         # = e(Q_id, basePoint)^{r·s}, identical to encrypt
  seed    := bls12381_gt_repr_to_bytes(seed_gt)
  okm     := HKDF-SHA256(IKM=seed, salt=∅, info=DST_KDF, L=44)
  key     := okm[0..32]
  nonce   := okm[32..44]
  return ChaCha20-Poly1305(key, nonce, AAD=∅).decrypt(aead_ct)              # throws on tag mismatch
```

**Output sizes** (excluding wire ULEBs):
- Ciphertext: **112 + |plaintext|** bytes.
- IDK share: **81 bytes** = 32B `eval_point` LE || 48B G1 || 1B share-proof flag.

**Security.** CCA-secure under [Boneh–Franklin 2001 / FullIdent](https://crypto.stanford.edu/~dabo/papers/bfibe.pdf) on BLS12-381 (BDH assumption), threshold-extended via Shamir over $\mathbb{F}_r$, in the random-oracle model. The AEAD provides authenticated encryption with a single-use derived (key, nonce) — no nonce reuse risk because each fresh $r$ derives a fresh seed and therefore a fresh $(\text{key}, \text{nonce})$. ~128-bit security level.

**Audit notes.**
- Share verification is `pairing(idk_share_i, basePoint) == pairing(Q_id, share_pk_i)` (`ts-sdk/src/t-ibe/bfibe-bls12381-shortsig-aead.ts:374-380`).
- The HKDF `info` parameter is the DST literal — there is no per-ciphertext context beyond the seed itself. Because the seed already binds `Q_id`, the basePoint, and the random `r`, this is sound; but if you ever add a second use of HKDF with the same seed, you must change `info`.
- HKDF L=44 is exactly key+nonce; the AEAD's internal IV expansion is per the AEAD spec.

### 3.2 Gt → bytes canonicalization

The t-IBE scheme feeds a Gt element into HKDF as IKM. Gt is $\mathbb{F}_{p^{12}}$ (576 bytes uncompressed). The canonical byte representation is the noble/`hpke-js` *big-endian per limb* output of `bls12_381.fields.Fp12.toBytes`, then reversed limb-by-limb to **little-endian per 48-byte Fp limb** to match the on-chain Move convention.

Implementation: `ts-sdk/src/t-ibe/bfibe-bls12381-shortpk-otp-hmac.ts::bls12381GtReprNobleToAptos` and the Rust mirror in `worker-components/network-node/src/crypto.rs`.

Audit hook: any change to this canonicalization breaks cross-implementation interop silently. Round-trip tests in `ts-sdk/tests/bfibe-bls12381-*.test.ts` are the regression gate.

---

## 4. Verifiable Secret Sharing (VSS) and DKG

ACE uses a Feldman-style PCS over an abstract `group::Element` (BLS12-381 G1 or G2). The core building block is a single dealer-driven VSS session; DKG composes `n` VSS sessions in parallel.

### 4.0 Origin and modifications

ACE's VSS implements the **synchronous VSS** of Algorithm 1, §5 in:

> Sourav Das, Zhuolun Xiang, Alin Tomescu, Alexander Spiegelman, Benny Pinkas, Ling Ren. **"Verifiable Secret Sharing Simplified."** IACR ePrint 2023/1196. <https://eprint.iacr.org/2023/1196>

The paper presents a publicly-verifiable, complete, t-resilient VSS for `n ≥ 2t+1` synchronous nodes assuming a polynomial commitment scheme `PC`, signatures, and a Byzantine broadcast channel. ACE preserves the protocol skeleton — single-round dealer share-out, ACK collection, second-round reveal of unacked shares — and inherits the paper's correctness, completeness, and secrecy theorems (Theorem 1, Theorem 4 in App. C) modulo the modifications listed below.

The asynchronous variant (Algorithm 2) and the dual-threshold extension (§7) are NOT adapted; ACE relies on synchrony.

**Modifications relative to Algorithm 1.** Auditors should re-check the security argument against each:

1. **Polynomial commitment scheme = Feldman.** The paper's `PC` is generic; its formal hiding requirement (§4.2 of the paper) is satisfied by the Pedersen-style PCS in their Appendix A.2 (`v_k = g^{a_k} · h^{r_k}`). ACE pins `PC` to **Feldman commitments over BLS12-381 G1 or G2** (the dealer publishes `v_k = a_k · basePoint`, no `h`-blinding). Consequence: `PC.Open` is trivial — the share `y_i` *is* the witness, and `PC.Verify` is the equation `y_i · basePoint == Σ_k (i+1)^k · v_k`. The paper's `PC.BatchOpen` collapses to "publish the missing scalar shares directly". See §4.1.

    **Security argument: computational reduction, not hiding-based simulation.** Feldman is *not* a hiding commitment — `v_0 = s · basePoint` publicly determines `g^s`. So paper's information-theoretic Lemma 1 (App. C) does NOT carry over: paper's simulator uses the Pedersen blinding factor `r(·)` to "rebind" the commitment to any candidate secret, which has no Feldman analogue. We instead prove **Theorem 1 (§4.5)** — a game-based reduction showing that any PPT adversary's chance of recovering the secret from the sharing-phase view is bounded by `Adv_DLog + n · Adv_PKE-IND-CPA + 1/|Fr|`. The game samples `s ←$ Fr` uniformly; auditors should verify that every VSS call site supplies a uniformly random secret (see §4.2 for the two ACE derivations, both uniform).

    **Why not Pedersen (the paper's choice).** Adopting Pedersen would force `v_0 = s · basePoint + r_0 · H`, which deliberately hides `g^s` from any public observer. ACE's DKR resharing-soundness check (§4.0.1 modification 1, `vss.move:201`) is `element_eq(v_0, s_j · B_old)` — a one-line group equality against the *publicly pre-published* `s_j · B_old` carried over from the parent committee's DKG. That check requires `v_0` to *equal* `g^{s_j}`, not to be a Pedersen commitment that hides it. With Pedersen we would need either an additional NIZK proof of opening (more transcript, more verification cost, no extra real safety beyond what `element_eq` already provides) or to publish `r_0` (which destroys hiding for `coefs[0]` and brings us back to Feldman for that coefficient anyway). Since ACE applications (DKG output `g^{MSK}` and DKR's pre-published `g^{s_j}`) make `g^s` public anyway, the hiding property buys nothing operational. Feldman is the natural fit.
2. **Private authenticated channel = PKE.** The paper assumes private authenticated channels between dealer and each node. ACE realizes this by **PKE-encrypting each share to the recipient's registered `pke_enc_key`**, with the resulting ciphertext riding the public broadcast channel. Confidentiality reduces to PKE security (§2). The auth side is provided by the chain layer: the share ciphertext is bound to the dealer's account by virtue of the `on_dealer_contribution_0` signed transaction.
3. **Byzantine broadcast channel = the L1 chain.** Total ordering, immutability, and authentication of the transcript come from the Aptos L1 (Aptos's BFT consensus replaces the abstract `BB` channel). Trust assumption shifts from "broadcast channel exists" to "Aptos validator quorum is honest". Documented in [`trust-model.md`](./trust-model.md) §5.
4. **Signed `ACK` = on-chain transaction.** The paper has nodes send `⟨ACK, σ_i⟩` over the broadcast channel, where `σ_i = sign(sk_i, v)`. ACE has them call `on_share_holder_ack(session_addr)` on-chain; the Aptos transaction signature *is* `σ_i`, and the chain naturally rejects `(t)` ACKs from any node that already ACKed. The authenticated-tally property the paper needs is provided by the L1.
5. **Selective reveal of missing shares.** The paper's second round does `(s, π) := PC.BatchOpen(p, I, w)` and broadcasts `(v, I, σ, s, π)`. ACE's equivalent reveals only the scalar shares of non-ackers as a vector of optional scalars (one slot per holder; `None` if they acked, `Some(y_j)` otherwise). With Feldman the proof drops out (modification 1), so the second-round message carries scalars only — the verifier (an on-chain incremental computation) re-runs the Feldman MSM check on each revealed share.
6. **Lazy `touch()` progression.** Move's per-transaction gas budget forces splitting the second-round verification across multiple `touch()` calls (one share-PK MSM per call). The paper's protocol is single-shot. This is a realization detail, not a security modification — `touch()` only ratchets state forward and is monotonic.
7. **Resharing-dealer challenge.** ACE adds an *optional* challenge $(P, H)$ plus a Sigma-DLog-Eq proof (§5) that pins the dealer's polynomial constant term $a_0$ to a previously-known share $s_j$ (where $P = s_j \cdot B_{\text{old}}$ from the parent DKG/DKR, and $H$ is an independent base derived from $P$). Used by Distributed Key Resharing (DKR — see §4.0.1) to prevent a dealer from substituting a fresh secret. **This is outside the paper's scope.** Audit hook: the soundness of resharing reduces to the soundness of Sigma-DLog-Eq — see §5 below.
8. **Dealer-state crash recovery.** ACE encrypts the dealer's own polynomial coefficients to itself (via PKE) so a crashed dealer can resume. Not in the paper. Encrypted with the dealer's own `pke_enc_key`; no other recipient ever decrypts it. Pure operational add-on; doesn't affect any security claim.
9. **Single threshold only.** ACE uses `secrecy threshold = reconstruction threshold = t`; the paper's dual-threshold variant (`ℓ ∈ [t, n-t]`) and the verifiable-encryption-of-Pedersen-commitment scheme of §7 are NOT used.
10. **Synchrony bound.** The paper's $2\Delta$ round timer becomes ACE's `ACK_WINDOW_MICROS = 10s` (`vss.move:47`). The chain's clock (`timestamp::now_microseconds`) provides $\Delta$-monotonicity; honest dealers and honest nodes are assumed to submit their next-round transactions within that window. Audit hook: under chain-level liveness pauses (Aptos BFT halt), the timer can lapse without genuine asynchrony being the cause; this is a *liveness* concern, not a *safety* concern (a halt cannot manufacture false ACKs).

### 4.0.1 Distributed Key Resharing (DKR): origin and modifications

DKR is a [proactive-secret-sharing](https://link.springer.com/chapter/10.1007/3-540-44750-4_27)-style **resharing** protocol that hands a master secret $s$ from an old committee $(C_{\text{old}}, t)$ to a new committee $(C_{\text{new}}, t')$ without $s$ ever existing in cleartext (each committee is a set of node addresses; on-chain these are the `current_nodes` / `new_nodes` fields of `dkr::Session`). ACE's instance lives in `contracts/dkr/sources/dkr.move`.

**Construction.** Each old node $j$ runs a fresh degree-$(t'-1)$ VSS as dealer with $g_j(0) := s_j$ (their own old share, where $s_j = f(j+1)$ is the share of the underlying polynomial $f$), recipients = $C_{\text{new}}$. The resharing-dealer challenge (§4.3) forces $g_j(0) = s_j$. Once $\geq t$ such VSS reach the success state, the contributing set $H \subseteq C_{\text{old}}$ is frozen on-chain, and each new node $i \in C_{\text{new}}$ derives its new share via Lagrange-at-zero over the contributing old indices:

$$S_i := \sum_{j \in H} \lambda_j \cdot z_{j,i}, \qquad z_{j,i} = g_j(i+1), \qquad \lambda_j = \prod_{k \in H, k \neq j} \frac{0 - (k+1)}{(j+1) - (k+1)} \pmod r$$

The combined polynomial $F(x) := \sum_{j \in H} \lambda_j \cdot g_j(x)$ has degree $t'-1$ and satisfies $F(0) = \sum_j \lambda_j s_j = f(0) = s$ (since the $\lambda_j$ Lagrange-interpolate $f$ at $0$ over $H$).

**References.**
- *Sourav Das, Zhuolun Xiang, Alin Tomescu, Alexander Spiegelman, Benny Pinkas, Ling Ren.* "Verifiable Secret Sharing Simplified." IACR ePrint 2023/1196 — already cited above; it provides the underlying VSS (Algorithm 1) used inside each per-old-dealer reshare.
- *Alin Tomescu*, ["How to reshare a secret"](https://alinush.github.io/2024/04/26/How-to-reshare-a-secret.html), 2024 — pedagogical overview of the exact construction ACE implements (Lagrange-at-zero combination of fresh VSS per old node).
- *Herzberg, Jakobsson, Jarecki, Krawczyk, Yung.* **"Proactive Secret Sharing or: How to Cope with Perpetual Leakage."** CRYPTO '95 — original PSS paper.
- *Desmedt, Jajodia.* **"Redistributing Secret Shares to New Access Structures and Its Applications."** Tech report ISSE-TR-97-01, 1997 — share-redistribution variant for distinct old/new committees.

**Modifications relative to classical PSS / the blog construction.**

1. **Resharing-dealer challenge.** A standard PSS dealer can quietly substitute their own fresh secret for $s_j$. ACE prevents this in two layers. The load-bearing layer is an on-chain check (`vss.move:201`) that the dealer's first Feldman commitment $v_0$ equals the pre-published $s_j \cdot B_{\text{old}}$ — combined with Feldman verification of the polynomial during normal-or-dispute share opening, this forces $f(0) = s_j$ regardless of dealer behavior. (This check is also the reason ACE's PCS is Feldman and not the paper's Pedersen instantiation — see §4.0 modification 1: a hiding `v_0` would obstruct this group equality.) On top of that, ACE requires a Sigma-DLog-Eq proof (§5) that the dealer *knows* $s_j$ as a scalar; this gives an early-reject of dealers who don't (which would otherwise fail later via no-ACK → reveal → on-chain Feldman fail) and provides an extractability hook for the simulation-based security argument. A future simplification may drop the Sigma-DLog-Eq proof — the on-chain check + Feldman are sufficient for safety; the proof's main value is reasoning convenience, not concrete attack prevention.
2. **Agreement on contributing set $H$ = chain.** Naïvely, the new committee would need a Byzantine agreement protocol among themselves to agree on which $t$ VSS sessions to combine. ACE delegates this to the L1: the on-chain orchestrator deterministically reads each VSS's completion flag and freezes the contributing set the first time $|\{j : \text{vss}_j \text{ done}\}| \geq t$. Every observer reads the same $H$ from on-chain state. **New-node honesty does not provide agreement; the chain does.** Same modification pattern as VSS §4.0 item 3.
3. **Lagrange coefficients computed on-chain.** Move computes $\{\lambda_j\}_{j \in H}$ once per session; new nodes don't compute their own. Saves cross-committee replay and ensures every party uses the same $\lambda_j$.
4. **No within-epoch share refresh.** Classical PSS refreshes shares periodically within an epoch to handle a mobile adversary. ACE refreshes only at epoch boundaries (`epoch_duration_micros ≥ 30s`); within an epoch, shares are static.

**Corruption model.** Across the resharing transition window, the standard PSS analysis tolerates:
- $b_{\text{old}} < t$ corrupted nodes in the old committee, **and**
- $b_{\text{new}} < t'$ corrupted nodes in the new committee.

This is the **dual** of the user-friendly liveness phrasing (which says: at least $t$ honest in the old committee and at least $t'$ honest in the new). Note the inequality direction: secrecy needs $b_{\text{old}} \leq t-1$, liveness needs $n - b_{\text{old}} \geq t$ (and analogously for new). The two coincide only when the corrupted and the offline-but-honest sets coincide (i.e., a malicious node acts by going silent).

**Effect of committee overlap.** ACE's typical deployment has heavy overlap: an epoch transition often rotates one or two nodes. With overlap:
- A node in the overlap that is corrupted contributes to **both** $b_{\text{old}}$ and $b_{\text{new}}$.
- The *abstract* secrecy bound is unchanged: still $b_{\text{old}} < t \;\land\; b_{\text{new}} < t'$.
- The *number of distinct physical nodes an adversary must corrupt* to reach both budgets is smaller. With overlap of size $k$, corrupting up to $\min(t-1, t'-1)$ overlap-nodes counts double — a $(t-1)$-bounded attacker on the old side automatically gets $t-1$ corruptions on the new side too if every corruption is an overlap node.
- In the limit ($C_{\text{old}} = C_{\text{new}}$, full overlap, $t = t'$), the resharing protocol's secrecy collapses to the static secrecy of the underlying VSS in that committee: if you don't change the committee, fresh polynomial coefficients alone do not protect against an attacker who already corrupts $\geq t$ of those nodes.

This is the expected behavior for any PSS — the proactive benefit comes from changing the corrupted set, not from the polynomial refresh. The overlap level is a *deployment policy* choice: small overlap maximizes proactive benefit at the cost of operational continuity; large overlap maximizes continuity at the cost of attacker-cost reduction.

**Liveness.** DKR completes when:
- $\geq t$ honest-and-online old dealers submit a valid first-round message (with valid Sigma-DLog-Eq proof for resharing); the chain advances the contribution flags.
- For each of those VSS sessions, $\geq t'$ honest-and-online new ackers ACK within the 10-second window (or the dealer reveals the missing shares in the second round).

Heavy overlap also helps liveness: a single honest-and-online physical node serves both as old dealer and as new acker.

**Audit notes.**
- $s_j \cdot B_{\text{old}}$ is read from the previous session's on-chain share-PK list; auditors should confirm the read path cannot be poisoned by a malicious admin upgrading the predecessor module.
- A chain liveness halt during DKR stalls the epoch transition arbitrarily long — *liveness* concern, not *safety*.
- Heavy overlap is a deployment policy; the protocol does not enforce or reject it. A deployment that rotates $\geq 1$ node per epoch but is otherwise stable inherits the analysis above.

### 4.1 Polynomial commitment

Given a polynomial `f(x) = a_0 + a_1·x + … + a_{t-1}·x^{t-1}` over Fr, the dealer publishes a commitment vector
```
v_k = a_k · basePoint ∈ G   for k = 0..t-1
```
where `basePoint` is the `public_base_element` of the VSS session. Verifying a share `y_i = f(i+1)` against the commitment amounts to checking
```
y_i · basePoint == Σ_{k=0}^{t-1} ((i+1)^k mod r) · v_k
```
(Multi-scalar multiplication on-chain.) Implemented in `worker-components/vss-common/src/vss_types.rs::feldman_verify` (Rust) and `contracts/vss/sources/vss.move::touch` (Move).

### 4.2 Share derivation

VSS shares are encrypted to recipients with the per-recipient PKE encryption key registered in `worker_config`. Each recipient's plaintext is a single Fr scalar serialized as `[scheme_byte u8][ULEB128(32) = 0x20][32B y_LE]`.

The dealer's polynomial coefficients are **deterministically derived** from its PKE decryption key:
```
a_0 := if secret_override.is_some() { Fr::from_le_bytes_mod_order(secret_override) } else { fr_from_dk_bytes(pke_dk_bytes, 0) }
a_k := fr_from_dk_bytes(pke_dk_bytes, k)    for k = 1..t-1
where
  fr_from_dk_bytes(dk, idx) := Fr::from_le_bytes_mod_order(SHA3-256("vss-coef-v1/" || dk || LE64(idx)))
```
(Source: `worker-components/vss-common/src/crypto.rs::fr_from_dk_bytes` + `worker-components/vss-dealer/src/lib.rs:198-208`.)

**Audit note.** Determinism is intentional: it lets a dealer recover its own contribution after a crash, and lets failed recipients have their share revealed by `on_dealer_open` without re-running the whole VSS. The downside is that **anyone who learns a dealer's PKE decryption key learns every secret that dealer has ever contributed to**. The `worker-config` registration step therefore commits the dealer to a single PKE key per `account_addr` for the duration of its membership.

### 4.3 Resharing-dealer challenge

A VSS session created as part of DKR carries a *resharing challenge* — a pair $(P, H)$ — so the dealer must prove they're resharing a *specific* known secret rather than dealing a fresh one. The challenge geometry:
- $P = s \cdot B_{\text{old}}$, the dealer's existing share-PK (read from the parent DKG/DKR's on-chain state).
- $H = \mathsf{HashToCurve}_G(P)$, an independent base point in the random-oracle model.

The dealer must produce a Sigma-DLog-Eq proof (§5) that the constant term $a_0$ committed via $v_0 = a_0 \cdot B_{\text{old}}$ equals the secret used to scale $H$ to a publicly-revealed $a_0 \cdot H$. The on-chain verifier checks this proof during the dealer's first-round message; a forged or absent proof aborts the VSS.

### 4.4 DKG and DKR composition

- **DKG**: every committee member runs one VSS as dealer; the joint master secret is the sum of `t` of those individual contributions; `share_pk_i` for recipient `i` is the sum of per-VSS `share_pks[i]` over the `t` contributing dealers; `master_pk = Σ (a_0)_dealer · basePoint`.
- **DKR**: every old-committee member runs one VSS as dealer **with the resharing challenge** so they're committed to resharing their existing share `s_i`; new shares for the new committee are Lagrange combinations of the contributing old shares at `x = 0`. (`contracts/dkr/sources/dkr.move::touch`.)

See [`protocols.md`](./protocols.md) for the on-chain state machines, error paths, and timeouts.

### 4.5 Sharing-phase secrecy theorem

Replacing the paper's Pedersen PCS with Feldman (§4.0 modification 1) requires a new security argument: paper's Lemma 1 leans on the Pedersen blinding `r(·)` to absorb arbitrary secret choices, which has no Feldman analogue. We state the resulting Feldman-based secrecy as a game-based reduction to DLog and PKE IND-CPA.

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
- (H3) the PKE scheme that encrypts shares (`pke.rs`) is IND-CPA-secure;
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

**Scope.** Theorem 1 covers only the **sharing phase** of a single VSS instance — from the dealer's first on-chain contribution through VSS reaching the qualifying state. Downstream uses (DKG aggregation, DKR resharing, threshold decryption, etc.) require independent theorems composed with this one.

**References.** The reduction structure is standard Feldman'87 / Pedersen'91 secrecy analysis under DLog, applied to the DAS 2023/1196 synchronous-VSS protocol skeleton with Feldman PCS substituted in. The PKE IND-CPA hybrid technique is standard Goldwasser–Micali.

---

## 5. Sigma-DLog-Eq Proof

**Statement.** Prover knows a witness $s \in \mathbb{F}_r$ such that

$$P_0 = s \cdot B_0, \qquad P_1 = s \cdot B_1, \qquad \text{both in } G \in \{G_1, G_2\}$$

given the four points $(B_0, P_0, B_1, P_1)$.

**Use.** The VSS resharing dealer (§4.3) uses this with $B_0 = B_{\text{old}}$, $P_0 = a_0 \cdot B_{\text{old}}$ (= the first commitment $v_0$), $B_1 = H$, $P_1 = a_0 \cdot H$. Convinces the verifier that the committed $a_0$ equals the original secret share $s_j$.

### 5.1 Prove (Schnorr + Fiat–Shamir)

```
r ← Fr                                        # CSPRNG, fresh per proof
t0 := r · B0                                  ∈ G
t1 := r · B1                                  ∈ G
P1 := s · B1                                  ∈ G   # also returned
trx := chain_id (1B)                          # Aptos chain id
     || ace_addr (32B)                        # ACE deployment address
     || 0x03 || "vss"                         # BCS-encoded String "vss"
     || for each pt in (B0, P0, B1, P1, t0, t1):
            scheme (1B) || u8(|pt|) || pt     # scheme = 0=G1, 1=G2
c       := Fr::from_le_bytes_mod_order( SHA-512(trx) )
s_proof := r + c·s                            ∈ Fr
return (t0, t1, s_proof, P1)
```

**Transcript shape note.** The element-length byte is a plain `u8` (not a ULEB128) — for G1 it's 48, for G2 it's 96, both fit in one byte. Audit point: if a future group adds a > 255-byte element, the transcript must be widened.

### 5.2 Verify

The on-chain verifier reconstructs the same Fiat–Shamir transcript from $(B_0, P_0, B_1, P_1, t_0, t_1)$ and the bound (`chain_id`, `ace_addr`, `"vss"`), derives $c$, and checks:

$$s_{\text{proof}} \cdot B_0 = t_0 + c \cdot P_0, \qquad s_{\text{proof}} \cdot B_1 = t_1 + c \cdot P_1$$

**Security.** Standard Schnorr-style argument; soundness holds in the algebraic group model under DLog in $G$; HVZK in the ROM. ~128-bit security level on BLS12-381.

**Audit notes.**
- The (`chain_id`, `ace_addr`, `"vss"`) binding prevents cross-chain / cross-deployment proof replay. If the contract is ever redeployed at a different address, **prior VSS proofs become unverifiable** — by design.
- `from_le_bytes_mod_order` of a SHA-512 digest produces a uniformly-distributed $\mathbb{F}_r$ element with negligible bias ($r > 2^{252}$, hash output is 512 bits).

---

## 6. Symmetric primitives

### 6.1 KDF

A SHA3-256-based deterministic KDF that mirrors `ts-sdk/src/utils.ts::kdf`.

```
kdf(seed, dst, target_len) → Vec<u8> of length target_len

block_idx := 0
output    := []
while target_len > 0:
    block := SHA3-256( BCS(seed) || BCS(dst) || LE64(target_len_total) || LE64(block_idx) )
    take  := min(32, target_len)
    output ||= block[0..take]
    target_len -= take
    block_idx  += 1
return output
```
where `BCS(bytes) = ULEB128(bytes.len()) || bytes` and `target_len_total` is the **original** requested length (not the decreasing remaining).

Source: `worker-components/vss-common/src/crypto.rs:26-48` (Rust), `ts-sdk/src/utils.ts` (TS).

**Audit notes.**
- Domain separation is provided by `dst`. `seed.len()` is also covered (via the BCS length prefix), so colliding `(seed, dst)` requires colliding the entire SHA3-256 input.
- `target_len` is included in the per-block hash, so the same `(seed, dst, block_idx)` produces a different block for a different `target_len`. This is non-standard relative to HKDF and serves no obvious security purpose — but it's harmless and matches the TS / on-chain Move spec.
- SHA3-256 is used (Keccak), not SHA-256. Sponge construction → no length-extension risk.

### 6.2 HMAC-SHA3-256

Standard HMAC ([RFC 2104](https://www.rfc-editor.org/rfc/rfc2104)) with SHA3-256 and a fixed 32-byte key.

```
hmac_sha3_256(key[32], msg) → [32]
  pad := key || 0x00·32      # 64 bytes
  ipad := pad XOR (0x36·64)
  opad := pad XOR (0x5c·64)
  inner := SHA3-256(ipad || msg)
  outer := SHA3-256(opad || inner)
  return outer
```
Source: `worker-components/vss-common/src/crypto.rs:76-96` (Rust), `ts-sdk/src/utils.ts` (TS).

**Audit notes.**
- HMAC is overkill on a sponge primitive (SHA3-256 is not vulnerable to length-extension), but the construction is well-understood and the cost is one extra hash.
- The 64-byte block size is the SHA3-256 *capacity-block* convention used in this repo for HMAC; it is not the SHA3-256 rate (which is 136 bytes). Result: this is **not** the FIPS 198-1 HMAC-SHA3-256 (which uses a 136-byte block). It is an HMAC-like construction with a fixed 64-byte block, identical across TS, Rust, and (transitively) Move-side roundtrips. **External tooling that expects FIPS HMAC-SHA3-256 will compute different MACs.**
- This is intentional and load-bearing; it is the contract between `ts-sdk` and the workers. Auditors should verify (a) it's used consistently and (b) the implication is documented.

---

## 7. Random number generation

| Component | RNG | Usage |
|-----------|-----|-------|
| TS SDK | WebCrypto `crypto.getRandomValues` (browser) / Node `crypto.randomBytes` | All ephemerals (`r` in PKE/IBE encrypt, ephemeral encryption keys) |
| Rust workers | `rand::rngs::OsRng` (`/dev/urandom` on Linux, `getrandom` syscall) | VSS dealer optional `secret_override`, HPKE keygen, Sigma-DLog-Eq proof randomness |
| Move (on-chain) | `aptos_framework::randomness` API | DKG basepoint sampling (e.g. `epoch_change::touch` uses `randomness::generate(...)` for new G2 base points) |

**Audit notes.**
- VSS dealer randomness is **derived from the dealer's PKE decryption key** (§4.2), not freshly sampled. This is intentional and security-equivalent provided the PKE dk is itself uniformly random; the operator-CLI generates the dk via `WebCrypto` at onboarding and stores it in the provider-specific secret manager (Cloud Run Secret, etc.).
- Aptos's on-chain `randomness::generate` is itself a threshold protocol. Trust assumption: the Aptos validator quorum is honest. This is part of the "contract is truth" trust premise — see [`trust-model.md`](./trust-model.md).

---

## 8. Curve and group identifiers (cheat sheet)

| Curve / Group | Field | Element size (compressed) | Hash-to-curve suite |
|---------------|-------|--------------------------:|---------------------|
| BLS12-381 G1 | Fp (381b) | **48 B** | `BLS12381G1_XMD:SHA-256_SSWU_RO_` |
| BLS12-381 G2 | Fp² | **96 B** | `BLS12381G2_XMD:SHA-256_SSWU_RO_` |
| BLS12-381 Fr | scalar (252b) | 32 B (LE) | n/a |
| BLS12-381 Gt | Fp¹² | 576 B (custom canonicalization, §3.2) | n/a |
| Ristretto255 | derived from Ed25519 (252b) | 32 B | n/a (rejection-sampled) |
| X25519 (Curve25519 Mont) | Fp (255b) | 32 B (raw clamp) | n/a |
| Ed25519 (verifying key) | Fp | 32 B | n/a — used only for ProofOfPermission |

`group::SCHEME_BLS12381G1 = 0x00`, `group::SCHEME_BLS12381G2 = 0x01`. Defined in `contracts/group/sources/group.move` and mirrored in `worker-components/vss-common/src/session.rs`.

---

## 9. Out of scope (not yet implemented)

The following were called out in earlier discussions and are **not** in the current codebase. Auditors should not flag their absence; they're tracked as future work.

- **Post-quantum PKE.** No PQ-hybrid or PQ-only scheme is currently shipped. (Future: HPKE-X-Wing or Kyber-hybrid; tracked separately.)
- **256-bit security level PKE.** Both PKE schemes are ~128-bit. (Future: HPKE-X448-HKDF-SHA512-ChaCha20Poly1305 or similar.)
- **t-IBE share proof.** The `IdentityDecryptionKeyShare` wire format reserves a 1-byte "proof" flag for a future per-share Schnorr proof; today it is always `0x00` (no proof). The verification check in §3.1 uses on-chain `share_pks` instead, which is sufficient for honest-majority assumptions but not for accountability under accusatory failure.
- **Move-side HPKE / shortsig-aead encrypt-decrypt.** Move only decodes these formats; the on-chain side never holds a private key for either, so no on-chain encrypt or decrypt is needed.

---

## 10. References

**Standards.**
- RFC 2104 — HMAC: Keyed-Hashing for Message Authentication.
- RFC 5869 — HKDF: HMAC-based Extract-and-Expand Key Derivation Function.
- RFC 7748 — Elliptic Curves for Security (Curve25519, Curve448).
- RFC 8032 — Edwards-Curve Digital Signature Algorithm (EdDSA / Ed25519).
- RFC 8439 — ChaCha20 and Poly1305 for IETF Protocols.
- RFC 9180 — Hybrid Public Key Encryption (HPKE).
- RFC 9380 — Hashing to Elliptic Curves.
- RFC 9496 — The Ristretto255 and Decaf448 Groups.
- FIPS 202 — SHA-3 Standard (Keccak).
- IRTF CFRG draft — `draft-irtf-cfrg-bls-signature` (BLS Signatures, "minimal-signature-size" / "minimal-pubkey-size" variants).

**Academic.**
- Boneh, Franklin. "Identity-Based Encryption from the Weil Pairing." CRYPTO 2001. <https://crypto.stanford.edu/~dabo/papers/bfibe.pdf>
- Boneh, Lynn, Shacham. "Short Signatures from the Weil Pairing." ASIACRYPT 2001.
- Fujisaki, Okamoto. "Secure Integration of Asymmetric and Symmetric Encryption Schemes." CRYPTO 1999.
- Shamir. "How to Share a Secret." Commun. ACM 22(11), 1979.
- Feldman. "A Practical Scheme for Non-Interactive Verifiable Secret Sharing." FOCS 1987.
- Schnorr. "Efficient Signature Generation by Smart Cards." J. Cryptology 4(3), 1991.
- Herzberg, Jakobsson, Jarecki, Krawczyk, Yung. "Proactive Secret Sharing or: How to Cope with Perpetual Leakage." CRYPTO 1995.
- Desmedt, Jajodia. "Redistributing Secret Shares to New Access Structures and Its Applications." ISSE-TR-97-01, 1997.
- Das, Xiang, Tomescu, Spiegelman, Pinkas, Ren. "Verifiable Secret Sharing Simplified." IACR ePrint 2023/1196. <https://eprint.iacr.org/2023/1196>

**Other.**
- Tomescu, Alin. "How to reshare a secret." 2024. <https://alinush.github.io/2024/04/26/How-to-reshare-a-secret.html>
