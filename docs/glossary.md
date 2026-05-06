# ACE Glossary

Definitions of terms and symbols used across all ACE specification documents. When a doc uses a term without further explanation, this is the source. Each entry notes which doc(s) use the term most.

---

## Identifiers and labels

- **`keypair_id`** — On-chain Aptos address of the **DKG session** that established a particular master secret. Acts as a stable identifier for the `(mpk, master_secret)` pair throughout its lifetime, including across DKR-based reshares: the new DKR session generates fresh share-PKs and updates which committee holds the secret, but the `keypair_id` remains the original DKG's address. Used by the SDK, app contracts, and t-IBE encryption identity. *(Used everywhere.)*

- **`contract_id`** — Application-defined tuple identifying the access-control contract that gates decryption.
  - **Aptos:** `(chain_id: u8, module_addr: address, module_name: string, function_name: string)`. The view function called as `{module_addr}::{module_name}::{function_name}(...)`.
  - **Solana:** `(known_chain_name: string, program_id: bytes)`. The Anchor program whose instruction the proof-of-permission must call.

- **`label`** *(also: app-specific label)* — Application-chosen bytes that scope a ciphertext within a `(keypair_id, contract_id)`. Two different labels bound to the same `(keypair_id, contract_id)` produce independent ciphertexts; the contract's view function receives `label` and uses it to look up access records (e.g. "who paid for blob X"). *Wire-format note: the basic-flow request struct names this field `domain` for historical reasons; the Move side has always called it `label`. The spec docs use `label` throughout.*

- **`identity`** *(IBE identity)* — The bytes hashed to a curve point $Q_{\text{id}}$ in t-IBE. Computed as `keypair_id || BCS(contract_id) || BCS(label)`. Same identity → same $Q_{\text{id}}$; different identities → independent IBE ciphertexts.

- **`epoch`** — A `u64` counter on the network state, monotonically incremented each time the orchestrator completes a committee change or auto-resharing. Workers in epoch $e$ hold shares of all currently-active master secrets at epoch $e$; shares from earlier epochs are not interchangeable. The decryption-request flow includes `epoch` so workers can serve stragglers from the just-prior epoch for ~30s after rotation.

- **`ephemeral encryption key`** *(per-request)* — A fresh PKE keypair the decryption requester generates for one decryption flow. IDK shares returned by workers are encrypted to it. Bound into the proof-of-permission so a captured proof cannot be replayed with a substituted ephemeral key.

- **`account_addr` / `userAddr`** — On-chain account address of the decryption requester (basic flow Aptos). Authenticates via Ed25519 signature; verified against the on-chain `authentication_key`.

---

## Roles and parties

- **App developer** — A team using ACE. Deploys an access-control contract, integrates the SDK. Off-chain only; not a protocol participant.

- **Encrypter / Decrypter** — End users (or their apps) at the two ends of an ACE flow. The encrypter computes a t-IBE ciphertext bound to a `(keypair_id, contract_id, label)`. The decrypter constructs a proof the contract will accept and runs the decryption-request flow.

- **Operator / worker** — Synonyms. Runs one worker process; holds an Ed25519 account key + a PKE decryption key + Shamir shares of every currently-active master secret. Participates in DKG, DKR, and serves decryption requests.

- **Committee** — The set of operators in the current epoch. Size $n$, secrecy/reconstruction threshold $t$ with $2t > n$.

- **Admin** — Controls the ACE Move package. Bootstraps the initial epoch; can propose committee changes (subject to vote). Holds no shares; cannot decrypt.

- **Dealer / recipient** *(in VSS context)* — Per-VSS roles. The dealer is the single party that publishes the polynomial commitment + per-recipient share ciphertexts. Recipients receive their encrypted shares, Feldman-verify, and ACK on-chain. In DKG every committee member is a dealer in their own VSS and a recipient in everyone else's.

---

## Cryptographic objects

- **Master secret** ($s$) — The secret the committee jointly holds. Output of a DKG; never instantiated in the clear by any single party. Shamir-shared as $s_i = f(i+1)$ over $\mathbb{F}_r$.

- **Master public key** ($\mathsf{mpk}$) — The public counterpart of $s$, equal to $s \cdot B$ where $B$ is the DKG basepoint. Stored on-chain; the user encrypts under it via t-IBE.

- **Share** ($s_i$) — Committee member $i$'s scalar share of the master secret. Held off-chain. Re-derivable by member $i$ from on-chain VSS messages by decrypting their shares with their PKE decryption key.

- **Share-PK** ($s_i \cdot B$) — Public commitment to a share. Stored on-chain (as `vss::share_pks` after the originating VSS reaches the success state). Used by the SDK to verify that a worker's released IDK share matches the committed share without leaking the share itself.

- **Basepoint** ($B$, sometimes $B_{\text{old}}$ / $B_{\text{new}}$) — Group generator (or a deterministic group element) such that $\mathsf{mpk} = s \cdot B$. Sampled fresh per fresh DKG via on-chain randomness; lives in BLS12-381 G1 (legacy path) or G2 (production path). DKR keeps the basepoint of its predecessor session; only DKG samples a new one.

- **IDK** *(Identity Decryption Key)* — $s \cdot Q_{\text{id}}$. Reconstructed from $\geq t$ IDK shares via Lagrange interpolation in the appropriate group; consumed by the t-IBE decrypt path.

- **IDK share** — $s_i \cdot Q_{\text{id}}$. What worker $i$ returns over HTTP for a permitted decryption request. Lives in G2 (legacy t-IBE) or G1 (production t-IBE).

- **Polynomial commitment** ($\{v_k\}_{k=0..t-1}$) — The Feldman commitment vector $v_k = a_k \cdot B$, where $\{a_k\}$ are the dealer's polynomial coefficients. Published on-chain in the dealer's first-round VSS message.

- **Lagrange coefficient** ($\lambda_i$) — Scalar in $\mathbb{F}_r$ that interpolates a polynomial at $x = 0$ from a set of evaluations: $\lambda_i = \prod_{j \neq i} (-x_j) / (x_i - x_j)$. Used to reconstruct the master secret (DKR) or the IDK (t-IBE decrypt).

- **$Q_{\text{id}}$** — The hash-to-curve image of the IBE identity. Lives in G2 (legacy) or G1 (production).

- **$\mathbb{F}_r$** — Scalar field of BLS12-381, prime order $r \approx 2^{252}$.

- **Polynomials.** $f$ is the dealer's secret-bearing polynomial in a VSS; $f(0)$ is the secret. In DKR, $g_j$ is old node $j$'s fresh resharing polynomial with $g_j(0) = s_j$; $F = \sum_j \lambda_j g_j$ is the implicit reshared polynomial with $F(0) = s$.

---

## Sub-protocols and acronyms

- **VSS** — Verifiable Secret Sharing. Single-dealer building block. See [`crypto-spec.md`](./crypto-spec.md) §4 and [`protocols.md`](./protocols.md) §2.

- **DKG** — Distributed Key Generation. $n$ parallel VSS sessions; output is a fresh master secret jointly held. See [`protocols.md`](./protocols.md) §3.

- **DKR** — Distributed Key Resharing. $n_{\text{curr}}$ parallel resharing-VSS sessions from old committee to new; the master secret is **the same** as before, just held by a different committee. Acronym: D = Distributed, K = Key, R = Resharing — note "DKR resharing" is redundant. See [`crypto-spec.md`](./crypto-spec.md) §4.0.1, [`protocols.md`](./protocols.md) §4.

- **PSS / PVSS** — Proactive Secret Sharing / Publicly Verifiable Secret Sharing. Academic umbrella terms; ACE's DKR is a PSS instance.

- **t-IBE** — Threshold Identity-Based Encryption. The user-facing layer; see [`crypto-spec.md`](./crypto-spec.md) §3.

- **BF-IBE** — Boneh–Franklin IBE. The construction family ACE's t-IBE belongs to.

- **PKE** — Public-Key Encryption. The transport layer used inside ACE for VSS share messages and decryption-request bodies. See [`crypto-spec.md`](./crypto-spec.md) §2.

- **HPKE** — Hybrid Public Key Encryption (RFC 9180). ACE's production PKE.

- **AEAD** — Authenticated Encryption with Associated Data.

- **KEM / KDF / DEM** — Key Encapsulation Mechanism / Key Derivation Function / Data Encapsulation Mechanism. The three layers of an HPKE-style construction.

- **PCS** — Polynomial Commitment Scheme. ACE uses Feldman.

- **BCS** — Binary Canonical Serialization (Aptos). The deterministic on-the-wire encoding used by every ACE protocol message. See [`wire-formats.md`](./wire-formats.md) §0.

- **MSM** — Multi-Scalar Multiplication. On-chain operation `Σ_k c_k · P_k` over a group; used by Move to verify Feldman openings and to derive share-PKs.

---

## Proofs

- **Proof-of-permission** — The user-supplied evidence a worker uses to decide whether to release its IDK share.
  - **Aptos basic flow:** Ed25519 signature over a pretty-printed `DecryptionRequestPayload` covering `(keypair_id, epoch, contract_id, label, ephemeralEncKey)`.
  - **Solana basic flow:** A structurally-valid (but unsubmitted) Solana transaction calling the configured Anchor program with instruction data containing `FullRequestBytes`. The worker validates structure + simulates with `sigVerify=true`.
  - **Aptos custom flow:** Arbitrary bytes the contract's `check_acl(label, encPk, payload)` will validate.
  - **Solana custom flow:** Like basic, but with `CustomFullRequestBytes` and the program's `assert_custom_acl` instruction.

- **Resharing-dealer challenge** — The binding that forces a DKR dealer to reshare a *specific* known share rather than a fresh secret. Geometrically: a pair $(P = s_j \cdot B_{\text{old}}, H = \mathsf{HashToCurve}(P))$, plus a Sigma-DLog-Eq proof from the dealer that the new polynomial's constant term $a_0$ equals $s_j$. See [`crypto-spec.md`](./crypto-spec.md) §4.3 and §5.

- **Sigma-DLog-Eq** — Discrete-log equality proof. Convinces a verifier that two pairs $(B_0, P_0)$ and $(B_1, P_1)$ share a common scalar $s$ such that $P_0 = s B_0$ and $P_1 = s B_1$, without revealing $s$. Implemented via Schnorr commitments + Fiat–Shamir.

---

## Numeric constants and parameters

- **$t$, $t'$** — Secrecy/reconstruction threshold, current and next epoch. The protocol requires $2t > n$.
- **$n$, $n'$** — Committee size, current and next epoch.
- **$\Delta$** — Synchrony bound between honest parties (paper notation). In ACE realized as `ACK_WINDOW_MICROS = 10s` (the time a dealer waits for ACKs before opening shares publicly).
- **$\kappa$** — Cryptographic security parameter. ACE's primitives target $\kappa \approx 128$ throughout.
- **`MIN_RESHARING_INTERVAL_SECS = 30`** — Lower bound on the auto-rotation period (`epoch_duration_micros`).
- **Per-worker HTTP timeout** — 8 seconds in the SDK's decryption fan-out (`AbortController` per fetch).

---

## Network / chain terms

- **L1** — Layer-1 blockchain. ACE depends on the Aptos L1 for its orchestration state, BFT consensus, on-chain randomness, and timestamps. Solana appears only as a *target* chain for proof-of-permission verification — ACE itself does not run on Solana.
- **chain_id** — The Aptos chain identifier (1 = mainnet, 2 = testnet, 4 = local devnet, etc.). Bound into the Sigma-DLog-Eq Fiat–Shamir transcript to prevent cross-chain replay.
- **Aptos `randomness`** — On-chain randomness primitive used to sample fresh DKG basepoints. Itself a threshold protocol; trust assumption: Aptos validator quorum is honest.
- **`view function`** — Move read-only function callable by RPC. Workers use these to read on-chain state without submitting transactions.
- **`simulateTransaction`** — Solana RPC call that runs a transaction in a fresh state without committing it. ACE workers use it (with `sigVerify=true`) to verify the user's signed Solana txn without sending it on-chain.

---

## How to use this glossary

- The four spec docs link here from their headers. When you hit an undefined term, check here first.
- This file is the canonical source for cross-doc terms. If a doc redefines a term inconsistently with this glossary, the doc is wrong.
- Implementation type names (Move struct fields, Rust types, TS classes) are NOT in scope here — see the source for those. This glossary covers protocol-level concepts only.
