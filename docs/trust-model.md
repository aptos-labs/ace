# ACE Trust Model

This document is the threat model for the ACE protocol — who is trusted, what they're trusted for, what an adversary can do, and what specifically is *not* protected.

For cryptographic constructions, see [`crypto-spec.md`](./crypto-spec.md). For protocol state machines, see [`protocols.md`](./protocols.md).

---

## 0. Deployment model

This version of ACE is a **permissioned protocol**. Operators are explicitly admitted by the existing committee (or by the admin in the bootstrap epoch) via on-chain proposals + threshold-vote approval. There is no on-chain reward, fee, or stake mechanism for operators; the design assumes operators are **incentivized by default** — typically because they are part of a consortium that wants the system to exist, or are compensated out-of-band by the admin.

**Implications for the threat model.**

- **Sybil resistance is operational, not cryptoeconomic.** The protocol does not gate operator admission on stake, work, or external identity. The committee's vote *is* the gate. An admin or supermajority that admits unqualified operators bypasses ACE's security entirely.
- **No on-chain accountability.** A misbehaving operator (returns wrong shares, refuses to deal, refuses to ACK) is removed via committee-change vote, not by automatic slashing. ACE has no "punish a worker" primitive.
- **Operators trust other operators institutionally.** The committee is small (typically 3–10), known to each other, and aligned by incentives outside the protocol.
- **Threat actors are a *subset* of admitted operators**, plus the usual external parties (decryption requesters, RPC providers, chain validators).

---

## 1. Actors

| Actor | What they hold | What they're trusted for |
|-------|----------------|--------------------------|
| **App developer** | The Move/Anchor access-control contract; the encryption key (public) | Writing a contract whose `check_permission` / `check_acl` view function returns `true` only for legitimate decryption requests. **Their contract is the access gate; ACE just enforces what the contract says.** |
| **End user (encrypter)** | The plaintext; the contract address it's bound to | Choosing the right contract + label for their privacy goal. |
| **End user (decrypter)** | A valid permission predicate (signature / ZK proof / Solana txn) | Constructing a request the contract will accept. |
| **Operator** | One Ed25519 account-signing key + one PKE decryption key + one Shamir share of every active master secret per epoch | Running a worker that (a) participates honestly in DKG/DKR, (b) only releases IDK shares to requests that pass on-chain `check_permission`/`check_acl`, (c) cooperates in epoch transitions. |
| **Admin** | Permissions to deploy the ACE contract, propose committee changes, and trigger initial epoch | Bootstrapping; admitting/rotating operators; setting `epoch_duration_micros`. |
| **RPC provider** | API endpoint(s) the worker queries to verify proofs | **In production: trusted to return correct view-function results and correct chain state.** This is the weakest link in the trust chain — covered below. |
| **Aptos validators / Solana validators** | The chain itself | Truth about contract state. ACE reduces its security to the chain's. |

The actors not on this list — block explorer operators, gas station providers, package registries — are intentionally outside the trust boundary.

---

## 2. Core security claims

### Claim 1: Threshold confidentiality

> **No coalition of `t-1` operators in a given epoch can decrypt any ciphertext encrypted to a master public key from that epoch's DKG/DKR.**

This reduces to:
- Boneh–Franklin IBE security on BLS12-381 (§3 of [`crypto-spec.md`](./crypto-spec.md)) under the BDH assumption + ROM.
- Shamir secret sharing's (`t-1`)-privacy.
- The honesty of the DKG: with at least `t` honest dealers contributing, the master secret is uniformly random in Fr from the adversary's viewpoint.

A coalition of size `t-1` learns at most `t-1` Lagrange-shares of the master secret, which gives them no information about `s` itself, so cannot reconstruct any `idk = s · Q_id`.

### Claim 2: Permission-gated decryption

> **A worker only releases an IDK share for a `(keypair_id, epoch, identity)` triple if the on-chain `check_permission` (basic flow) or `check_acl` (custom flow) view function returns `true` for that exact request.**

Enforced by `worker-components/network-node/src/verify.rs::verify_basic` / `verify_custom`. For Aptos, this means a successful Aptos view-function call returning literal `true`. For Solana, this means a successful `simulateTransaction` with `sigVerify=true` against a known-program-id instruction whose embedded request bytes match.

### Claim 3: No replay across sessions

> **A captured proof-of-permission cannot be replayed by a different requester or to extract a share encrypted to a different ephemeral public key.**

For Aptos: the Ed25519 signature covers the pretty-printed message including `keypairId`, `epoch`, `contractId`, `domain`, **and `ephemeralEncKey`**. Substituting any field invalidates the signature. (`worker-components/network-node/src/verify.rs::aptos_decryption_request_message`.)

For Solana: the program instruction binds `keypair_id`, `epoch`, `enc_pk` (ephemeral key), and `domain` (or `label`) into the data, and the worker compares those bytes against its own reconstruction. (`ace_anchor_kit::build_full_request_bytes`.)

### Claim 4: No silent dealer cheating

> **A VSS dealer that publishes inconsistent shares (one polynomial encrypted to recipient `i`, a different polynomial committed in `pcs_commitment`) is detected.**

Recipients run Feldman verification (`worker-components/vss-common/src/vss_types.rs::feldman_verify`) before ACKing. A failed verification leads to the recipient *not* ACKing within `ACK_WINDOW_MICROS = 10s`; the dealer must then publicly reveal the share (via `on_dealer_open`), and Move re-runs Feldman verification on-chain (`vss::touch`) before promoting the session to `STATE__SUCCESS`.

### Claim 5: No silent reshare from unknown source

> **A DKR dealer cannot reshare a secret it does not actually hold a share of.**

The resharing-VSS carries a `ResharingDealerChallenge { expected_scaled_element, another_base_element }` derived from the dealer's old `share_pk`. The dealer must produce a sigma DLog-Eq proof (§5 of `crypto-spec.md`) that the secret committed in the new VSS equals the secret behind `expected_scaled_element`. Verified on-chain in `vss::on_dealer_contribution_0`.

---

## 3. What each actor can do (and what they can't)

The §2 claims are organized by security guarantee; this section organizes the same surface by adversary class — the view auditors use when threat-modeling.

| Adversary class | Can | Cannot |
|-----------------|-----|--------|
| **Decrypter (single user)** | Submit any proof-of-permission to all workers; choose any ephemeral encryption key. | Recover the master secret. Force a worker to release a share for a request the on-chain `check_permission` / `check_acl` rejects. Replay a signed message across `(keypair_id, epoch, contract_id, domain, ephemeralEncKey)` tuples — the signature binds all five. Replay a captured Solana proof-txn — `simulateTransaction` checks against current account state and a recent blockhash. |
| **Single malicious operator** | Refuse to serve; return a wrong share (SDK detects via on-chain share-PK pairing check and discards); withhold their dealer contribution (protocol completes from $\geq t$ other dealers); see request metadata they handle. | Decrypt anything alone. Pollute the master public key (DKG/DKR-protected). Cause a false positive on `check_permission` for any other worker (each verifies independently on-chain). |
| **$t-1$ malicious-operator coalition** | All of the above in aggregate. Stall any decryption by collective refusal. Stall DKG/DKR by collective non-dealing (but the protocol completes if $\geq t$ honest workers deal). Stall an epoch transition if they form a recipient-blocking majority of the next committee. | Decrypt any ciphertext. Forge a master public key. Inject false-positive shares (SDK pairing-check rejects them, regardless of source). |
| **$t$ malicious-operator coalition** | **Trust assumption broken.** Reconstruct any master secret they hold shares for; decrypt every ciphertext bound to those `keypair_id`s. With admin collusion, push a committee-change proposal admitting more colluders. | — *(no protocol-level defense; mitigated only operationally — committee composition, organizational diversity)* |
| **Admin** | Deploy / upgrade the ACE contract (a malicious upgrade can change `check_permission` semantics or add an exfiltrating view — the upgrade policy on Aptos is the critical control). Propose committee changes (subject to vote). Set `epoch_duration_micros` ($\geq 30\,\text{s}$). | Decrypt anything (holds no shares). Bypass the voting threshold (admin proposals also require committee votes). Freeze the protocol — any committee member can also propose; auto-rotation triggers on epoch-duration expiry. |
| **RPC provider** | Return arbitrary view-function results, arbitrary chain state (e.g., forged `authentication_key`), arbitrary `simulateTransaction` results — to whichever worker queries them. **Thinnest part of the trust model.** | — *(defense is "run your own fullnode" or trust one you trust; light-client verification, fraud proofs, and multi-RPC quorum are out of scope.)* |

---

## 4. What is NOT protected

These are explicit non-goals or known limitations. Auditors should confirm they are documented elsewhere and not introduce surprise findings.

### 4.1 Plaintext length

Both PKE and t-IBE leak the plaintext length in their ciphertext size (no padding). Applications that need length-hiding must pad upstream.

### 4.2 Metadata privacy

Workers see, in plaintext:
- Every decryption request body (the proof-of-permission, the requester's `userAddr` for basic-flow Aptos, the ephemeral pubkey).
- The `(keypair_id, epoch, contract_id, domain)` of every request.

A worker that logs requests can reconstruct a per-user access pattern across all encrypted assets bound to that worker's committee. **There is no on-chain or off-chain mixing layer.** Applications that need access-pattern privacy (private information retrieval, oblivious workers) are out of scope.

The SDK fans out to **all** committee workers in parallel; each gets the same request body (encrypted under that worker's key). A single malicious worker that ignores or stalls a request learns no more than its honest peers — they all see the same metadata. See [`protocols.md`](./protocols.md) §8.6 for the latency model.

### 4.3 Front-running and timing

A worker that delays its response to gain visibility into other workers' responses or transaction order learns nothing exploitable: shares are encrypted to the requester's ephemeral pubkey, so even an eavesdropping worker cannot decrypt another worker's response.

The chain itself is subject to whatever ordering / front-running properties the underlying L1 (Aptos / Solana) has. ACE inherits these.

### 4.4 Long-term secret rotation

Master secrets rotate on every epoch (auto every `epoch_duration_micros` ≥ 30s, or on `CommitteeChange`). However:
- A *retired* committee member who held a share at epoch `e` retains that share's bytes on disk after they leave the committee. If `t-1` retired members for the same generation collude later with one current member that still holds a backwards-compatible share for any reason, decryption is possible. **The PKE decryption key derivation step (§4.2 of `crypto-spec.md`) deterministically derives polynomial coefficients from the dealer's PKE dk, so the dealer can always recover their old contributions while their PKE dk lives.** Operationally, deleting old shares from disk is the operator's responsibility; the protocol does not enforce it.
- See [`project_epoch_in_decryption_request`](../.claude/projects/-Users-zhoujun-ma-repos-aptos-labs-ace/memory/project_epoch_in_decryption_request.md) — workers retain old shares for ~30s after rotation to handle in-flight requests.

### 4.5 Sybil resistance and cryptoeconomic incentives

Per §0, ACE is permissioned and assumes external incentives for operators. Out of scope:

- **Sybil-resistant operator admission.** Anyone the committee votes in can join; the protocol does not check stake, work, or identity.
- **Per-request fees / rewards.** Workers do not earn on-chain rewards for serving decryption requests, dealing in DKG/DKR, or staying online.
- **Slashing for verifiable misbehavior.** Wrong shares, refusal to deal, or refusal to ACK are addressed by manual `CommitteeChange`, not by an automatic on-chain penalty.

A future permissionless variant that adds stake / rewards / slashing is a *different protocol*; the analysis here doesn't carry over.

### 4.6 Denial-of-service

The HTTP server has a concurrency semaphore (`worker-components/network-node/src/http_server.rs:36`) but no per-source rate limit, no PoW, no IP filtering. A worker exposed to the public internet can be DoS'd cheaply. Mitigations are operational (Cloud Run autoscaling, gateway rate limits) and not in the protocol layer.

### 4.7 Implementation faults

Out of scope for the protocol-level trust model:
- TS / Rust / Move bugs that break wire-format compatibility (covered by integration tests).
- A compromised operator-CLI machine during onboarding (the PKE dk is generated locally and submitted to the operator's container as an env var; if the local machine is compromised, all downstream security is too).
- Side channels in the underlying primitives (`@hpke/core`, `curve25519-dalek`, `ark-bls12-381`, etc.).

---

## 5. Cryptographic assumptions (in one place)

| Primitive | Assumption | Used by |
|-----------|------------|---------|
| ElGamal-OTP-Ristretto255 | DDH on Ristretto255 + ROM (KDF, HMAC) | PKE scheme 0 |
| HPKE-X25519-HKDF-SHA256-ChaCha20Poly1305 | RFC 9180 base-mode security: GapDH on X25519, HKDF-SHA256, ChaCha20-Poly1305 IND-CCA | PKE scheme 1 |
| BFIBE-BLS12381-ShortPK-OTP-HMAC | BDH on BLS12-381 + ROM, threshold via Shamir | t-IBE scheme 0 |
| BFIBE-BLS12381-ShortSig-AEAD | BDH on BLS12-381 + ROM, ChaCha20-Poly1305 IND-CCA | t-IBE scheme 1 |
| Sigma DLog-Eq | DLog on BLS12-381 + ROM (Fiat–Shamir) | VSS resharing |
| Feldman PCS | DLog on BLS12-381 (binding) | VSS share verification |
| Ed25519 | EUF-CMA (RFC 8032) | ProofOfPermission (Aptos) |
| Aptos chain | BFT honest 2/3 supermajority | Truth of view-function results |
| Solana chain | BFT honest 2/3 supermajority | Truth of `simulateTransaction` and account-state queries |
| Aptos `randomness` | Threshold honest validator quorum | DKG basepoint sampling on-chain (`epoch_change::touch`) |

A break of any of the above invalidates the corresponding claim in §2. The composition is no stronger than its weakest link.

---

## 6. Operator-side secret handling

The worker process expects two pieces of secret material at startup, both passed as CLI arguments today:

| Flag | Meaning | Lifetime |
|------|---------|----------|
| `--account-sk` | Ed25519 signing key for the worker's on-chain account | Long-lived (rotated only via re-onboarding) |
| `--pke-dk` | PKE decryption key (hex of the BCS-encoded `DecryptionKey`) | Long-lived (matches the public `EncryptionKey` registered in `worker_config`) |

(`worker-components/network-node/src/main.rs:42-46`.)

The operator-CLI's onboarding wizard (`operator-cli/src/onboarding.ts`) generates both secrets locally, prints a `gcloud run deploy` / `docker run` command that writes them as Cloud Run secrets / env vars, and registers the public counterparts on-chain.

**Audit hooks:**
- A worker that loses its `pke-dk` cannot be replaced with a fresh PKE dk without losing all its current Shamir shares (because share derivation is deterministic on the dk per §4.2 of `crypto-spec.md`). Recovery requires either a DKR (which fails if the worker's dk is unrecoverable and they hold above-threshold shares) or admin intervention via `CommitteeChange`.
- A leaked `pke-dk` reveals every Shamir share that worker has ever dealt — past *and* future, until they're rotated out.
- Storing the dk as a Cloud Run env var places trust in the cloud provider's secret-manager. Field-level KMS encryption is not currently used.

Recommended operator practices (not enforced):
- Run on a single-tenant VM or Cloud Run service.
- Use an HSM-backed signing key for `--account-sk` (custom worker build required).
- Rotate the `pke-dk` via re-onboarding on a fixed schedule; coordinate with the admin to time-align with `CommitteeChange`.

---

## 7. On-chain "contract is truth" caveat

The ACE worker treats the on-chain view-function result as gospel. Specifically:
- The worker calls `{moduleAddr}::{moduleName}::{functionName}(userAddr, domain)` (basic flow Aptos) or `{moduleAddr}::{moduleName}::{functionName}(label, encPk, payload)` (custom flow Aptos), via the configured RPC.
- A `bool == true` response → the worker releases its share.
- The worker does **not** sandbox, fuzz, or verify the view function semantically.

This means:
- A buggy `check_permission` is a security hole the protocol cannot mitigate.
- A maliciously-upgraded contract that broadens `check_permission` retroactively decrypts all prior content bound to that contract.

**Defense.** Apps SHOULD deploy `check_permission` as part of an immutable / governance-locked module. Aptos's package upgrade policies (`upgrade_policy: arbitrary` vs `compatible` vs `immutable`) are the primary control here. Auditors of an ACE-using application MUST check the upgrade policy on the access-control contract.

---

## 8. Glossary

- **Keypair-id** — On-chain address of the DKG session that established a master secret. Used as a stable identifier for the (master_pk, master_secret) pair across DKR-based reshares.
- **Epoch** — A monotonically-increasing counter on `network::State`. Workers in the current epoch hold shares of all currently-active master secrets. Shares from earlier epochs are not interchangeable.
- **Domain / Label** — Application-chosen bytes that scope a piece of ciphertext within a `keypair_id`. The contract receives these as `label` in its view function.
- **Identity (IBE)** — The IBE identity is the BCS-encoded triple `(keypair_id, contract_id, domain)`. Internally called `fdd_bytes` (FullDecryptionDomain bytes).
- **Ephemeral encryption key** — A fresh PKE keypair the requester generates for a single decryption flow; IDK shares are encrypted to it.
- **DKG / DKR / VSS** — see [`protocols.md`](./protocols.md).
