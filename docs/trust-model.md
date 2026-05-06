# ACE Trust Model

This document is the threat model for the ACE protocol — who is trusted, what they're trusted for, what an adversary can do, and what specifically is *not* protected.

For cryptographic constructions, see [`crypto-spec.md`](./crypto-spec.md). For protocol state machines, see [`protocols.md`](./protocols.md).

---

## 0. Deployment model

This version of ACE is a **permissioned protocol**. Operators are explicitly admitted by the existing committee (or by the admin in the bootstrap epoch) via on-chain proposals + threshold-vote approval (`network::new_proposal` + `voting::vote`). There is no on-chain reward, fee, or stake mechanism for operators; the design assumes operators are **incentivized by default** — typically because they are members of a consortium, app developers running their own workers for their own applications, or compensated out-of-band by the admin.

**Implications for the threat model.**

- **Sybil resistance is operational, not cryptoeconomic.** The protocol does not gate operator admission on stake, work, or external identity. The committee's vote *is* the gate. An admin or supermajority that admits unqualified operators bypasses ACE's security entirely.
- **No on-chain accountability.** A misbehaving operator (returns wrong shares, refuses to deal, refuses to ACK) is removed via `CommitteeChange`, not by automatic slashing. ACE has no "punish a worker" primitive.
- **Operators trust other operators institutionally.** The committee is small (typically 3–10), known to each other, and aligned by incentives outside the protocol.
- **Threat actors are a *subset* of admitted operators**, plus the usual external parties (decryption requesters, RPC providers, chain validators).

**A permissionless variant** would need to add: stake / bond, on-chain rewards (per-decryption-share fee, per-DKG fee), slashing rules tied to verifiable misbehavior, and a Sybil-resistant admission gate. None of those are in this version. Auditors should not flag the absence of these mechanisms; the rest of the document assumes the deployment model above.

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

### 3.1 The end user (decrypter)

**Can:**
- Construct an arbitrary proof-of-permission and submit it to all workers.
- Reuse an `(account_addr, signature)` pair across multiple `(keypairId, epoch, contractId, domain, ephemeralEncKey)` tuples — but the signature *covers* all five, so the proof is only valid for the exact tuple it was signed for.
- Choose any `ephemeralEncKey`; the IDK shares will be encrypted to whatever they specified.

**Cannot:**
- Recover the master secret without colluding with `t` workers.
- Force a worker to release a share for a request the on-chain `check_permission` rejects.
- Replay a captured Solana proof-txn — Solana's `simulateTransaction` with `sigVerify=true` checks the txn signature against the **current** account state and a recent blockhash; a stale blockhash → simulation rejects.

### 3.2 An operator (single, malicious)

**Can:**
- Refuse to serve. Workers are unable to compel each other.
- Return a wrong IDK share. The SDK detects this via the share-verification pairing check (§3.1/§3.2 of `crypto-spec.md`) and discards the bad share.
- Withhold their dealer contribution in DKG/DKR — this stalls *that* worker's contribution but as long as `t` other dealers complete, the joint secret is still established.
- See every decryption request that hits *their* worker (request body, including the proof-of-permission, ephemeral pubkey, and the requested `(keypair_id, epoch, identity)`). They learn **what** is being decrypted by **whom**, but not the plaintext.

**Cannot:**
- Decrypt anything alone.
- Pollute the master public key (DKG-protected) or secret reshares (DKR + sigma-dlog-eq protected).
- Cause a false positive on `check_permission` (workers verify on-chain independently; one worker's lie has no effect on the others).

### 3.3 A `t-1` malicious-operator coalition

**Can:** all of the above, in aggregate. Specifically:
- Stall any decryption by collectively refusing.
- DOS the DKG/DKR by collectively refusing to deal — but the protocol still completes if at least `t` honest workers deal.
- Stall an epoch transition for an extended period **if** they're a majority of the *next* committee that needs to receive shares (the resharing VSS needs `t` recipient ACKs).

**Cannot:**
- Decrypt any ciphertext on their own.
- Forge a master public key.
- Make a "false-positive" share — the share-verification pairing check on the SDK side prevents accepting wrong shares from any source, including a `t-1` coalition.

### 3.4 A `t` malicious-operator coalition

> **Trust assumption is broken.** A `t-of-n` coalition can reconstruct any master secret from the epoch they all hold shares for, and decrypt every ciphertext bound to those `keypair_id`s. They can also collude with the admin to push a `CommitteeChange` proposal that admits more colluders.

The protocol does not protect against this. Defense is purely operational (committee composition, geographic / organizational diversity).

### 3.5 The admin

**Can:**
- Deploy / upgrade the ACE contract. **A malicious upgrade can change `check_permission` semantics, alter the view function being called, or extract worker secrets via a new view that they re-add to `worker_config`.** The contract's upgrade policy on Aptos is a critical control.
- Propose committee changes (with voting threshold approval).
- Set `epoch_duration_micros` (subject to `MIN_RESHARING_INTERVAL_SECS = 30s`).

**Cannot:**
- Decrypt anything. Admin holds no shares, no PKE dk, no t-IBE secret.
- Bypass the voting threshold for committee changes (admin proposals also require committee votes per `network::touch`).
- Freeze the protocol — any committee member can also propose; epoch transitions auto-trigger on `epoch_duration_micros` expiry even with no admin or committee action.

### 3.6 The RPC provider (per chain, per worker)

> **This is the thinnest part of the trust model.** A malicious RPC provider that the worker queries can return:
> - Arbitrary view-function results (turning `check_permission` from `false` to `true`, or vice versa).
> - Arbitrary chain state (forge that an account's `authentication_key` matches a different public key, accepting a forged signature).
> - Arbitrary `simulateTransaction` results on Solana.

A worker's defense is to run its own fullnode or to trust a fullnode operator they trust. Workers that share an RPC provider with their adversary inherit that provider's trust assumptions.

This is documented in the README (`README.md:288-294`) but should be repeated in every operator-onboarding flow. Auditors should treat any deployment running on a third-party RPC as having a single point of compromise per chain. Mitigation in scope: the worker's own fullnode. Mitigation **not** in scope: light-client verification, fraud proofs, multi-RPC quorum.

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

The SDK's network manager (`ts-sdk/src/_internal/common.ts`) sends to **all** committee workers in parallel and uses the first `t` responses, so a single malicious worker that ignores or stalls requests does not learn more than its honest peers.

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
