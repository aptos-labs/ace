# ACE Protocols

This document describes the on-chain state machines (VSS, DKG, DKR, voting, epoch-change, network) and the off-chain decryption-request flow. For cryptographic primitives, see [`crypto-spec.md`](./crypto-spec.md). For wire formats, see [`wire-formats.md`](./wire-formats.md).

> **Convention.** State-code values listed below are the literal `u8` constants in the corresponding Move module (`STATE__*`). Function signatures are abridged; see the source for full types.

---

## 1. Map of Move modules

| Module | File | Purpose |
|--------|------|---------|
| `ace::worker_config` | `contracts/worker_config/sources/worker_config.move` | Each worker registers `(endpoint, pke_enc_key)`. Read by `vss::new_session`, `network::start_initial_epoch`, etc. |
| `ace::vss` | `contracts/vss/sources/vss.move` | Single-dealer Verifiable Secret Sharing session. |
| `ace::dkg` | `contracts/dkg/sources/dkg.move` | Distributed Key Generation: composes `n` parallel VSS sessions. |
| `ace::dkr` | `contracts/dkr/sources/dkr.move` | Distributed Key Resharing: hands a secret from an old committee to a new one via `n_old` resharing-VSS sessions + Lagrange. |
| `ace::voting` | `contracts/voting/sources/voting.move` | Generic threshold-vote primitive. |
| `ace::epoch_change` | `contracts/epoch-change/sources/epoch_change.move` | Orchestrator that launches the DKR/DKG sessions for an epoch transition. |
| `ace::network` | `contracts/network/sources/network.move` | The top-level state: epoch, committee, active secrets, pending proposals. Drives `epoch_change`. |
| `ace::group` | `contracts/group/sources/group.move` (+ `group_bls12381_g1.move`, `group_bls12381_g2.move`) | Abstract `Element` enum over BLS12-381 G1 / G2; MSM, hash-to-curve, generators. |
| `ace::sigma_dlog_eq` | `contracts/sigma-dlog-eq/sources/sigma_dlog_eq.move` | Two-element DLog-equality verifier (used by VSS resharing). |
| `ace::pke` | `contracts/pke/sources/pke.move` | Decoders for `EncryptionKey` / `Ciphertext` enums (no on-chain encrypt or decrypt). |

---

## 2. VSS — Verifiable Secret Sharing (single dealer)

A single dealer commits to a degree-`t-1` polynomial over `Fr` and distributes Feldman-verifiable shares to `n` recipients. Used as a building block by DKG and DKR.

The state machine below implements §5 / Algorithm 1 of [Das, Xiang, Tomescu, Spiegelman, Pinkas, Ren — "Verifiable Secret Sharing Simplified", IACR ePrint 2023/1196](https://eprint.iacr.org/2023/1196), with the crypto-relevant modifications enumerated in [`crypto-spec.md`](./crypto-spec.md) §4.0 (Feldman PCS in place of generic `PC`, PKE-as-private-channel, the chain as broadcast channel, on-chain ACK, selective reveal as `Option<BcsScalar>` vector, resharing-dealer challenge for DKR).

### 2.1 Session struct (abridged)

`contracts/vss/sources/vss.move:89-104`

```move
struct Session {
    dealer: address,
    share_holders: vector<address>,
    threshold: u64,
    public_base_element: group::Element,            // basePoint for the Feldman commitment
    resharing_challenge: Option<ResharingDealerChallenge>,  // present only for DKR-spawned VSS
    state_code: u8,
    deal_time_micros: u64,                          // set when DC0 arrives
    dealer_contribution_0: Option<DealerContribution0>,
    share_holder_acks: vector<bool>,                // length = n
    dealer_contribution_1: Option<DealerContribution1>,
    share_pks: vector<group::Element>,              // computed during VERIFY_DEALER_OPENING
}
```

### 2.2 State machine

```
   ┌──────────────────────┐
   │  STATE__DEALER_DEAL  │ ← new_session_entry()
   └──────────┬───────────┘
              │ on_dealer_contribution_0(payload)
              │   • verifies ResharingDealerChallenge if present (sigma-dlog-eq)
              │   • records deal_time_micros
              ▼
   ┌────────────────────────────┐
   │   STATE__RECIPIENT_ACK     │
   └──────┬─────────────────────┘
          │ on_share_holder_ack()  ← each recipient who Feldman-verifies
          │ (toggles their ack flag; no state change)
          │
          │ on_dealer_open(payload)  ← after ACK_WINDOW_MICROS = 10s
          │   • requires ≥ threshold acks
          │   • requires every non-acker has a revealed share in payload
          ▼
   ┌──────────────────────────────────────┐
   │ STATE__VERIFY_DEALER_OPENING         │
   └──────┬───────────────────────────────┘
          │ touch()  (called repeatedly; one share_pk per call)
          │   for j in 0..n:
          │     if share_holder_acks[j]: derive share_pk[j] via on-chain MSM
          │     else: validate revealed share against MSM, then derive share_pk[j]
          │   when all n done:
          ▼
   ┌──────────────────────┐
   │   STATE__SUCCESS     │     ← share_pks fully populated
   └──────────────────────┘
```

`STATE__FAILED` is defined (`vss.move:53`) but currently unreachable; the dealer-open path always converges given enough acks.

### 2.3 Entry function summary

| Function | Caller | Pre-state | Post-state | Notes |
|----------|--------|-----------|------------|-------|
| `new_session_entry(dealer, share_holders, threshold, base_point, secretly_scaled_element)` | any | n/a | `DEALER_DEAL` | All share_holders must have a registered `pke_enc_key`. `secretly_scaled_element=None` for fresh DKG; `Some(s · basePoint_old)` for DKR (becomes the resharing challenge's `expected_scaled_element`). |
| `on_dealer_contribution_0(session_addr, payload)` | session.dealer only | `DEALER_DEAL` | `RECIPIENT_ACK` | Aborts if resharing-challenge sigma-dlog-eq verification fails. |
| `on_share_holder_ack(session_addr)` | any holder in `share_holders` | `RECIPIENT_ACK` | (same) | Toggles `share_holder_acks[idx] = true`. |
| `on_dealer_open(session_addr, payload)` | session.dealer only | `RECIPIENT_ACK`, `now ≥ deal_time_micros + 10s`, `acks ≥ threshold`, every holder either acked or revealed | `VERIFY_DEALER_OPENING` | Reveals scalar shares for every non-acker. |
| `touch(session_addr)` | any | `VERIFY_DEALER_OPENING` | `VERIFY_DEALER_OPENING` (loop) or `SUCCESS` | Computes one `share_pk` per call (gas budget). |

### 2.4 Failure modes and operator response

- **Dealer never sends DC0.** Session stuck in `DEALER_DEAL`. The composing protocol (DKG / DKR) tolerates this — only `t` of `n` VSS need to complete. The owning DKG `touch` will see this VSS not in `STATE__SUCCESS` and skip it.
- **Recipient cannot decrypt the share message** (PKE decryption fails or Feldman verification fails). Recipient MUST NOT call `on_share_holder_ack`. After the 10s window, dealer opens the share publicly; if the publicly-revealed share also fails on-chain Feldman verification, `on_dealer_open` aborts with `E_INVALID_SHARE` and the VSS session is unrecoverable. (Composing protocol then proceeds without this VSS.)
- **`< threshold` recipients ack within the window.** `on_dealer_open` aborts with `E_NOT_ENOUGH_ACKS`. The composing protocol skips this VSS.

---

## 3. DKG — Distributed Key Generation

`contracts/dkg/sources/dkg.move`. Composes `n` parallel VSS sessions: each worker is a dealer in one VSS and a recipient in all `n`. The joint master secret is `Σ_{k done} a_0^(k)` for the `t`+ contributing dealers; share `i` for worker `i` is `Σ_{k done} f_k(i+1)` where `f_k` is dealer `k`'s polynomial.

### 3.1 Session struct (abridged)

`dkg.move:43-56`

```move
struct Session {
    caller: address,
    workers: vector<address>,
    threshold: u64,
    public_base_element: group::Element,
    state: u8,
    vss_sessions: vector<address>,      // one per worker; built lazily
    done_flags: vector<bool>,            // populated when entering AGGREGATE
    secretly_scaled_element: Option<group::Element>,  // = master_pk; set when AGGREGATE entered
    share_pks: vector<group::Element>,   // one per worker; built lazily in AGGREGATE
}
```

### 3.2 State machine

```
   ┌──────────────────────┐
   │ STATE__START_VSSS    │ ← new_session_entry()
   └──────┬───────────────┘
          │ touch()  (lazy: one VSS::new_session per call)
          │   for idx in 0..n:
          │     vss::new_session(dealer = workers[idx],
          │                      share_holders = workers,
          │                      threshold,
          │                      base_point = public_base_element,
          │                      secretly_scaled_element = None)
          │   when idx == n:
          ▼
   ┌──────────────────────────────┐
   │  STATE__VSS_IN_PROGRESS      │
   └──────┬───────────────────────┘
          │ touch()
          │   done = count(vss::completed(vs) for vs in vss_sessions)
          │   if done >= threshold:
          │     done_flags := [vss::completed(vs) for vs in ...]
          │     master_pk := Σ vss::result_pk(vs) for done vs
          ▼
   ┌──────────────────────────────────┐
   │ STATE__AGGREGATE_SHARE_PKS       │
   └──────┬───────────────────────────┘
          │ touch()  (one share_pk per call)
          │   for j in 0..n:
          │     share_pks[j] := Σ vss::share_pks(vs)[j] for done vs
          │   when j == n:
          ▼
   ┌──────────────────────┐
   │   STATE__DONE        │
   └──────────────────────┘
```

Plus `STATE__FAIL` reached only via `cancel(caller, ...)` (`dkg.move:161-167`).

### 3.3 Worker behavior

Each worker monitors `network::state_view_v0_bcs`, sees DKG sessions where it is in `workers`, and runs the matching dealer + recipient roles concurrently:

- **Dealer role** (`worker-components/vss-dealer/src/lib.rs`): builds `DealerContribution0` (commitments + per-recipient ciphertexts + dealer state ciphertext); after `ACK_WINDOW_MICROS`, builds `DealerContribution1` revealing shares of non-ackers.
- **Recipient role** (`worker-components/vss-recipient/src/lib.rs`): for each VSS where the worker is a holder, fetches DC0 from the chain, decrypts its share, runs Feldman verification, calls `on_share_holder_ack` if good.
- **Touch role** (`worker-components/dkg-worker/src/lib.rs`): periodically calls `dkg::touch` to drive the state machine.

### 3.4 Output

After `STATE__DONE`:
- `master_pk = secretly_scaled_element` (call `dkg::params_for_resharing` or compose via `network::state_view_v0`).
- Each worker reads its share via `share_reconstruction::reconstruct_share` (`worker-components/vss-common/src/share_reconstruction.rs`):
  ```
  share_i := Σ_{k: done_flags[k]} decrypt_pke(dk, vss[k].private_share_messages[my_idx]).y
  ```
  and `share_pk_i = share_i · public_base_element` (also available on-chain in `dkg::share_pks`).

---

## 4. DKR — Distributed Key Resharing

`contracts/dkr/sources/dkr.move`. Re-distributes an existing master secret from an old committee `(curr_nodes, t_curr)` to a new committee `(new_nodes, t_new)`, **without** the secret ever existing in cleartext. Each old worker runs one resharing-VSS as dealer, with the resharing challenge bound to their own old share PK.

### 4.1 Session struct (abridged)

`dkr.move:26-48`

```move
struct Session {
    caller: address,
    public_base_element: group::Element,        // copied from previous DKG/DKR
    secretly_scaled_element: group::Element,    // = master_pk being reshared
    original_session: address,                  // root DKG (for keypair_id stability)
    previous_session: address,                  // direct predecessor (DKG or DKR)
    current_nodes: vector<address>, current_threshold: u64,    // old committee
    new_nodes: vector<address>,     new_threshold: u64,        // new committee
    state_code: u8,
    src_share_pks: vector<group::Element>,      // pre-fetched share_pks of previous_session
    vss_sessions: vector<address>,              // one per old node
    vss_contribution_flags: vector<bool>,
    lagrange_coeffs_at_zero: vector<group::Scalar>,
    share_pks: vector<group::Element>,          // per new node
}
```

### 4.2 State machine

```
   ┌──────────────────────┐
   │ STATE__START_VSSS    │ ← new_session_entry()
   └──────┬───────────────┘
          │ touch()  (lazy: one VSS::new_session per call)
          │   for idx in 0..n_curr:
          │     vss::new_session(dealer = current_nodes[idx],
          │                      share_holders = new_nodes,
          │                      threshold = new_threshold,
          │                      base_point = public_base_element,
          │                      secretly_scaled_element = Some(src_share_pks[idx]))
          │     # ↑ this becomes the resharing challenge; dealer must prove they
          │     #   know the secret behind src_share_pks[idx]
          │   when idx == n_curr:
          ▼
   ┌──────────────────────────────┐
   │ STATE__VSS_IN_PROGRESS       │
   └──────┬───────────────────────┘
          │ touch()
          │   done = #completed VSS
          │   if done >= current_threshold:
          ▼
   ┌──────────────────────────────────────┐
   │ STATE__CALC_LAGRANGE_COEFFS          │  (single touch)
   └──────┬───────────────────────────────┘
          │ touch()
          │   contributing := { j : vss_contribution_flags[j] }
          │   evals := { j+1 : j in contributing }    in Fr
          │   lagrange_coeffs_at_zero := { Π_{k≠i} (-evals[k])/(evals[i]-evals[k]) }
          ▼
   ┌──────────────────────────────────────┐
   │ STATE__AGGREGATE_SHARE_PKS           │
   └──────┬───────────────────────────────┘
          │ touch()  (one new-node share_pk per call)
          │   for new_idx in 0..n_new:
          │     share_pks[new_idx] := MSM(
          │         vss[j].share_pks[new_idx]  for j in contributing,
          │         lagrange_coeffs_at_zero
          │     )
          │   when new_idx == n_new:
          ▼
   ┌──────────────────────┐
   │   STATE__DONE        │
   └──────────────────────┘
```

The reshared master_pk is unchanged: `secretly_scaled_element` is copied from the previous session. Auditors can verify this by checking that `vss[j].result_pk()` for each contributing `j` equals `src_share_pks[j]`, and that the new committee can recover the same master secret via Lagrange-at-zero.

### 4.3 Worker behavior

Same three roles as DKG (dealer / recipient / touch) but each old-committee worker is also a dealer who **must** include a correct sigma-dlog-eq proof that they know the share `s_j` behind `src_share_pks[j]`. The dealer's polynomial constant term `a_0` is forced to equal `s_j` by the proof; non-constant coefficients are still derived deterministically from `pke_dk`.

---

## 5. Voting

`contracts/voting/sources/voting.move`. Generic `t-of-n` boolean voting primitive used by `network::new_proposal`. Trivial:

```
   STATE__ACCEPTING_VOTES → (touch passes when count(votes) ≥ threshold)
                          → STATE__PASSED
                          → (or owner.cancel())
                          → STATE__CANCELLED
```

A voter calls `vote(proposal_addr)` exactly once. `cancel(proposal_addr)` is owner-only.

---

## 6. epoch_change

`contracts/epoch-change/sources/epoch_change.move`. Orchestrates the multi-session sequence that an epoch transition needs: zero or more DKR (one per secret to reshare) + zero or more DKG (one per fresh secret in the new epoch).

### 6.1 Session struct (abridged)

```move
struct Session {
    caller, cur_nodes, cur_threshold,
    nxt_nodes, nxt_threshold,
    nxt_epoch_duration_micros,
    secrets_to_reshare: vector<address>,       // DKG/DKR session addresses
    new_secret_schemes: vector<u8>,            // group schemes for fresh DKGs
    state_code: u8,
    dkgs: vector<address>,
    dkrs: vector<address>,
}
```

### 6.2 State machine

```
   STATE__START_DKRS        → touch() lazily creates one dkr::new_session per secret_to_reshare
   STATE__START_DKGS        → touch() lazily creates one dkg::new_session per new_secret_scheme
                              (each fresh DKG uses a freshly-sampled basePoint via aptos_framework::randomness)
   STATE__AWAIT_SUBSESSION_COMPLETION
                            → touch() polls; if all (dkrs + dkgs) report completed(), transition
   STATE__DONE              → results() returns the new secrets list to network
```

---

## 7. network — committee, epoch, top-level state

`contracts/network/sources/network.move`. Owns the global ACE state singleton.

### 7.1 State

`network.move:47-57`

```move
struct State {
    epoch: u64,
    epoch_start_time_micros: u64,
    epoch_duration_micros: u64,
    cur_nodes: vector<address>,
    cur_threshold: u64,
    secrets: vector<address>,                 // active DKG/DKR sessions
    proposals: vector<Option<ProposalState>>, // length = n+1 (admin slot at index n)
    epoch_change_info: Option<EpochChangeInfo>,
}
```

A `ProposalState` carries a `ProposedEpochConfig` (next nodes, next threshold, fresh secret schemes, secrets to retain, target epoch) and the address of its `voting::Session`.

### 7.2 Driver: `network::touch`

`network.move:230-308`

```
if epoch_change_info.is_some():
    if epoch_change::completed(info.session_addr):
        # apply results
        epoch     += 1
        cur_nodes  = info.nxt_nodes
        cur_threshold = info.nxt_threshold
        secrets   = epoch_change::results(info.session_addr).secrets
        proposals = []
        epoch_change_info = None
        epoch_start_time_micros = now()
    else:
        return  # epoch_change::touch is responsible for progress
else:
    # 1. Touch all open voting sessions (drains threshold-met proposals)
    for proposal in proposals: voting::touch(proposal.voting_session)
    # 2. Look for the first completed (PASSED) voting session
    for i, proposal in enumerate(proposals):
        if voting::completed(proposal.voting_session):
            epoch_change_info = epoch_change::new_session(
                cur_nodes, cur_threshold,
                proposal.proposal.nodes, proposal.proposal.threshold,
                proposal.proposal.epoch_duration,
                secrets that aren't in secrets_to_retain → reshare,
                proposal.proposal.new_secrets schemes,
            )
            return
    # 3. No proposal accepted; auto-rotate if epoch duration expired
    if now() ≥ epoch_start_time_micros + epoch_duration_micros:
        epoch_change_info = epoch_change::new_session(
            cur_nodes, cur_threshold,
            cur_nodes, cur_threshold,           # identity committee change
            epoch_duration_micros,
            all current secrets → reshare,
            no new secrets,
        )
```

Key invariants:
- `epoch_change_info.is_some()` **and** `proposals.is_empty()` is the in-flight epoch state. New proposals are rejected while it's set (`E_EPOCH_CHANGE_ALREADY_IN_PROGRESS`).
- A node can only have one open proposal per epoch (`E_YOU_ALREADY_PROPOSED_IN_THIS_EPOCH`). Admin has a separate slot.

### 7.3 Proposal validation

`network.move:352-376` checks:
- `target_epoch == current epoch`
- `2t > n`, `t ≥ 2`, `t ≤ n` (Byzantine threshold preconditions)
- All next nodes are in `worker_config`
- `epoch_duration_micros ≥ MIN_RESHARING_INTERVAL_SECS = 30s`
- All `new_secrets` schemes are recognized by `group::`
- `secrets_to_retain ⊆ current secrets`

### 7.4 View functions

- `state_bcs() → Vec<u8>`: full `State` BCS.
- `state_view_v0_bcs() → Vec<u8>`: a richer composed snapshot. For each secret, fetches `(keypair_id, scheme)` via `dkg::keypair_id_and_scheme` or `dkr::keypair_id_and_scheme`. For each proposal, fetches `(votes, threshold)` via `voting::session_votes_and_threshold`. For an in-flight epoch change, includes `(nxt_nodes, nxt_threshold)` via `epoch_change::nxt_nodes_and_threshold`.

This view is the SDK's primary read path (`ts-sdk/src/_internal/network.ts`).

---

## 8. End-to-end decryption-request flow

The full flow that turns a user's "decrypt this ciphertext" intent into plaintext.

### 8.1 Encrypt (client side)

1. SDK reads on-chain state via `network::state_view_v0_bcs()` to find the active `(keypair_id, master_pk, scheme, epoch)` for the application's chosen `keypair_id`.
2. SDK validates that `master_pk`'s group matches the chosen t-IBE scheme (`tibe::MasterPublicKey::fromGroupElements`).
3. Computes IBE identity: `identity = keypair_id || BCS(contract_id) || BCS(domain)`.
4. Encrypts via `tibe::encrypt(master_pk, identity, plaintext)` (§3 of [`crypto-spec.md`](./crypto-spec.md)).

The output `Ciphertext` is what the application persists / publishes.

### 8.2 Decrypt — basic flow (Aptos)

```
SDK                                    Workers (n in committee, threshold t)
─────────────────────────────────      ─────────────────────────────────────────
(1) Generate ephemeral PKE keypair
    (encryptionKey, decryptionKey)

(2) Build DecryptionRequestPayload =
    { keypairId, epoch, contractId,
      domain, ephemeralEncKey }

(3) User signs `pretty(payload)`
    with their Ed25519 account

(4) Build BasicFlowRequest =
    { payload-fields ||
      AptosProofOfPermission { userAddr,
        pk_scheme=0, pubkey, sig_scheme=0,
        sig, fullMessage } }

(5) PKE-encrypt that BCS body to each
    worker's registered enc_key.

(6) HTTP POST /  hex-encoded ciphertext
    in parallel to ALL committee workers.
                                       (7) PKE-decrypt with worker's pke_dk
                                       (8) bcs::from_bytes::<RequestForDecryptionKey>
                                           → BasicFlowRequest
                                       (9) verify_basic:
                                           a. verifySig: fullMessage contains
                                              (or hex-contains) pretty(payload),
                                              and Ed25519 verify
                                           b. checkAuthKey: SHA3-256(pk||0x00) ==
                                              on-chain authentication_key for userAddr
                                              (a + RPC call)
                                           c. checkPermission: view-call
                                              {moduleAddr}::{moduleName}::{functionName}
                                              (userAddr, domain) → expects true
                                       (10) Look up cached share for (keypairId, epoch)
                                            → (scalar_le32, tibe_scheme)
                                       (11) eval_point := my position in cur_nodes + 1
                                       (12) Compute idk_share = scalar · hashToCurve(identity)
                                            in G2 (scheme 0) or G1 (scheme 1)
                                       (13) Encrypt response = pke_encrypt(
                                                ephemeralEncKey, BCS(idk_share))
                                       (14) HTTP 200 hex-encoded ciphertext

(15) For each response: PKE-decrypt
     with ephemeral decryptionKey;
     run share-verification pairing
     check against on-chain share_pks.

(16) When ≥ t valid shares collected,
     Lagrange-reconstruct full IDK
     and run t-IBE decrypt.
```

### 8.3 Decrypt — basic flow (Solana)

Steps 1-2 and 5-16 are identical. Steps 3-4 and 9 differ:

3'. User builds a Solana txn that calls a known program-id with instruction data containing `build_full_request_bytes(keypair_id, epoch, encKey, domain)` (`ace-anchor-kit/src/lib.rs:28-36`). They sign that txn but do NOT submit it to the chain. The ACL program is a no-op happy-path; the txn is structurally valid + recently-blockhash-bound but never lands.

4'. Build BasicFlowRequest with `SolanaProofOfPermission { inner_scheme, txn_bytes }`.

9'. `verify_solana`:
- Parses the Solana txn (legacy or versioned).
- Asserts exactly one instruction with `program_id == contract_id.program_id`.
- Asserts the instruction data carries `build_full_request_bytes(...)` matching the worker's reconstruction.
- Calls Solana `simulateTransaction` with `sigVerify=true, commitment=confirmed`. A success means the chain accepted the user's signature, the program ran without error, and the recent-blockhash is fresh.

The Solana ACL program is responsible for asserting access (e.g. that a payment Receipt PDA exists owned by the ACL program). The worker doesn't sandbox the program — it just trusts `simulateTransaction`.

### 8.4 Decrypt — custom flow (Aptos)

Steps 1-2 are identical. Step 3 differs: instead of an Ed25519 signature, the user supplies a `payload: Vec<u8>` that the contract's `check_acl(label, encPk, payload) -> bool` will verify. The `domain` field is renamed `label` to emphasize that it is the named binding key that `check_acl` looks up.

The CustomFlowRequest carries `CustomFlowProof::Aptos(payload)`. `verify_custom_aptos` view-calls `check_acl(label, encPk, payload)` on the chain via the worker's RPC.

A typical use: payload is a Groth16 ZK proof bound to `encPk` so a captured proof cannot be reused with a different ephemeral keypair.

### 8.5 Decrypt — custom flow (Solana)

Same shape but the proof is again a structurally-valid Solana txn that calls an `assert_custom_acl` instruction; the worker decodes `CustomFullRequestBytes` from the instruction data and matches all five fields (`keypair_id, epoch, enc_pk, label, payload`) against its reconstruction. Then `simulateTransaction`.

### 8.6 What if `< t` workers respond?

The SDK collects responses and short-circuits as soon as it has `t` valid shares. If, after all workers respond / time out, fewer than `t` valid shares were collected, the SDK returns an error. The client retries (typically with a fresh ephemeral keypair).

---

## 9. Error handling and abort codes

Every entry function uses Move's `assert!` with a numeric error code. The codes are module-local (defined as `const E_*: u64 = N;` at the top of each module). Auditors should treat any abort as a hard halt for that transaction; the protocol does not silently swallow errors.

Selected codes auditors will see most:
| Code | Meaning | Module |
|------|---------|--------|
| `E_INVALID_THRESHOLD` | `threshold` doesn't satisfy `2t > n, t ≥ 2, t ≤ n` | vss, dkg, network |
| `E_INVALID_DEALER` / `E_INVALID_RECIPIENT` | dealer / share holder not registered in `worker_config` | vss |
| `E_NOT_IN_PROGRESS` | Wrong state for this entry | vss, dkg, dkr, voting |
| `E_NOT_ENOUGH_ACKS` | `on_dealer_open` called with `< threshold` acks | vss |
| `E_TOO_EARLY_TO_OPEN` | `on_dealer_open` called within 10s of DC0 | vss |
| `E_INVALID_SCALED_ELEMENT_PROOF` | sigma-dlog-eq verification failed in resharing | vss |
| `E_INVALID_SHARE` | Publicly-revealed share fails Feldman verification on-chain | vss |
| `E_ONLT_DEALER_CAN_DO_THIS` | (sic) entry function called by non-dealer | vss |
| `E_EPOCH_CHANGE_ALREADY_IN_PROGRESS` | new_proposal during in-flight epoch change | network |
| `E_YOU_ALREADY_PROPOSED_IN_THIS_EPOCH` | Same proposer already has an open proposal | network |
| `E_ALREADY_VOTED` | Voter already cast a vote | voting |

A defense-in-depth note: the worker's HTTP layer maps verification failures to HTTP 403 (`worker-components/network-node/src/http_server.rs::handle_basic_flow / handle_custom_flow`); other internal errors map to 400 / 500. Auditors should verify that no path leaks a worker share via the error response body.

---

## 10. Timeouts (single source of truth)

| Constant | Value | Defined | Meaning |
|----------|-------|---------|---------|
| `vss::ACK_WINDOW_MICROS` | 10_000_000 (10s) | `vss.move:47` | Min time between DC0 and DC1 |
| `network::MIN_RESHARING_INTERVAL_SECS` | 30 | `network.move:17` | Lower bound on `epoch_duration_micros` |
| (TS SDK request timeout) | 30s default | `ts-sdk/src/_internal/common.ts` | Per-worker HTTP timeout in decryption flow |
| (Worker HTTP server) | unbounded per request | `network-node/src/http_server.rs` | Bounded only by the concurrency semaphore |

A future optional addition (currently absent): a maximum DKG / DKR session lifetime on-chain that lets `network::touch` give up on a stuck epoch change.
