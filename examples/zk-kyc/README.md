# ZK-KYC Example

A DeFi protocol encrypts a secret so that only KYC-verified users may decrypt it —
**without revealing their nationality**.  This example walks through the full flow as each
party would experience it, using Groth16 zero-knowledge proofs and the ACE custom-flow
decryption hook.

---

## The Parties

### KYC Provider
A regulated identity-verification service (Jumio, Persona, …).  They hold a Baby JubJub
signing key — in production this lives in an HSM.  Their job is to check a user's
identity documents and issue a **credential**: a signature over that user's jurisdiction
code.  They learn nothing about what the user does with the credential later.

### The App (DeFi Protocol)
A protocol that wants to gate some content — a compliance report, trading parameters,
gated yield, etc. — to KYC-verified users only.  They deploy a Groth16 verifier contract
on-chain and encrypt their secret under a KYC policy.  They learn nothing about which
users decrypt or when.

### The User
Someone who has passed KYC and holds a credential from the provider.  They want to
decrypt the app's secret.  To do so they generate a zero-knowledge proof locally — the
proof shows they hold a valid credential for a permitted jurisdiction, without revealing
which country.

### ACE Workers (infrastructure)
A threshold-decryption network that enforces the policy.  Before releasing a key share,
each worker simulates the app's `check_acl` view function on-chain.  No single worker can
decrypt alone; the user needs a threshold of workers to accept the proof.

---

## What is a jurisdiction code?

A jurisdiction code is a small integer identifying the jurisdiction where the user was
KYC-verified.  ZK circuits operate over finite-field arithmetic, so credentials are field
elements rather than strings.  This demo uses a simple mapping:

| Code | Status |
|------|--------|
| 0–3 | Blocked |
| 10, 20, … (any other value) | Permitted |

A production system would define its own blocklist and could use a standardised numbering
scheme such as [ISO 3166-1 numeric](https://en.wikipedia.org/wiki/ISO_3166-1_numeric).

The jurisdiction value is a **private** input to the ZK circuit — the on-chain verifier
and ACE workers learn only that it is not on the blocklist, nothing more.

---

## What the ZK Proof Guarantees

The Groth16 circuit proves three statements simultaneously:

| Statement | How it is enforced |
|---|---|
| I hold a credential signed by the registered KYC provider | EdDSA-Poseidon signature verification inside the circuit |
| My jurisdiction is **not** on the blocklist (codes 0–3) | Arithmetic constraint: `not_blocked === 1` |
| This proof is bound to my ACE decryption key `enc_pk` | The circuit packs `enc_pk[67]` into 3 BN254 Fr public inputs |

The third guarantee prevents replay: a proof generated for one decryption session cannot
be reused for a different one.

---

## Prerequisites

- **Node.js ≥ 18** and **pnpm**
- **Aptos CLI** — `cargo install aptos` or download from [aptos.dev](https://aptos.dev/tools/aptos-cli/)
- **circom 2.x** — `cargo install --git https://github.com/iden3/circom.git circom`

---

## Walkthrough

### Terminal 1 — Start the ACE network (infrastructure)

```bash
cd <repo-root>
pnpm install
cd scenarios
pnpm run-local-network-forever
```

Wait for the `ACE local network is READY` banner.  Keep this terminal open.

---

### Terminal 2 — Step 0: Compile the circuit (one time, done by nobody in particular)

```bash
cd examples/zk-kyc/circuit
./setup.sh
```

This runs the full Groth16 trusted setup locally:
1. Compiles `kyc.circom` → `kyc_js/kyc.wasm` (witness generator) + `kyc.r1cs`
2. Generates a Powers-of-Tau file (2^15 constraints, ~30 s)
3. Phase 2 → `kyc_final.zkey` (proving key, stays with the user)
4. Exports `vk.json` (verification key, published on-chain by the app)

> For production, substitute the local ptau with a public ceremony output such as
> the [Hermez ptau](https://github.com/iden3/snarkjs#7-prepare-phase-2).

Then install JS dependencies:

```bash
cd ..   # back to examples/zk-kyc
pnpm install
```

---

### Step 1 — KYC Provider: generate a signing keypair

> *The KYC provider is setting up their infrastructure.  They generate a Baby JubJub
> keypair whose public key will be embedded in the on-chain verifier, so that only
> credentials signed by this key are accepted.*

```bash
pnpm 1-provider-setup
```

Generates `data/provider-key.json` (private key + public key coordinates).  In
production this key lives in an HSM and the private key is never exported.

---

### Step 2 — App: deploy the on-chain verifier

> *The DeFi protocol deploys its KYC policy on-chain.  It locks in two things: the
> Groth16 verification key (which defines the circuit rules) and the KYC provider's
> public key (which determines whose credentials are accepted).  Neither can be changed
> after initialization.*

```bash
pnpm 2-deploy-contract
```

- Creates a fresh admin account and funds it via the localnet faucet.
- Deploys `kyc_verifier.move`, which contains the Groth16 pairing check and the
  `check_acl(label, enc_pk, payload)` hook that ACE workers call.
- Calls `initialize` with the verification key and the provider's public key.
- Writes `data/config.json` for use by the remaining scripts.

---

### Step 3 — KYC Provider: issue a credential to a user

> *A user has presented their identity documents.  The KYC provider verifies them,
> determines the user's jurisdiction, and issues a credential — a signature over that
> jurisdiction code.  The user stores this credential locally; it is never published.*

```bash
pnpm 3-issue-credential            # jurisdiction 10 (United States)
pnpm 3-issue-credential -- 20      # or jurisdiction 20 (European Union)
```

Computes `Poseidon(jurisdiction)` and signs the hash with the provider's Baby JubJub
private key.  Saves the signature to `data/credential.json`.

---

### Step 4 — App: encrypt a secret under the KYC policy

> *The protocol publishes some gated content.  It uses ACE to encrypt the plaintext so
> that only someone who can pass the `check_acl` check — i.e. only a KYC-verified user
> from a permitted jurisdiction — can obtain the decryption key.*

```bash
pnpm 4-encrypt
```

Encrypts a plaintext under the `kyc-demo` label using ACE custom flow.  Saves
`data/session.json` (ciphertext + ephemeral PKE keys for the decryption request).

Anyone can run this step — encryption is a public operation.

---

### Step 5 — User: prove compliance and decrypt

> *The user wants to read the gated content.  They have a credential from the provider
> but do not want to reveal their country.  They run the ZK prover locally: it produces
> a proof that they hold a valid credential for a permitted jurisdiction, without
> disclosing which one.  The proof is sent to ACE workers, who verify it on-chain and
> release their key shares.*

```bash
pnpm 5-decrypt
```

What happens under the hood:
1. Reads `data/credential.json` and `data/session.json`.
2. Calls `snarkjs.groth16.fullProve` with the circuit inputs — the ZK prover runs
   locally in Node.js and produces a Groth16 proof in ~2 seconds.
3. Encodes the proof as a 256-byte payload and calls `AptosCustomFlow.decrypt`.
4. Each ACE worker simulates `kyc_verifier::check_acl` on-chain (BN254 pairing check).
   If the proof is valid, the worker releases its key share.
5. Once a threshold of shares is collected, the threshold key is reconstructed and the
   ciphertext is decrypted.

Expected output:

```
=== Decryption successful! ===
Plaintext: "KYC-GATED SECRET: you have been verified!"
```

---

### Step 6 — What if a user is from a blocked jurisdiction? (optional)

> *A corrupt KYC provider issues a credential for a blocked jurisdiction (code 0).  Or a
> user tries to forge one.  Either way, the ZK prover itself refuses to produce a proof —
> the circuit's arithmetic constraints make it mathematically impossible.*

```bash
pnpm 6-try-sanctioned              # blocked jurisdiction code 0
pnpm 6-try-sanctioned -- 1         # blocked jurisdiction code 1
```

Expected output:

```
=== Proof generation FAILED as expected! ===

The circuit constraint "not_blocked === 1" is violated for Jurisdiction A.
The witness is inconsistent — no valid proof can be produced.
```

The blocklist check is baked into the circuit's arithmetic constraints — it is not a
check performed by any trusted party at proof time.  Even if the KYC provider issues a
credential for a blocked jurisdiction, the user cannot produce a valid proof.  The
constraint `not_blocked === 1` is as hard to bypass as breaking the underlying
elliptic-curve cryptography.

---

## Cryptographic Details

```
Private inputs (user only)       Public inputs (visible to on-chain verifier)
────────────────────────         ────────────────────────────────────────────
jurisdiction (u8)                pk_provider_ax, pk_provider_ay
sig_r8x, sig_r8y, sig_s          enc_pk_p0, enc_pk_p1, enc_pk_p2
enc_pk[67]
```

| Layer | Algorithm |
|---|---|
| ZK proof system | Groth16 over BN254 (bn128) |
| Signature scheme | EdDSA-Poseidon over Baby JubJub |
| Hash function (inside circuit) | Poseidon |
| On-chain verifier | `aptos_std::crypto_algebra` + `bn254_algebra` |
| Trusted setup | Local Powers-of-Tau + Phase 2 (demo only) |

---

## How This Extends to Production

| Demo | Production |
|---|---|
| Local Powers-of-Tau ceremony | Public ceremony (Hermez, Semaphore, …) |
| Private key in `data/provider-key.json` | HSM at a regulated KYC provider |
| Jurisdiction as a small integer | Richer credential (age, accreditation, …) |
| Localnet | Aptos mainnet/testnet |
| Fixed label `"kyc-demo"` | Per-protocol label registered with ACE |

---

## Project Structure

```
zk-kyc/
├── circuit/
│   ├── kyc.circom          ← the ZK circuit (Circom 2.x)
│   ├── package.json        ← circomlib + snarkjs for setup
│   └── setup.sh            ← one-command: circuit → proving key + vk.json
├── contract/
│   └── sources/
│       └── kyc_verifier.move  ← on-chain Groth16 verifier + check_acl hook
├── scripts/
│   ├── common.ts           ← shared helpers (byte encoding, packing)
│   ├── 1-provider-setup.ts ← generate KYC provider Baby JubJub keypair
│   ├── 2-deploy-contract.ts← deploy Move module + initialize with VK
│   ├── 3-issue-credential.ts← provider signs a jurisdiction code
│   ├── 4-encrypt.ts        ← encrypt a secret under the KYC policy
│   ├── 5-decrypt.ts        ← generate ZK proof + ACE decrypt
│   └── 6-try-sanctioned.ts ← watch proof generation fail for a blocked jurisdiction
└── data/                   ← generated files (gitignored)
```
