# ZK-KYC Example

A DeFi protocol encrypts a secret so that only age-verified users (18+) may decrypt it —
**without revealing their actual age**.  This example walks through the full flow as each
party would experience it, using Groth16 zero-knowledge proofs and the ACE custom-flow
decryption hook.

---

## The Parties

### KYC Provider
A regulated identity-verification service (Jumio, Persona, …).  They hold a Baby JubJub
signing key — in production this lives in an HSM.  Their job is to check a user's
identity documents and issue a **credential**: a signature over `Poseidon(user_secret, age)`,
where `user_secret` is a random value only the user knows.  This binds the credential to
that specific user — analogous to signing "this user's age is X" — without the provider
ever learning what the user does with the credential later.

### The App (DeFi Protocol)
A protocol that wants to gate some content — a compliance report, trading parameters,
gated yield, etc. — to verified adults only.  They deploy a Groth16 verifier contract
on-chain and encrypt their secret under an age policy.  They learn nothing about which
users decrypt or when.

### The User
Someone who has passed KYC and holds a credential from the provider.  They want to
decrypt the app's secret.  To do so they generate a zero-knowledge proof locally — the
proof shows they hold a valid credential attesting to age ≥ 18, without revealing
their exact age.

### ACE Workers (infrastructure)
A threshold-decryption network that enforces the policy.  Before releasing a key share,
each worker simulates the app's `check_acl` view function on-chain.  No single worker can
decrypt alone; the user needs a threshold of workers to accept the proof.

---

## What the ZK Proof Guarantees

The Groth16 circuit proves three statements simultaneously and produces one public output:

| | How it is enforced |
|---|---|
| I hold a credential signed by the registered KYC provider | EdDSA-Poseidon signature verification on `Poseidon(user_secret, age)` inside the circuit |
| My age is **18 or older** | Arithmetic constraint: `GreaterEqThan(8)` comparator |
| This proof is bound to my ACE decryption key `enc_pk` | `enc_pk_p0/p1/p2` are public inputs — Groth16 IC terms bind them to the proof |
| **Nullifier** output: `Poseidon(user_secret)` | Same user always yields the same nullifier; a real app records it on-chain to detect reuse |

Both `user_secret` and `age` are **private** inputs — the verifier learns only that the
age satisfies ≥ 18 and that the credential was issued to the holder of this secret.

> **Note — credential reuse (out of scope for this demo):** the nullifier is included in
> the proof and printed by script 5, but this demo does not record it on-chain.  A
> production app must store every nullifier after a successful decryption and reject any
> future request that presents a duplicate.  Without this check, the same credential can
> be used to decrypt an unlimited number of times.

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

> *The DeFi protocol deploys its age-verification policy on-chain.  It locks in two
> things: the Groth16 verification key (which defines the circuit rules, including the
> age ≥ 18 threshold) and the KYC provider's public key (which determines whose
> credentials are accepted).  Neither can be changed after initialization.*

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

> *A user has presented their identity documents.  The KYC provider verifies them and
> issues a credential.  First the user generates a random `user_secret` — a value only
> they will ever know.  The provider signs `Poseidon(user_secret, age)`, binding both
> the user's identity and their age into a single unforgeable credential.  The credential
> is stored locally by the user and never published.*

```bash
pnpm 3-issue-credential            # age 25 (default)
pnpm 3-issue-credential -- 30      # or a different eligible age
```

Generates a fresh `user_secret`, computes `Poseidon(user_secret, age)`, and signs the
hash with the provider's Baby JubJub private key.  Saves `user_secret`, `age`, and the
signature to `data/credential.json`.

---

### Step 4 — App: encrypt a secret under the age policy

> *The protocol publishes some gated content.  It uses ACE to encrypt the plaintext so
> that only someone who can pass the `check_acl` check — i.e. only a user with a valid
> age credential showing 18+ — can obtain the decryption key.*

```bash
pnpm 4-encrypt
```

Encrypts a plaintext under the `kyc-demo` label using ACE custom flow.  Saves
`data/session.json` (ciphertext and label only).

Anyone can run this step — encryption is a public operation.

---

### Step 5 — User: prove eligibility and decrypt

> *The user wants to read the gated content.  They have a credential from the provider
> but do not want to reveal their exact age.  They run the ZK prover locally: it produces
> a proof that they hold a valid credential attesting to age ≥ 18, without disclosing the
> actual value.  The proof is sent to ACE workers, who verify it on-chain and release
> their key shares.*

```bash
pnpm 5-decrypt
```

What happens under the hood:
1. Reads `data/credential.json` and `data/session.json`.
2. Generates an ephemeral PKE keypair for this decrypt request; the proof binds to its
   `enc_pk` so it cannot be replayed for another caller key.
3. Calls `snarkjs.groth16.fullProve` with the circuit inputs — the ZK prover runs
   locally in Node.js and produces a Groth16 proof in ~2 seconds.
4. Encodes the proof as a 256-byte payload and calls `AptosCustomFlow.decrypt`.
5. Each ACE worker simulates `kyc_verifier::check_acl` on-chain (BN254 pairing check).
   If the proof is valid, the worker releases its key share.
6. Once a threshold of shares is collected, the threshold key is reconstructed and the
   ciphertext is decrypted.

Expected output:

```
=== Decryption successful! ===
Plaintext: "KYC-GATED SECRET: you have been verified!"
```

---

### Step 6 — What if a user is underage? (optional)

> *A corrupt KYC provider issues a credential for age 16.  Or a user tries to forge one.
> Either way, the ZK prover itself refuses to produce a proof — the circuit's arithmetic
> constraints make it mathematically impossible.*

```bash
pnpm 6-try-underage              # age 16 (default)
pnpm 6-try-underage -- 17        # age 17
```

Expected output:

```
=== Proof generation FAILED as expected! ===

The circuit constraint "age >= 18" is violated for age 16.
The witness is inconsistent — no valid proof can be produced.
```

The age check is baked into the circuit's arithmetic constraints — it is not a check
performed by any trusted party at proof time.  Even if a corrupt KYC provider issues a
credential for an underage holder, the user cannot produce a valid proof.  The
`GreaterEqThan` constraint is as hard to bypass as breaking the underlying
elliptic-curve cryptography.

---

## Cryptographic Details

```
Private inputs (user only)       Public output      Public inputs (on-chain verifier)
────────────────────────         ─────────────────  ─────────────────────────────────
user_secret (Fr)                 nullifier (Fr)     pk_provider_ax, pk_provider_ay
age (u8)                                            enc_pk_p0, enc_pk_p1, enc_pk_p2
sig_r8x, sig_r8y, sig_s
```

`enc_pk_p0/p1/p2` are the raw `enc_pk` bytes packed into three BN254 Fr scalars.
The on-chain verifier computes them from the `enc_pk` in the decryption request;
the Groth16 pairing equation binds them to the proof without any circuit constraint.

| Layer | Algorithm |
|---|---|
| ZK proof system | Groth16 over BN254 (bn128) |
| Signature scheme | EdDSA-Poseidon over Baby JubJub |
| Hash function (inside circuit) | Poseidon |
| Age comparison | `GreaterEqThan(8)` from circomlib |
| On-chain verifier | `aptos_std::crypto_algebra` + `bn254_algebra` |
| Trusted setup | Local Powers-of-Tau + Phase 2 (demo only) |

---

## How This Extends to Production

| Demo | Production |
|---|---|
| Local Powers-of-Tau ceremony | Public ceremony (Hermez, Semaphore, …) |
| Private key in `data/provider-key.json` | HSM at a regulated KYC provider |
| Age threshold hardcoded at 18 | Configurable threshold per protocol |
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
│   ├── 3-issue-credential.ts← provider signs an age value
│   ├── 4-encrypt.ts        ← encrypt a secret under the age policy
│   ├── 5-decrypt.ts        ← generate ZK proof + ACE decrypt
│   └── 6-try-underage.ts   ← watch proof generation fail for age < 18
└── data/                   ← generated files (gitignored)
```
