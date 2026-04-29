# ZK-KYC Example

A real-world ZK proof integration with ACE custom flow.

A DeFi protocol encrypts a secret (e.g. a compliance report, gated content, or trading
parameters) so that only users who can prove KYC compliance may decrypt it — **without
revealing their nationality**.

---

## What is Being Proved?

The prover holds a KYC credential: a **jurisdiction code** signed by a trusted KYC
provider using EdDSA over Baby JubJub.

**What is a jurisdiction code?**  It is a small integer that identifies the
country/jurisdiction where the user passed KYC.  ZK circuits operate over finite-field
arithmetic, so credentials are represented as field elements rather than strings.  This
demo uses a simple numbering: 0 = DPRK, 1 = Iran, 2 = Cuba, 3 = Syria (sanctioned), and
any other value (e.g. 10 for United States, 20 for EU) for permitted jurisdictions.  A
production system would use a standardised scheme such as [ISO 3166-1 numeric](https://en.wikipedia.org/wiki/ISO_3166-1_numeric).

The KYC provider attests to a user's jurisdiction by computing `Poseidon(jurisdiction)`
and signing the hash with their Baby JubJub private key.  The signed credential is handed
to the user.  The user then uses it as a **private** witness in the ZK proof — the
jurisdiction value itself is never revealed on-chain.

The Groth16 circuit simultaneously proves three things:

| Statement | How it is enforced |
|---|---|
| I hold a credential signed by the registered KYC provider | EdDSA-Poseidon signature verification inside the circuit |
| My jurisdiction is **not** sanctioned (DPRK/Iran/Cuba/Syria) | Arithmetic constraint: `not_sanctioned === 1` |
| This proof is bound to my ACE decryption key `enc_pk` | The circuit packs `enc_pk[67]` into 3 BN254 Fr public inputs |

The jurisdiction itself is a **private** input — the verifier learns nothing about which
country the prover comes from, only that it is not on the sanctions list.

### The circuit in one picture

```
Private (secret)               Public (visible to verifier)
─────────────────              ──────────────────────────────────────
jurisdiction (u8)   ─┐         pk_provider_ax, pk_provider_ay  (Baby JubJub pubkey)
sig_r8x, sig_r8y    │ circuit  enc_pk_p0, enc_pk_p1, enc_pk_p2 (enc_pk packed into
sig_s (EdDSA sig)   ─┘    →    three BN254 Fr scalars)
enc_pk[67]         ─┘
```

The on-chain `check_acl` function receives `enc_pk` directly from the ACE worker and
independently computes the same `p0/p1/p2` packing — ensuring the proof cannot be
replayed against a different key.

### Cryptographic stack

| Layer | Algorithm |
|---|---|
| ZK proof system | Groth16 over BN254 (bn128) |
| Signature scheme | EdDSA-Poseidon over Baby JubJub |
| Hash function (inside circuit) | Poseidon |
| On-chain verifier | `aptos_std::crypto_algebra` + `bn254_algebra` |
| Trusted setup | Local Powers-of-Tau + Phase 2 (demo only; production would use a public ceremony) |

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
│   └── 6-try-sanctioned.ts ← watch proof generation fail for a sanctioned code
└── data/                   ← generated files (gitignored)
```

---

## Prerequisites

- **Node.js ≥ 18** and **pnpm**
- **Aptos CLI** — `cargo install aptos` or download from [aptos.dev](https://aptos.dev/tools/aptos-cli/)
- **circom 2.x** — `cargo install --git https://github.com/iden3/circom.git circom`

---

## Walkthrough

### Terminal 1 — Start the ACE local network

```bash
cd <repo-root>
pnpm install
cd scenarios
pnpm run-local-network-forever
```

Wait until you see the `ACE local network is READY` banner.  Keep this terminal open.

---

### Terminal 2 — Run the example

#### Step 0 — Compile circuit and run trusted setup (one time)

```bash
cd examples/zk-kyc/circuit
./setup.sh
```

This runs the full Groth16 ceremony locally:
1. Compiles `kyc.circom` → `kyc_js/kyc.wasm` (witness generator) + `kyc.r1cs`
2. Generates a fresh Powers-of-Tau file (2^15 constraints, ~30 s)
3. Runs Groth16 Phase 2 → `kyc_final.zkey` (proving key)
4. Exports `vk.json` (verification key, uploaded to the chain in step 2)

> For production you would substitute the local ptau with a public ceremony output
> such as the [Hermez ptau](https://github.com/iden3/snarkjs#7-prepare-phase-2).

---

Install the JS dependencies (back in `examples/zk-kyc`):

```bash
cd ..   # back to examples/zk-kyc
pnpm install
```

---

#### Step 1 — KYC provider setup

```bash
pnpm 1-provider-setup
```

Generates a Baby JubJub private key for the KYC provider and saves it to
`data/provider-key.json`.  In a real system this key lives in a HSM at the provider.

---

#### Step 2 — Deploy the on-chain verifier

```bash
pnpm 2-deploy-contract
```

- Funds a fresh Aptos account on localnet.
- Deploys `kyc_verifier.move`, which contains the Groth16 pairing check.
- Calls `initialize` with the VK (from `circuit/vk.json`) and the provider's
  public key.  The VK is now locked on-chain.
- Writes `data/config.json`.

---

#### Step 3 — Issue a KYC credential

```bash
pnpm 3-issue-credential            # defaults to jurisdiction 10 (United States)
pnpm 3-issue-credential -- 20      # or try jurisdiction 20 (European Union)
```

The KYC provider signs `Poseidon(jurisdiction)` with their Baby JubJub private key.
The resulting signature is saved to `data/credential.json`.

---

#### Step 4 — Encrypt a secret

```bash
pnpm 4-encrypt
```

Encrypts a plaintext under the `kyc-demo` label using ACE custom flow.
Saves `data/session.json` (ciphertext + ephemeral PKE keys).

Anyone can run this step — encryption is public.

---

#### Step 5 — Generate ZK proof and decrypt

```bash
pnpm 5-decrypt
```

1. Reads the credential and the enc_pk.
2. Calls `snarkjs.groth16.fullProve` with the circuit inputs — this is the ZK prover
   running locally in Node.js.  It produces a Groth16 proof in ~2 seconds.
3. Encodes the proof as a 256-byte payload and calls `AptosCustomFlow.decrypt`.
4. ACE workers receive the request, simulate `kyc_verifier::check_acl` on-chain,
   and verify the proof using BN254 pairings.  If it passes, they release their key
   shares.
5. The threshold key is reconstructed and the ciphertext is decrypted.

You should see:

```
=== Decryption successful! ===
Plaintext: "KYC-GATED SECRET: you have been verified!"
```

---

#### Step 6 — Try a sanctioned jurisdiction (optional but educational)

```bash
pnpm 6-try-sanctioned              # tries DPRK (code 0)
pnpm 6-try-sanctioned -- 1         # tries Iran (code 1)
```

Even with a valid EdDSA signature from the provider, the Groth16 prover fails:

```
=== Proof generation FAILED as expected! ===

The circuit constraint "not_sanctioned === 1" is violated for DPRK (North Korea).
The witness is inconsistent — no valid proof can be produced.
```

The sanctions check is enforced by the arithmetic constraints inside the circuit —
not by any party at proof time.  There is no way to produce a valid proof for a
sanctioned jurisdiction, regardless of what the KYC provider signs.

---

## How This Extends to Production

| Demo | Production |
|---|---|
| Local Powers-of-Tau ceremony | Public ceremony (Hermez, Semaphore, …) |
| Private key in `data/provider-key.json` | HSM at a regulated KYC provider |
| Jurisdiction as a small integer | Richer credential (age, accreditation, …) |
| Localnet | Aptos mainnet/testnet |
| Fixed label `"kyc-demo"` | Per-protocol label registered with ACE |
