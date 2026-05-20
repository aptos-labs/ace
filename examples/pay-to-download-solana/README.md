# Pay-to-Download (Solana)

This example shows how to gate ACE-encrypted content behind a Solana payment: users pay on-chain, then prove the payment to ACE workers via a signed Solana transaction to obtain the decryption key.

## Overview

This demo shows how to:
- Use ACE for decryption key management
- Use a Solana program to track payments
- Prove payment to ACE workers via a signed Solana transaction

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              TWO PROGRAMS                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────┐     ┌─────────────────────────────────────┐    │
│  │   access_control        │     │   ace_hook                          │    │
│  │   (Main Program)        │     │   (Access Control Hook)             │    │
│  ├─────────────────────────┤     ├─────────────────────────────────────┤    │
│  │ • register_blob()       │     │ • assert_access()                   │    │
│  │ • purchase()            │◄────│   - Verifies blob_metadata PDA      │    │
│  │                         │     │   - Verifies receipt PDA            │    │
│  │ Stores:                 │     │   - Checks seqnum match             │    │
│  │ • BlobMetadata (PDA)    │     │                                     │    │
│  │ • Receipt (PDA)         │     │ Workers call this to verify access  │    │
│  └─────────────────────────┘     └─────────────────────────────────────┘    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Why Two Programs?

With a single program containing multiple entry functions, there's no reliable way for decryption committee members to confirm that a proof-of-permission transaction actually calls the access verification function.

The pattern is:
1. **Main Program** (`access_control`) - Normal Anchor app with business logic
2. **Hook Program** (`ace_hook`) - Single `assert_access` instruction that ACE workers can verify

ACE workers verify that a signed transaction calls `ace_hook::assert_access` before releasing decryption key shares.

## Project Structure

```
pay-to-download-solana/
├── programs/
│   ├── access_control/           # Main program (business logic)
│   │   └── src/
│   │       ├── lib.rs             # Program entry points
│   │       ├── instructions/      # Instruction handlers
│   │       │   ├── register_blob.rs
│   │       │   └── purchase.rs
│   │       └── utils.rs           # Solana→Aptos address derivation
│   └── ace_hook/                  # Hook program (access verification)
│       └── src/
│           └── lib.rs             # assert_access instruction
├── tests/
│   └── e2e.ts                     # End-to-end test
├── Anchor.toml                    # Anchor configuration
└── package.json
```

## Quick Start

### Prerequisites

1. **Solana CLI** - Install from [Solana docs](https://docs.solana.com/cli/install-solana-cli-tools)
2. **Anchor CLI** - Install from [Anchor docs](https://www.anchor-lang.com/docs/installation)
3. **Node.js 18 or 20** (LTS) and **pnpm** — tests use the standard Anchor `ts-mocha` setup; Node 22+ can trigger ESM errors in the test runner.

### Step 1: Start the ACE Local Network

From the repo root:

```bash
cd scenarios
pnpm run-local-network-forever
```

Wait for the `ACE local network is READY` banner. This deploys the ACE contract to Aptos localnet,
runs DKG, and starts the workers — writing `aceContract` and `keypairId` to
`/tmp/ace-localnet-config.json`.

> **Note:** This does **not** start a Solana validator. The Solana validator is started automatically
> by `anchor test` in Step 2.

### Step 2: Run the Test

```bash
cd examples/pay-to-download-solana
pnpm install
pnpm test:localnet
```

This will:
1. Start a local Solana validator
2. Build and deploy both Anchor programs
3. Run the e2e test with automatic airdrop funding

### Run e2e against testnet

If the programs are already deployed on testnet, run the same e2e test against testnet (no local validator, no deploy):

```bash
cd examples/pay-to-download-solana
solana config set --url https://api.testnet.solana.com
pnpm test:testnet
```

Prerequisites: programs deployed at the IDs in `Anchor.toml` under `[programs.testnet]`, and ACE workers running (see Step 1). The test will print two addresses (Alice and Bob) to fund on testnet and wait until they have enough SOL, or you can airdrop: `solana airdrop 2 <ADDRESS>`.

## How It Works

### The Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      UPLOAD FLOW (Alice - Content Owner)                    │
├─────────────────────────────────────────────────────────────────────────────┤
│  1. Encrypt the content payload directly with ACE → ciphertext              │
│     - Uses keypairId, aceContract, contractId, and fullBlobName             │
│  2. Register the ciphertext on-chain via access_control::register_blob      │
│     - Creates BlobMetadata PDA with price                                   │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                      DOWNLOAD FLOW (Bob - Consumer)                         │
├─────────────────────────────────────────────────────────────────────────────┤
│  1. Purchase access via access_control::purchase                            │
│     - Transfers SOL from Bob to Alice                                       │
│     - Creates Receipt PDA (proves payment)                                  │
│  2. Create proof-of-permission:                                             │
│     - Build transaction calling ace_hook::assert_access                     │
│     - Sign the transaction (proves Bob controls the account)                │
│  3. Request decryption key from ACE workers with the signed transaction     │
│     - ACE workers simulate the transaction to verify access                 │
│     - If assert_access passes, ACE workers release key shares               │
│  4. Aggregate key shares → decryption key                                   │
│  5. ACE-decrypt the ciphertext → original content                           │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Encryption Model

ACE encrypts the content **directly** — the bytes stored on-chain in
`BlobMetadata.ciphertext` *are* the protected payload. There is no
intermediate symmetric-key wrapping layer.

With ACE's current default t-IBE scheme, direct encryption of
reasonably-sized payloads is the recommended pattern. Earlier designs
sometimes used a two-layer model (symmetric key encrypts the file,
ACE encrypts the symmetric key, file ciphertext lives off-chain); that
pattern is no longer recommended for new applications.

### Solana → Aptos Address Derivation

Solana addresses are converted to Aptos Derivable Abstracted Account (DAA) addresses for cross-chain compatibility:

```
Solana PublicKey  →  Hash(auth_function + domain)  →  Aptos Address
```

This allows the same logical identity to be used across both chains.

## Program Details

### access_control (Main Program)

| Instruction | Description |
|-------------|-------------|
| `register_blob` | Register a new encrypted blob with metadata and price |
| `purchase` | Pay for access and create a receipt |

**Accounts:**
- `BlobMetadata` (PDA): Stores owner, ACE ciphertext, price, sequence number
- `Receipt` (PDA): Proves a user has purchased access

### ace_hook (Hook Program)

| Instruction | Description |
|-------------|-------------|
| `assert_access` | Verify a user has access to a blob (called by ACE workers) |

**Verification steps:**
1. Verify `blob_metadata` is owned by `access_control`
2. Verify `receipt` is owned by `access_control`
3. Parse full blob name and derive expected PDAs
4. Check that receipt's seqnum matches blob_metadata's seqnum

## Code Examples

### Content Owner: Encrypt and Register

```typescript
// Encrypt the content payload directly with ACE
const ciphertext = (await ACE.SolanaBasicFlow.encrypt({
  aceDeployment,
  keypairId,
  knownChainName,
  programId: aceHookProgram.programId.toBase58(),
  domain: fullBlobNameBytes,
  plaintext: secretContent,
})).unwrapOrThrow();

// Register on-chain
await program.methods
  .registerBlob(ownerAptosAddr, fileName, ciphertextScheme, Buffer.from(ciphertext), price)
  .accounts({ owner: alice.publicKey })
  .signers([alice])
  .rpc();
```

### Consumer: Purchase and Decrypt

```typescript
// Purchase access
await program.methods
  .purchase(ownerAptosAddr, fileName)
  .accounts({ buyer: bob.publicKey, owner: alice.publicKey })
  .signers([bob])
  .rpc();

// Build proof-of-permission transaction (calls ace_hook::assert_access)
const session = await ACE.SolanaBasicFlow.DecryptionSession.create({
  aceDeployment, keypairId, knownChainName,
  programId: aceHookProgram.programId.toBase58(),
  domain: fullBlobNameBytes, ciphertext,
});
const fullRequestBytes = await session.getRequestToSign();
const txn = await aceHookProgram.methods
  .assertAccess(Buffer.from(fullRequestBytes))
  .accounts({
    blobMetadata: deriveBlobMetadataPda(...),
    receipt: deriveAccessReceiptPda(...),
    user: bob.publicKey,
  })
  .transaction();
txn.feePayer = bob.publicKey;
txn.recentBlockhash = (await connection.getLatestBlockhash()).blockhash;
txn.sign(bob);

// Request decryption from ACE workers; on success returns the original content.
const content = (await session.decryptWithProof({ txn: txn.serialize() })).unwrapOrThrow();
```
