# Solana Access Control Example

This example demonstrates how a Shelby app may use ACE and a Solana contract to implement access control.

## Overview

This demo dApp shows how to:
- Use ACE for decryption key management
- Use Solana contracts to track access permissions (e.g., payments)
- Prove access permission to ACE workers via signed Solana transactions

**Note:** Currently, only pay-to-download mode is implemented.

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
shelby-access-control-solana/
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
cd examples/shelby-access-control-solana
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
cd examples/shelby-access-control-solana
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
│  1. Generate a symmetric encryption key (RedKey)                            │
│  2. Encrypt RedKey with ACE → GreenBox (encrypted key)                      │
│     - Uses keypairId, aceContract, contractId, and fullBlobName             │
│  3. Register GreenBox on-chain via access_control::register_blob           │
│     - Creates BlobMetadata PDA with price                                   │
│  4. Encrypt file content with RedKey → RedBox (encrypted file)              │
│  5. Upload RedBox to Shelby storage (off-chain)                             │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                      DOWNLOAD FLOW (Bob - Consumer)                         │
├─────────────────────────────────────────────────────────────────────────────┤
│  1. Purchase access via access_control::purchase                           │
│     - Transfers SOL from Bob to Alice                                       │
│     - Creates Receipt PDA (proves payment)                                  │
│  2. Create proof-of-permission:                                             │
│     - Build transaction calling ace_hook::assert_access                     │
│     - Sign the transaction (proves Bob controls the account)                │
│  3. Request decryption key from ACE workers with the signed transaction     │
│     - ACE workers simulate the transaction to verify access                 │
│     - If assert_access passes, ACE workers release key shares               │
│  4. Aggregate key shares → decryption key                                   │
│  5. Decrypt GreenBox → RedKey                                               │
│  6. Download RedBox from Shelby, decrypt with RedKey → original file        │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Key Concepts

#### RedKey & GreenBox Pattern

```
┌──────────────────┐         ACE         ┌──────────────────┐
│     RedKey       │ ─────────────────►  │    GreenBox      │
│  (32-byte key)   │     Encrypt         │ (encrypted key)  │
└──────────────────┘                     └──────────────────┘
        │
        │ Symmetric
        │ Encrypt
        ▼
┌──────────────────┐
│     RedBox       │  ← Stored in Shelby (off-chain)
│ (encrypted file) │
└──────────────────┘
```

- **RedKey**: Random symmetric key for file encryption
- **GreenBox**: RedKey encrypted with ACE (stored on-chain in BlobMetadata)
- **RedBox**: File content encrypted with RedKey (stored off-chain in Shelby)

#### Solana → Aptos Address Derivation

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
- `BlobMetadata` (PDA): Stores owner, encrypted key (GreenBox), price, sequence number
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
// Generate encryption key (RedKey)
const redKey = crypto.getRandomValues(new Uint8Array(32));

// Encrypt RedKey → GreenBox
const { ciphertext: greenBox } = (await ace_ex.encrypt({
  keypairId,
  contractId,
  domain: fullBlobNameBytes,
  plaintext: redKey,
  aceContract,
})).unwrapOrThrow();

// Register on-chain
await program.methods
  .registerBlob(ownerAptosAddr, fileName, greenBoxScheme, Buffer.from(greenBox), price)
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

// Build proof-of-permission transaction
const txn = await accessControlProgram.methods
  .assertAccess(fullBlobNameBytes)
  .accounts({
    blobMetadata: deriveBlobMetadataPda(...),
    receipt: deriveAccessReceiptPda(...),
    user: bob.publicKey,
  })
  .transaction();
txn.feePayer = bob.publicKey;
txn.recentBlockhash = (await connection.getLatestBlockhash()).blockhash;
txn.sign(bob);

// Request decryption key and decrypt GreenBox → RedKey
const pop = ace_ex.ProofOfPermission.createSolana({ txn: txn.serialize() });
const redKey = (await ace_ex.decrypt({
  keypairId, contractId, domain: fullBlobNameBytes, proof: pop, ciphertext: greenBox, aceContract,
})).unwrapOrThrow();
```
