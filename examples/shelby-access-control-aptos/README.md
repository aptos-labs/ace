# Aptos Access Control Example

This example demonstrates how a Shelby app may leverage ACE to implement access control on Aptos.

## Overview

The Shelby Access Control system allows content owners to:
- Encrypt data using ACE
- Register encrypted blobs on-chain with access policies
- Control access via allowlists, time locks, or pay-to-download
- Grant/revoke permissions dynamically

Consumers can decrypt content only after being granted permission by the content owner.

## Project Structure

```
shelby-access-control-aptos/
├── contract/                 # Move smart contract
│   ├── sources/
│   │   └── access_control.move
│   └── Move.toml
└── demo-cli-flow/           # TypeScript demo CLI
    ├── src/
    │   ├── test-localnet.ts  # Full e2e test on localnet
    │   ├── test-testnet.ts   # Full e2e test on testnet
    │   ├── policy.ts         # Access policy types (mirrors Move structs)
    │   └── utils.ts          # Helper functions
    └── package.json
```

## Quick Start

### Prerequisites

1. **Aptos CLI** - Install from [Aptos CLI docs](https://aptos.dev/tools/aptos-cli/install-cli/)
2. **Node.js** (v18+) and **pnpm**
3. **ACE Workers** - Local workers for localnet testing (testnet uses public workers)

### Run Against Localnet

This will deploy the contract to a local Aptos network and run the full e2e test.

#### Step 1: Start Aptos Localnet

In one terminal:

```bash
cd examples/shelby-access-control-aptos/demo-cli-flow
pnpm install
pnpm localnet
```

Wait for the localnet to start (you'll see "Setup is complete, you can now use the localnet!").

#### Step 2: Start ACE Workers

In two separate terminals, start the workers:

```bash
# Terminal 1 - Worker 0
cd worker
pnpm start:worker0

# Terminal 2 - Worker 1
cd worker
pnpm start:worker1
```

#### Step 3: Run the Test

In another terminal:

```bash
cd examples/shelby-access-control-aptos/demo-cli-flow
pnpm test:localnet
```

This will:
1. Deploy the Move contract to localnet
2. Initialize the contract
3. Create test accounts (Alice and Bob)
4. Alice encrypts data and registers a blob with an empty allowlist
5. Bob attempts to decrypt (fails - not in allowlist)
6. Alice updates the allowlist to include Bob
7. Bob decrypts successfully

### Custom Worker Configuration

If your workers are running on different ports:

```bash
WORKER_0=http://localhost:9000 WORKER_1=http://localhost:9001 pnpm test:localnet
```

### Run Against Testnet

This runs the e2e test against Aptos testnet using the already-deployed contract and public ACE workers.

```bash
cd examples/shelby-access-control-aptos/demo-cli-flow
pnpm test:testnet
```

The script will:
1. Generate test accounts (Alice and Bob)
2. **Pause and prompt you to fund the accounts** via the [Aptos testnet faucet](https://aptos.dev/en/network/faucet)
3. Continue with the e2e test flow (encrypt, register, grant access, decrypt)

This test uses public ACE workers by default. To use custom workers:

```bash
WORKER_0=https://my-worker-0.example.com WORKER_1=https://my-worker-1.example.com pnpm test:testnet
```

## How It Works

### The Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           ENCRYPTION FLOW (Alice)                           │
├─────────────────────────────────────────────────────────────────────────────┤
│  1. Fetch encryption key from worker committee                              │
│  2. Encrypt plaintext with:                                                 │
│     - Committee info (worker endpoints + threshold)                         │
│     - Contract ID (points to check_permission function)                     │
│     - Domain (unique blob identifier)                                       │
│  3. Register blob on-chain with access policy (e.g., empty allowlist)       │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           DECRYPTION FLOW (Bob)                             │
├─────────────────────────────────────────────────────────────────────────────┤
│  1. Create proof-of-permission (sign the decryption domain)                 │
│  2. Request decryption key from workers:                                    │
│     - ACE workers call check_permission(bob, domain) on-chain               │
│     - If returns true, ACE workers release their key shares                 │
│  3. Aggregate key shares into full decryption key                           │
│  4. Decrypt ciphertext                                                      │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 1. Content Owner (Alice) Flow

```typescript
// Step 1: Encrypt data with ACE
const { fullDecryptionDomain, ciphertext } = ACE.encrypt({
  encryptionKey,       // Encryption key from workers (includes threshold info)
  contractId,          // Points to check_permission function
  domain: blobName,    // Unique identifier for this blob
  plaintext: data,     // Data to encrypt
});

// Step 2: Register blob on-chain with access policy
const policy = AccessPolicy.newAllowlist([]);  // Empty = owner only
const reg = new RegistrationInfo(fileName, policy);
await runTxn(aptos, alice, `${CONTRACT}::access_control::register_blobs`, [regsToBytes([reg])]);

// Step 3 (later): Grant access to Bob by updating the allowlist
const newPolicy = AccessPolicy.newAllowlist([bob.accountAddress]);
await runTxn(aptos, alice, `${CONTRACT}::access_control::force_update_policy`, [fileName, newPolicy.toBytes()]);
```

### 2. Consumer (Bob) Flow

```typescript
// Step 1: Create proof of permission by signing the domain
const msgToSign = fullDecryptionDomain.toPrettyMessage();
const proofOfPermission = ACE.ProofOfPermission.createAptos({
  userAddr: bob.accountAddress,
  publicKey: bob.publicKey,
  signature: bob.sign(msgToSign),
  fullMessage: msgToSign,
});

// Step 2: Request decryption key from ACE workers
// ACE workers will call check_permission(bob, domain) on-chain to verify access
const decryptionKey = await ACE.DecryptionKey.fetch({
  committee,
  contractId,
  domain,
  proof: proofOfPermission,
});

// Step 3: Decrypt the content
const plaintext = ACE.decrypt({ decryptionKey, ciphertext });
```

## Move Contract

The `access_control.move` contract provides:

| Function | Description |
|----------|-------------|
| `initialize()` | Initialize the contract (admin only) |
| `register_blobs(regs)` | Register encrypted blobs with access policies |
| `force_update_policy(blob_name, policy)` | Update access policy for a blob (owner only) |
| `check_permission(user, domain)` | View function called by ACE workers to verify access |

### Access Policies

The contract supports three access control modes:

| Mode | Description |
|------|-------------|
| **Allowlist** | Only specified addresses can decrypt (owner always has access) |
| **TimeLock** | Anyone can decrypt after a specified timestamp |
| **PayToDownload** | Users must pay to gain decryption access |

### Full Blob Name Format

Blobs are identified by a full name combining owner address and file name:
```
@<owner_address_without_0x>/<file_name>
```

Example: `@00000000000000000000000000000000000000000000000000000000000000aa/star-wars.mov`
