# ACE

ACE is a protocol for access-controlling encrypted data with smart contracts.

> ⚠️ **Prototype**: ACE is currently a prototype and not yet ready for production use.

With ACE, dApps can support privacy scenarios like these—without any single party holding a decryption key:
- **Pay-to-decrypt**: Alice sells her album as encrypted files; Bob can only decrypt after paying.
- **Time-locked release**: A journalist encrypts a story that auto-releases on January 1, 2027. Until then, no one can decrypt it.
- **The general pattern**: Encrypt now; let a contract decide who can decrypt later.

This monorepo provides a TypeScript SDK, worker implementation, and examples for Aptos and Solana.

## How to Use

### Core Concepts

| Term | Description |
|------|-------------|
| **Committee** | A set of worker endpoints that collectively manage decryption keys |
| **ContractID** | Identifies the on-chain contract that manages decryption permission |
| **Domain** | Unique ID within the scope of the app of the object to encrypt |
| **FullDecryptionDomain** | Bundle of contractId + domain; signed to create proof |
| **ProofOfPermission** | Signed proof that a user has permission to decrypt |

### Quick Start: how to implement Pay-to-Decrypt

Let's implement the pay-to-decrypt scenario: Alice sells her album; Bob can only decrypt after paying.

**1. Deploy an Access Control Contract**

Deploy a contract that tracks who has paid for what albums. Workers will query this contract to check permission.

**Aptos:** Create a Move module with a `#[view]` function:

```move
module 0xcafe::album_store {
    use std::table::Table;

    struct PaymentRecords has key {
        // tracks: (buyer, album_id) -> has_paid
        records: Table<(address, vector<u8>), bool>,
    }

    public entry fun buy_album(buyer: &signer, album_id: vector<u8>) {
        // Process payment and record purchase
        // ...
    }

    #[view]
    public fun check_permission(user: address, album_id: vector<u8>): bool {
        // Return true if user has paid for this album
        // ...
    }
}
```

**Solana:** Create a hook program that checks for a payment receipt PDA:

```rust
declare_id!("AlbumStoreXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX");

pub fn check_access(ctx: Context<CheckAccess>, album_id: Vec<u8>) -> Result<()> {
    // Verify buyer's Receipt PDA exists for this album_id
    // Reverts if no receipt found (access denied), returns Ok(()) if paid
}
```

> **Note:** On Solana, the hook must be an Anchor program with exactly one instruction, since the contract identifier can only capture the program ID.

**2. Alice Encrypts Her Album**

Alice picks a committee of workers and encrypts her album.

> ⚠️ By picking a committee, Alice assumes the workers do not collude, and at least `t` of them will be available for decryption requests.

```typescript
import { ace } from "@aptos-labs/ace-sdk";

// Alice picks a decryption committee (e.g., 2-of-2 threshold)
// For testing, you can use the public test workers (see below)
const committee = new ace.Committee({
  workerEndpoints: ["https://worker1.example.com", "https://worker2.example.com"],
  threshold: 2,
});

// Fetch encryption key from the committee
const encryptionKey = await ace.EncryptionKey.fetch({ committee });

// Point to Alice's album store contract
// Aptos
const contractId = ace.ContractID.newAptos({
  chainId: 1,
  moduleAddr: "0xcafe",
  moduleName: "album_store",
  functionName: "check_permission",
});
// Solana
const contractId = ace.ContractID.newSolana({
  knownChainName: "mainnet-beta", // or "devnet", "localnet"
  programId: "AlbumStoreXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
});

// Encrypt the album with a unique album ID
const { fullDecryptionDomain, ciphertext } = ace.encrypt({
  encryptionKey: encryptionKey.unwrapOrThrow(),
  contractId,
  domain: new TextEncoder().encode("album-001"),
  plaintext: albumData,
}).unwrapOrThrow();

// Alice publishes fullDecryptionDomain + ciphertext (e.g., stores on Shelby)
```

**3. Bob Pays and Decrypts**

After Bob pays on-chain, he can request the decryption key.

```typescript
// Bob calls buy_album("album-001") on-chain first...

// Then Bob creates a proof of permission (chain-specific)
// Aptos: sign the decryption domain
const messageToSign = fullDecryptionDomain.toPrettyMessage();
const signOutput = await signMessage({ message: messageToSign, nonce: "" });
const proof = ace.ProofOfPermission.createAptos({
  userAddr: bob.accountAddress,
  publicKey: bob.publicKey,
  signature: signOutput.signature,
  fullMessage: signOutput.fullMessage,
});
// Solana: Bob signs a transaction calling the hook program
const proof = ace.ProofOfPermission.createSolana({
  txn: signedTransaction.serialize(),
});

// Fetch decryption key (workers query the contract to check permission)
// Note: committee must be obtained from the same source as encryptionKey
const decryptionKey = await ace.DecryptionKey.fetch({
  committee,
  contractId: fullDecryptionDomain.contractId,
  domain: fullDecryptionDomain.domain,
  proof,
});

// Bob decrypts the album
const albumData = ace.decrypt({
  decryptionKey: decryptionKey.unwrapOrThrow(),
  ciphertext,
}).unwrapOrThrow();
```

### Full Examples

| Example | Chain | Description |
|---------|-------|-------------|
| [Aptos Access Control](./examples/shelby-access-control-aptos) | Aptos | Allowlist-based encryption with Move contract |
| [Solana Access Control](./examples/shelby-access-control-solana) | Solana | Pay-to-download with Anchor programs |

### Public Test Workers

Two public test workers are available for development and testing:

| Worker | Endpoint |
|--------|----------|
| Worker 0 | `https://ace-worker-0-646682240579.europe-west1.run.app` |
| Worker 1 | `https://ace-worker-1-646682240579.europe-west1.run.app` |

```typescript
const committee = new ace.Committee({
  workerEndpoints: [
    "https://ace-worker-0-646682240579.europe-west1.run.app",
    "https://ace-worker-1-646682240579.europe-west1.run.app",
  ],
  threshold: 2,
});
```

> ⚠️ **Test only**: These workers are for development/testing purposes. For production, run your own workers (see below).

### Running Your Own Worker

To run your own decryption worker:

**1. Run fullnodes **

> ⚠️ This step is optional for testing. For production with high security requirement, each worker must run their own fullnodes — using shared or public RPC endpoints introduces a trust dependency; a malicious provider could return false permission results and steal the decryption key.

Workers query contracts to check decryption permissions. Run your own fullnodes:

- **Aptos:** See [Run a public fullnode](https://aptos.dev/network/nodes/full-node)
- **Solana:** See [Setup a Solana RPC node](https://docs.solanalabs.com/operations/setup-an-rpc-node)

**2. Generate a Worker Profile**

```bash
npm install -g @aptos-labs/ace-worker@latest
ace-worker new-worker-profile > worker-profile.txt
```

This outputs an IBE master secret key (`IBE_MSK`) and master public key (`IBE_MPK`) to `worker-profile.txt`. Keep `IBE_MSK` secret and never expose it on screen or in logs.

**3. Start the Worker**

```bash
# Pass env vars inline (IBE_MSK only goes to ace-worker, not exported to shell)
env $(grep -v '^#' worker-profile.txt | xargs) \
APTOS_MAINNET_API_ENDPOINT=https://my-aptos-fullnode:8080/v1 \
APTOS_MAINNET_API_KEY=your-api-key \
SOLANA_MAINNET_API_ENDPOINT=https://my-solana-rpc:8899 \
ace-worker run-worker --port 3000
```

## Project Structure

| Package | Description |
|---------|-------------|
| [`ts-sdk`](./ts-sdk) | TypeScript SDK for ACE operations |
| [`worker`](./worker) | ACE worker for key share management |
| [`examples/shelby-access-control-aptos`](./examples/shelby-access-control-aptos) | Aptos Move example |
| [`examples/shelby-access-control-solana`](./examples/shelby-access-control-solana) | Solana Anchor example |

## License

Apache 2.0
