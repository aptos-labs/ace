# Aptos VRF: Move-Gated Derivation

## TLDR

Use ACE VRF when an Aptos contract should decide whether a user may derive deterministic secret bytes for `(keypairId, contract, account, label)`. A VRF, or verifiable random function, is like a keyed hash: the same input always gives the same output, but nobody can predict the output without the secret key. In ACE, that secret key is split across workers, so no single worker can derive the output alone.

The most common app pattern is per-object access keys. For example, a data owner can derive `VRF(blob_id, owner, ...)`, map the 32-byte output into an access keypair, register the public key on-chain, and use the private key to create pre-signed access grants. The owner can re-derive the same private key later without storing it.

You need to:

- Write a Move module with `on_ace_vrf_request(label, account, origin): bool`.
- Store whatever policy decides who may derive the access key for a blob.
- Use `ACE.VRF_Aptos.DerivationSession` for wallet-driven clients, or `ACE.VRF_Aptos.derive` for one-shot scripts.
- Use a stable, domain-separated derivation label such as `access-key:v1:<blob_id>`.
- Map the returned bytes into your app's key material and register the public half where later access checks can find it.

## Example walkthrough: Per-blob access keys

This example app derives per-blob access keypairs. Each encrypted blob has a canonical `blob_id`, and the owner derives an access keypair from the ACE VRF tuple:

```text
(keypairId, contractId, ownerAddress, accessKeyLabel)
where accessKeyLabel = "access-key:v1:" || blob_id
```

The 32-byte VRF output is not sent to the reader directly. The owner maps it into an access private key, computes the matching public key, registers that public key on-chain, and later gives the private key or a grant containing it to the reader. The custom IBE hook then verifies reader proofs against the registered public key.

### 1. Write the Move Contract

The contract below gates who may derive each access-key label. `account` is the Aptos account that signed the derivation request, and `origin` pins the request to your deployed client.

The hook name and signature are fixed:

```move
public fun on_ace_vrf_request(
    label: vector<u8>,
    account: address,
    origin: String,
): bool
```

First, store the owner allowed to derive each access-key label. This is the derivation policy: only that owner account can ask ACE workers to produce VRF shares for that label.

```move
struct AccessKeyPolicy has key {
    owners: Table<vector<u8>, address>,
}

public entry fun allow_deriver(
    admin: &signer,
    access_key_label: vector<u8>,
    owner: address,
) acquires AccessKeyPolicy {
    assert!(signer::address_of(admin) == @admin, error::permission_denied(E_NOT_ADMIN));
    let policy = borrow_global_mut<AccessKeyPolicy>(@admin);
    policy.owners.upsert(access_key_label, owner);
}
```

Next, store the expected client origin in app-level config, separate from the per-label derivation policy:

```move
struct AppConfig has key {
    client_origin: vector<u8>,
}

public entry fun set_client_origin(
    admin: &signer,
    origin: vector<u8>,
) acquires AppConfig {
    assert!(signer::address_of(admin) == @admin, error::permission_denied(E_NOT_ADMIN));
    assert!(exists<AppConfig>(@admin), error::not_found(E_NOT_INITIALIZED));
    let config = borrow_global_mut<AppConfig>(@admin);
    config.client_origin = origin;
}
```

Then the hook checks both facts: the wallet-signed origin matches your deployed client, and the account that signed the derivation request is the owner recorded for that access-key label.

```move
#[view]
public fun on_ace_vrf_request(
    label: vector<u8>,
    account: address,
    origin: String,
): bool acquires AccessKeyPolicy, AppConfig {
    if (!exists<AccessKeyPolicy>(@admin)) return false;
    if (!exists<AppConfig>(@admin)) return false;
    let policy = borrow_global<AccessKeyPolicy>(@admin);
    let config = borrow_global<AppConfig>(@admin);
    if (origin.bytes() != &config.client_origin) return false;
    if (!policy.owners.contains(label)) return false;
    *policy.owners.borrow(label) == account
}
```

Putting those pieces together, the full module looks like this:

```move
module admin::vrf_access {
    use aptos_std::table;
    use aptos_std::table::Table;
    use std::error;
    use std::signer;
    use std::string::String;

    const E_NOT_ADMIN: u64 = 1;
    const E_NOT_INITIALIZED: u64 = 2;

    struct AccessKeyPolicy has key {
        owners: Table<vector<u8>, address>,
    }

    struct AppConfig has key {
        client_origin: vector<u8>,
    }

    public entry fun init(admin: &signer) {
        assert!(signer::address_of(admin) == @admin, error::permission_denied(E_NOT_ADMIN));
        if (!exists<AccessKeyPolicy>(@admin)) {
            move_to(admin, AccessKeyPolicy {
                owners: table::new(),
            });
        };
        if (!exists<AppConfig>(@admin)) {
            move_to(admin, AppConfig {
                client_origin: vector::empty(),
            });
        };
    }

    public entry fun set_client_origin(
        admin: &signer,
        origin: vector<u8>,
    ) acquires AppConfig {
        assert!(signer::address_of(admin) == @admin, error::permission_denied(E_NOT_ADMIN));
        assert!(exists<AppConfig>(@admin), error::not_found(E_NOT_INITIALIZED));
        let config = borrow_global_mut<AppConfig>(@admin);
        config.client_origin = origin;
    }

    public entry fun allow_deriver(
        admin: &signer,
        access_key_label: vector<u8>,
        owner: address,
    ) acquires AccessKeyPolicy {
        assert!(signer::address_of(admin) == @admin, error::permission_denied(E_NOT_ADMIN));
        let policy = borrow_global_mut<AccessKeyPolicy>(@admin);
        policy.owners.upsert(access_key_label, owner);
    }

    #[view]
    public fun on_ace_vrf_request(
        label: vector<u8>,
        account: address,
        origin: String,
    ): bool acquires AccessKeyPolicy, AppConfig {
        if (!exists<AccessKeyPolicy>(@admin)) return false;
        if (!exists<AppConfig>(@admin)) return false;
        let policy = borrow_global<AccessKeyPolicy>(@admin);
        let config = borrow_global<AppConfig>(@admin);
        if (origin.bytes() != &config.client_origin) return false;
        if (!policy.owners.contains(label)) return false;
        *policy.owners.borrow(label) == account
    }
}
```

If the hook returns `true`, workers return threshold VRF shares. The SDK verifies the shares, reconstructs the VRF output, and returns 32 bytes. Your app then turns those bytes into the access key material it needs.

Deploy the Move package, initialize policy, and configure which owner accounts may derive each access-key label. After deploying the client, call `set_client_origin` once with the client's stable origin. The origin is app-level configuration, separate from per-label derivation policy. Record:

- `chainId`, `moduleAddr`, and `moduleName`.
- `aceDeployment` and `keypairId`.
- The label construction for each derivation, for example `access-key:v1:<blob_id>`.

### 2. Call the TypeScript SDK

For a wallet or web app, prefer the session API:

```typescript
import * as ACE from "@aptos-labs/ace-sdk";

const blobId = `@${ownerAddress.toStringLong().slice(2)}/song-1.mp3`;
const accessKeyLabel = new TextEncoder().encode(`access-key:v1:${blobId}`);

const contractId = ACE.ContractID.newAptos({
  chainId,
  moduleAddr,
  moduleName: "vrf_access",
});

const session = await ACE.VRF_Aptos.DerivationSession.create({
  aceDeployment,
  keypairId,
  contractId,
  label: accessKeyLabel,
  accountAddress: ownerAddress,
});

const message = await session.getRequestToSign();
const signed = await wallet.signMessage({
  message,
  nonce: crypto.randomUUID(),
  application: true,
  chainId,
  address: ownerAddress,
});

const vrfBytes = await session.deriveWithSignature({
  pubKey: signed.publicKey,
  signature: signed.signature,
  fullMessage: signed.fullMessage,
});

const { accessPrivateKey, accessPublicKey } = vrfOutputToAccessKeypair(vrfBytes);

// Then submit your app's registration transaction, for example:
// presigned_access::register(blob_id_suffix, accessPublicKey)
```

`vrfOutputToAccessKeypair` is your app's documented mapping from 32 VRF bytes into the target key type. In the pre-signed-access example, it reduces the bytes into a BLS12-381 scalar for `accessPrivateKey` and computes the matching G1 public key. The public key is stored on-chain for later custom IBE checks; the private key becomes the bearer capability that can sign reader grants.

For CLIs or server-side jobs that already know how to sign, use the one-shot helper instead of the session API:

```typescript
const vrfBytes = await ACE.VRF_Aptos.derive({
  aceDeployment,
  keypairId,
  chainId,
  moduleAddr,
  moduleName: "vrf_access",
  label: accessKeyLabel,
  accountAddress: ownerAddress,
  sign: async (message) => {
    const signed = await signAptosMessage(message);
    return {
      pubKey: signed.publicKey,
      signature: signed.signature,
      fullMessage: signed.fullMessage,
    };
  },
});
```

The remaining order is the same: map `vrfBytes` into the access keypair, register the public key on-chain, and put the private key only in the grant or controlled client that is supposed to use it.

As with Aptos basic IBE, deploy the client first, learn the stable origin, then update the app config resource once to accept only that origin.

## Remarks

The derived access private key is a bearer capability. Anyone who obtains it can sign whatever reader proof your follow-on access flow accepts, so do not log it, publish it on-chain, or put it in a client that should not be able to grant access.

Derivation is reproducible only for the exact ACE keypair, contract id, owner account, and label. Use a canonical, domain-separated label such as `access-key:v1:<blob_id>`. Re-running the same tuple gives the same private key; rotating access requires changing the derivation inputs or registering a different public key, not re-deriving the same tuple.

## Ready-To-Run Examples

- [`examples/presigned-access-aptos`](../../../examples/presigned-access-aptos): derives per-blob access keys with ACE VRF, then uses custom IBE for readers.
- [`scenarios/test-threshold-vrf-derive-flow.ts`](../../../scenarios/test-threshold-vrf-derive-flow.ts): end-to-end localnet VRF derivation scenario.
- [`scenarios/threshold-vrf-origin`](../../../scenarios/threshold-vrf-origin): minimal origin-check Move hook.
