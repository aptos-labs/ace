# Derive per-app, per-account, per-label values with Aptos approval

## TLDR

ACE VRF lets your app derive the same 32 bytes again later for the same app contract, Aptos account, and label, but only when the app contract approves the derivation request. Apps can map those bytes into per-object signing keys, deterministic grants, app-scoped randomness, private nonces, or other app-specific material.

Use this guide when the app needs a value that is stable for a specific `(contract, account, label)` tuple, but should not be derivable unless your Aptos policy says yes.

To use it, you will:

- In your Move module, expose `on_ace_vrf_request(...)` as the source of truth for derivation decisions.
- Choose a stable derivation label, such as `access-key:v1:<blob_id>` or another app-specific label.
- In your client, derive bytes with `ACE.VRF_Aptos` and map them into whatever your app needs.

## Example: per-blob access keys

In this example, we show one concrete use of ACE VRF: creating per-blob access keypairs. The high-level idea is to let an owner recreate the same private key for a blob, register the matching public key on-chain, and use the private key as grant material in a later off-chain identity access flow.

For each encrypted blob, we define a canonical `blob_id`, then derive 32 bytes from this tuple:

```text
(contractId, ownerAddress, accessKeyLabel)
where accessKeyLabel = "access-key:v1:" || blob_id
```

Conceptually, `derive(contractId, ownerAddress, accessKeyLabel)` produces deterministic private bytes scoped to that app contract, owner, and label. In this example, we map those bytes into an access private key, compute the matching public key, register that public key on-chain for the encrypted object, and later give the private key or a grant containing it to the reader. The off-chain identity access hook then verifies reader proofs against the registered public key.

### Contract changes

In this example, the Move module is named `vrf_access`. After you publish it, the SDK's `moduleAddr` is the publisher address and `moduleName` is `"vrf_access"`.

The Move contract does not need to store who can derive each access key. The owner account is already part of the VRF input: deriving with `(contractId, ownerAddress, accessKeyLabel)` gives different bytes from deriving with `(contractId, anotherAddress, accessKeyLabel)`. In this example, the contract only checks that the wallet signature was made for your deployed app origin.

To work with ACE VRF, the module exposes `on_ace_vrf_request` so ACE can ask the contract before deriving.

ACE calls the contract through a view function with this fixed name and signature:

```move
public fun on_ace_vrf_request(
    label: vector<u8>,
    account: address,
    origin: String,
): bool
```

First, we store the expected client origin in app-level config:

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

Then the hook checks that the wallet-signed origin matches your deployed client. It does not need to inspect `label` or `account` for this example; ACE already includes them in the derivation input.

```move
#[view]
public fun on_ace_vrf_request(
    label: vector<u8>,
    account: address,
    origin: String,
): bool acquires AppConfig {
    if (!exists<AppConfig>(@admin)) return false;
    let config = borrow_global<AppConfig>(@admin);
    origin.bytes() == &config.client_origin
}
```

Putting those pieces together, the full module looks like this:

```move
module admin::vrf_access {
    use std::error;
    use std::signer;
    use std::string::String;

    const E_NOT_ADMIN: u64 = 1;
    const E_NOT_INITIALIZED: u64 = 2;

    struct AppConfig has key {
        client_origin: vector<u8>,
    }

    public entry fun init(admin: &signer) {
        assert!(signer::address_of(admin) == @admin, error::permission_denied(E_NOT_ADMIN));
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

    #[view]
    public fun on_ace_vrf_request(
        label: vector<u8>,
        account: address,
        origin: String,
    ): bool acquires AppConfig {
        if (!exists<AppConfig>(@admin)) return false;
        let config = borrow_global<AppConfig>(@admin);
        origin.bytes() == &config.client_origin
    }
}
```

If the hook returns `true`, the SDK returns 32 bytes. In this example, we turn those bytes into access key material.

Deploy the Move package and run `init`. After deploying the client, call `set_client_origin` once with the client's stable origin. Record:

- `chainId`, `moduleAddr`, and `moduleName`.
- `aceDeployment` and `keypairId` from the ACE deployment you target, such as a preview value provided by the ACE team or a localnet/example config.
- The object ID used by your follow-on access hook, and the derivation label built from it, for example `access-key:v1:<blob_id>`.

### Client changes

Before the SDK calls, fill in the ACE deployment values and the app module identity:

```typescript
import * as ACE from "@aptos-labs/ace-sdk";
import { AccountAddress } from "@aptos-labs/ts-sdk";

const aceDeployment = new ACE.AceDeployment({
  apiEndpoint: "https://api.testnet.aptoslabs.com/v1",
  contractAddr: AccountAddress.fromString("0x<ace-contract-address>"),
});
const keypairId = AccountAddress.fromString("0x<ace-keypair-id>");
const chainId = 2; // Aptos testnet

const moduleAddr = AccountAddress.fromString("0x<app-module-address>");
const moduleName = "vrf_access"; // matches module <publisher>::vrf_access
```

In the client, we construct the same derivation label, ask the owner wallet to sign the derivation request, derive bytes, map them into key material, and register the public half on-chain. For a wallet or web app, prefer the session API:

```typescript
const blobId = `@${ownerAddress.toStringLong().slice(2)}/song-1.mp3`;
const objectId = new TextEncoder().encode(blobId);
const accessKeyLabel = new TextEncoder().encode(`access-key:v1:${blobId}`);

const contractId = ACE.ContractID.newAptos({
  chainId,
  moduleAddr,
  moduleName,
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
// presigned_access::register(objectId, accessPublicKey)
```

`vrfOutputToAccessKeypair` is your app's documented mapping from 32 derived bytes into the target key type. In the pre-signed-access example, we reduce the bytes into a BLS12-381 scalar for `accessPrivateKey` and compute the matching G1 public key. The public key is stored on-chain under the encrypted object's ID for later off-chain identity checks; the private key becomes the bearer capability that can sign reader grants.

For CLIs or server-side jobs that sign directly with an Aptos account, build the same wallet-style `fullMessage` before signing:

```typescript
const vrfBytes = await ACE.VRF_Aptos.derive({
  aceDeployment,
  keypairId,
  chainId,
  moduleAddr,
  moduleName,
  label: accessKeyLabel,
  accountAddress: ownerAddress,
  sign: async (message) => {
    const fullMessage = ACE.VRF_Aptos.buildAptosWalletFullMessage({
      accountAddress: ownerAddress,
      application: "https://<your-deployed-app-origin>",
      chainId,
      message,
      nonce: crypto.randomUUID(),
    });
    return {
      pubKey: ownerAccount.publicKey,
      signature: ownerAccount.sign(fullMessage),
      fullMessage,
    };
  },
});
```

The remaining order is the same: we map `vrfBytes` into the access keypair, register the public key on-chain for `objectId`, and put the private key only in the grant or controlled client that is supposed to use it.

As with Aptos account access, deploy the client first, learn the stable origin, then update the app config resource once to accept only that origin.

## Remarks

If you map the derived bytes into a private key, that private key is a bearer capability. Anyone who obtains it can sign whatever reader proof your follow-on access flow accepts, so do not log it, publish it on-chain, or put it in a client that should not be able to grant access.

Derivation is reproducible only for the exact ACE deployment key identifier, contract id, account, and label. Use a canonical, app-specific label such as `access-key:v1:<blob_id>`. Re-running the same tuple gives the same bytes; rotating the result requires changing the derivation inputs, not deriving the same tuple again.

## Ready-To-Run Examples

- [`examples/presigned-access-aptos`](../../../examples/presigned-access-aptos): derives per-blob access keys, then uses off-chain identity access for readers.
- [`scenarios/test-threshold-vrf-derive-flow.ts`](../../../scenarios/test-threshold-vrf-derive-flow.ts): end-to-end localnet VRF derivation scenario.
- [`scenarios/threshold-vrf-origin`](../../../scenarios/threshold-vrf-origin): minimal origin-check Move hook.
