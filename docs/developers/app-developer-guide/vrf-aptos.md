# Derive Per-App, Per-Label Values With Aptos Approval

ACE threshold VRF lets an app derive the same 32 bytes again later for the same ACE keypair, app contract, and label, but only when the app contract approves the derivation request.

Use this guide when the app needs a deterministic value that is stable for a specific `(keypair, contract, label)` tuple and should not be derivable unless your Aptos policy says yes. The request carries an Aptos account for authorization, but that account is not part of the VRF input; include the account bytes in `label` if the output must be per-account.

## Contract Hook

The worker calls a view function with this fixed name and signature:

```move
#[view]
public fun on_ace_vrf_request(
    label: vector<u8>,
    account: address,
    origin: String,
): bool
```

`label` is the SDK request label, `account` is the Aptos account the user proves control of, and `origin` is extracted from the wallet/WebAuthn signed message. Return `true` only for requests your app wants ACE workers to serve.

A minimal origin-gated hook looks like this:

```move
module admin::vrf_access {
    use std::error;
    use std::string::String;

    const E_NOT_ADMIN: u64 = 1;
    const E_NOT_INITIALIZED: u64 = 2;

    struct AppConfig has key {
        client_origin: vector<u8>,
    }

    public entry fun init(admin: &signer) {
        assert!(admin.address_of() == @admin, error::permission_denied(E_NOT_ADMIN));
        if (!exists<AppConfig>(@admin)) {
            move_to(admin, AppConfig { client_origin: vector[] });
        };
    }

    public entry fun set_client_origin(admin: &signer, origin: vector<u8>) {
        assert!(admin.address_of() == @admin, error::permission_denied(E_NOT_ADMIN));
        assert!(exists<AppConfig>(@admin), error::not_found(E_NOT_INITIALIZED));
        let config = &mut AppConfig[@admin];
        config.client_origin = origin;
    }

    #[view]
    public fun on_ace_vrf_request(_label: vector<u8>, _account: address, origin: String): bool {
        if (!exists<AppConfig>(@admin)) return false;
        let config = &AppConfig[@admin];
        origin.bytes() == &config.client_origin
    }
}
```

Real apps usually also check the label and account against their policy state. The account gates authorization; it does not by itself change the derived bytes.

The cryptographic VRF input used by both the TypeScript SDK and the Rust worker is exactly:

```text
("ace.threshold-vrf.input.v1", keypairId, contractId, label)
```

`accountAddress`, `epoch`, and the response encryption key are still signed and sent to workers, but they are request authorization / freshness / transport fields, not VRF output inputs.

## Client Flow

Fill in the ACE deployment values and your app module identity:

```typescript
import * as ACE from "@aptos-labs/ace-sdk";
import { AccountAddress } from "@aptos-labs/ts-sdk";

const aceDeployment = new ACE.AceDeployment({
  apiEndpoint: "https://api.testnet.aptoslabs.com/v1",
  contractAddr: AccountAddress.fromString("0x<ace-contract-address>"),
});

const keypairId = AccountAddress.fromString("0x<ace-keypair-id>");
const chainId = 2;
const moduleAddr = AccountAddress.fromString("0x<app-module-address>");
const moduleName = "vrf_access";
```

For a wallet or web app, prefer the session API:

```typescript
const label = new TextEncoder().encode("access-key:v1:blob-123");
const ownerAddress = AccountAddress.fromString("0x<owner>");

const contractId = ACE.ContractID.newAptos({
  chainId,
  moduleAddr,
  moduleName,
});

const session = await ACE.VRF_Aptos.DerivationSession.create({
  aceDeployment,
  keypairId,
  contractId,
  label,
  accountAddress: ownerAddress,
});

const message = await session.getRequestToSign();
// AIP-62 signMessage does not return the account public key. Obtain and
// normalize it from the wallet's connected account as an Aptos `PublicKey`.
const connectedAccountPublicKey = getConnectedAccountPublicKey();
const signed = await wallet.signMessage({
  message,
  nonce: crypto.randomUUID(),
  address: true,
  application: true,
  chainId: true,
});

// This assumes the adapter returns an Aptos SDK `Signature` object. If it
// returns serialized bytes or hex instead, normalize it at the adapter boundary.

const vrfBytes = (await session.deriveWithSignature({
  pubKey: connectedAccountPublicKey,
  signature: signed.signature,
  fullMessage: signed.fullMessage,
})).unwrapOrThrow("ACE VRF derive failed");
```

For CLIs or server-side jobs that sign directly with an Aptos account, build the same wallet-style `fullMessage` before signing:

```typescript
const vrfBytes = (await ACE.VRF_Aptos.derive({
  aceDeployment,
  keypairId,
  chainId,
  moduleAddr,
  moduleName,
  label,
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
})).unwrapOrThrow("ACE VRF derive failed");
```

The `address`, `application`, and `chainId` AIP-62 inputs are boolean inclusion flags. ACE requires `fullMessage` to contain the exact SDK-generated hexadecimal BCS request, verifies the signature and account key, and passes the signed `application` value to `on_ace_vrf_request` as `origin`.

For a passkey account, request the WebAuthn challenge and submit the browser assertion through the dedicated API:

```typescript
const challenge = await session.getRequestToSignForWebAuthn();
const credential = await navigator.credentials.get({
  publicKey: {
    challenge,
    rpId: window.location.hostname,
    allowCredentials,
    userVerification: "required",
  },
}) as PublicKeyCredential;
const response = credential.response as AuthenticatorAssertionResponse;

const vrfBytes = (await session.deriveWithWebAuthnAssertion({
  pubKey: connectedPasskeyPublicKey,
  authenticatorData: new Uint8Array(response.authenticatorData),
  clientDataJSON: new Uint8Array(response.clientDataJSON),
  signature: new Uint8Array(response.signature),
})).unwrapOrThrow("ACE passkey VRF derive failed");
```

The SDK encrypts each worker request to that worker's registered PKE key, decrypts the encrypted VRF shares returned by workers, verifies the share proofs, combines at least threshold many valid shares, and returns 32 bytes.

## Output Handling

Use a canonical, app-specific label such as `access-key:v1:<blob_id>` or `randomness:v1:<round_id>`. Re-running the same `keypairId`, contract id, and label gives the same bytes. If distinct accounts need distinct bytes, encode the account into the label. Rotating output requires changing one of the VRF inputs.

If you map the derived bytes into private key material or bearer capability bytes, treat the result as secret. Do not log it, publish it on-chain, or expose it to clients that should not be able to exercise that capability.

## Scenario

The maintained end-to-end localnet coverage is [`scenarios/test-threshold-vrf-derive-flow.ts`](../../../scenarios/test-threshold-vrf-derive-flow.ts).
