# Shelby S3: Encrypted Upload With a Bearer Access Token

This example shows an Aptos **basic flow** for a Shelby S3-style app:

1. A file owner encrypts a file before uploading it to Shelby.
2. During upload, the owner also mints an access token by signing a file-scoped seed.
3. The token's derived Aptos address is registered on-chain in the file allowlist.
4. A stranger cannot decrypt the file.
5. Anyone holding the token private key can sign the ACE decryption request and decrypt.

The token is called "pre-signed" in the product sense: the owner can mint it immediately at upload time and privately share it later. Cryptographically, it is a bearer capability key, not a pre-signed transaction or URL.

The owner does not have to memorize a random token private key forever. The token key is derived from:

```text
sha256("shelby-s3/derived-token-key/v1" || owner_signature(seed_message))
```

where `seed_message` contains the owner address, file id, and a public token nonce. To recreate the same token, the owner signs the same seed again. The nonce can live in Shelby object metadata or the app database.

## Why Basic Flow Is Enough

The authorization predicate is:

> Is the requester's Aptos address the file owner or in this file's allowlist?

ACE basic flow already provides that requester address by verifying the decryption-request signature. If the reader signs with the token private key, the requester address is the token's derived Aptos address:

```move
public fun check_permission(user: address, file_id: vector<u8>): bool
```

No custom payload or ZK proof is needed because the contract only checks an address allowlist.

## Important Properties

- The token account does not need to exist on-chain or hold APT. It only signs ACE decryption requests.
- The token is transferable: anyone who has the private key can decrypt while its address remains allowlisted.
- Access is scoped by ACE domain. This example uses one token for one `file_id`.
- The owner can regenerate the token from their wallet signature plus the saved public nonce.
- Revocation is an on-chain allowlist update problem. This minimal demo includes `grant_access`; a production contract would also add `revoke_access`.
- Once a reader decrypts, they can copy the plaintext. ACE controls key release, not downstream file handling.

## Files

```text
examples/shelby-s3-aptos/
├── contract/
│   └── sources/shelby_s3.move
├── scripts/
│   ├── 1-setup.ts
│   ├── 2-deploy-contract.ts
│   ├── 3-upload-and-mint-token.ts
│   ├── 4-try-stranger.ts
│   ├── 5-decrypt-with-token.ts
│   └── common.ts
└── data/
```

## Run

From the repo root:

```bash
pnpm install
pnpm --filter shelby-s3-aptos 1-setup
pnpm --filter shelby-s3-aptos 2-deploy-contract
pnpm --filter shelby-s3-aptos 3-upload-and-mint-token
pnpm --filter shelby-s3-aptos 4-try-stranger
pnpm --filter shelby-s3-aptos 5-decrypt-with-token
```

Step 3 prints the private share token. In a real app, the owner would copy that token and send it privately to a reader. This demo saves it to `data/access-token.json` so step 5 can run automatically.

## What This Demonstrates

This is a useful basic-flow example because it is not just "add Bob to an allowlist." The owner can mint access at upload time before knowing the recipient's wallet address. The token address acts like a synthetic reader identity:

```text
owner signs seed -> derived token private key -> signs ACE request -> token address -> allowlist hit -> decrypt
```

That keeps the app flow close to familiar S3 pre-signed sharing while using ACE to enforce decryption access.
