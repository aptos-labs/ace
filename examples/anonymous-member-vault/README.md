# Anonymous Member Vault

This example demonstrates the ACE custom flow as **anonymous, app-defined authorization**.

An organization publishes encrypted member-only content. Users should be able to decrypt only if they are members, but the app must not reveal which member is decrypting. The basic flow can prove "this Aptos address has access"; this custom flow proves "the requester is some member" without disclosing an address or member identity.

## What It Proves

Each member has a private `member_secret`. The organization stores only a Merkle root of `Poseidon(member_secret)` commitments on-chain.

The local demo writes `data/group.json` as public metadata (`root` plus commitments) and `data/member-credential.json` as one member's private secret and Merkle path.

To decrypt, a user generates a Groth16 proof:

```text
I know member_secret such that:
  Poseidon(member_secret) is included in the current member Merkle root.
  This proof is bound to this ACE label.
  This proof is bound to this request's enc_pk.
```

The proof is sent as the custom-flow `payload`. ACE workers call:

```move
check_acl(label, enc_pk, payload): bool
```

The Move verifier returns `true` only if the proof matches the current root, the exact `label`, and the exact `enc_pk`.

## Why Custom Flow Matters Here

Basic flow requires an address-authenticated requester. That is useful for ordinary allowlists and payments, but it exposes which address is asking for a decryption share.

This example needs a different access predicate:

```text
The requester is a valid member, but do not reveal which member.
```

That predicate is not a wallet signature. It is an application-defined proof, so it belongs in custom flow.

## Payload Layout

`payload` is:

```text
Groth16 proof (256 bytes) || nullifier (32 bytes)
```

Public verifier inputs are:

```text
nullifier = Poseidon(member_secret, label_fr, enc_pk_p0, enc_pk_p1, enc_pk_p2)
root
label_fr
enc_pk_p0
enc_pk_p1
enc_pk_p2
```

`label_fr` is a demo-friendly packing of up to 30 label bytes plus a length byte. `enc_pk_p0/p1/p2` are the ACE request encryption key packed into three BN254 field elements, each carrying up to 30 bytes plus a length suffix.

The `enc_pk` binding prevents replaying a captured proof with a different response key. The `label` binding prevents reusing a proof for one encrypted document against another. The demo nullifier is request-bound because it includes `enc_pk`; a production app that needs one-claim-per-label semantics can add a separate stable nullifier output.

## Run It Locally

Start an ACE local network first:

```bash
cd ../../scenarios
pnpm run-local-network-forever
```

In another shell:

```bash
cd examples/anonymous-member-vault
pnpm install
pnpm 1-create-group
pnpm setup-circuit
pnpm 2-deploy-contract
pnpm 3-encrypt
pnpm 4-decrypt-as-member
pnpm 5-try-non-member
```

Expected successful decrypt output:

```text
=== Decryption successful ===
Plaintext: "MEMBER-ONLY SECRET: roadmap draft for anonymous members."
```

The final script shows a random non-member secret cannot generate a valid proof for the published member root.

## Production Notes

This example uses Groth16 because the repo already has an Aptos Move BN254 verifier path and it keeps the on-chain proof small. Custom flow itself does not require Groth16; any payload that `check_acl(label, enc_pk, payload)` can verify is valid.

For production, use a real ceremony or a trusted proving system setup, choose a larger tree, protect member credentials, and put governance around root rotation.
