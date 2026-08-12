# ACE Python SDK

Python SDK for ACE (Aptos Confidential Extension). This package mirrors the
core crypto and wire-format surface of `@aptos-labs/ace-sdk` for Python
callers.

The SDK currently includes:

- BCS helpers for the wire formats ACE uses.
- Scheme-tagged BLS12-381 G1/G2 group wrappers.
- Feldman/Shamir VSS helpers.
- Pedersen polynomial commitments, DKG and DKR state decoders.
- Public-key encryption schemes used by ACE.
- Scheme-tagged Ed25519 signing helpers for reconstructor/admin flows.
- Threshold IBE primitives.
- Known deployment metadata and network state view decoders.
- Discovery snapshot decoding for the keyless discovery service.
- Aptos IBE encryption helpers.
- Worker decryption request helpers for basic and custom flows.
- Disaster-recovery master-secret reconstruction helpers.
- Aptos threshold-VRF request, share verification, and output reconstruction helpers.

## Install for local development

```bash
python -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
```

## Quick check

```python
from ace_sdk import pke

encryption_key, decryption_key = pke.keygen()
ciphertext = pke.encrypt(encryption_key, b"hello ace")
plaintext = pke.decrypt(decryption_key, ciphertext).unwrap_or_throw("decrypt failed")
assert plaintext == b"hello ace"
```

The API follows Python naming conventions (`from_bytes`, `to_hex`,
`derive_encryption_key`) while preserving ACE's byte-level compatibility with
the TypeScript SDK.

## Admin IBE validation

The reconstructed master secret printed by the ACE disaster-recovery flow is a
32-byte little-endian Fr scalar. Use it to extract a full identity decryption
key and validate a ciphertext:

```python
from ace_sdk import t_ibe

idk = t_ibe.extract(msk_scalar=msk_scalar, identity=label).unwrap_or_throw("extract")
plaintext = t_ibe.decrypt([idk], ciphertext).unwrap_or_throw("decrypt")
```

For Aptos app encryption, `ibe_aptos.encrypt` builds the same full decryption
domain as the TypeScript SDK before t-IBE encryption.

## Benchmarks

The BLS12-381 pairing implementation is pure Python and intentionally kept out
of the default test suite. Run its opt-in benchmark with:

```bash
python benchmarks/bench_pairing.py --iterations 5
```

## Aptos custom flow

For custom access-control flows, callers provide the application proof payload
and the PKE keypair that workers should use to encrypt returned IDK shares:

```python
from ace_sdk import ibe_aptos, pke

enc_pk, enc_sk = pke.keygen()
plaintext = ibe_aptos.decrypt_custom_flow(
    ace_deployment=deployment,
    keypair_id=keypair_id,
    chain_id=chain_id,
    module_addr=module_addr,
    module_name="example",
    label=b"object-id",
    enc_pk=enc_pk,
    enc_sk=enc_sk,
    payload=custom_proof_payload,
    ciphertext=ciphertext_bytes,
).unwrap_or_throw("custom decrypt")
```
