# ACE v6 bootstrap from the initial committee multisig

Create the native multisig M0 with the initial service nodes as owners and the
secret-sharing threshold as its required signature count. Register each node's
PKE key before starting the epoch. The Python SDK exposes unsigned
`governance.creation_transaction_payload(...)` for creating M0 and unsigned
proposal, approval, and execution builders for its transactions.

Prepare a JSON input such as:

```json
{
  "initial_multisig": "0x...",
  "seed_hex": "0xace0",
  "nodes": ["0x...", "0x...", "0x..."],
  "threshold": 2,
  "resharing_interval_secs": 3600,
  "initial_secret_requests": [{ "expected_usage": 2, "note": "BF-IBE" }],
  "initial_features": []
}
```

Run `ace v6-bootstrap-plan input.json --out bootstrap-plan.json` from the
v6 checkout. The command derives the stable `@ace` resource account from M0
and the seed, patches the Move named addresses in a temporary copy, compiles
all packages, and writes 16 ordered unsigned native multisig payloads. It
does not submit transactions or read private keys. The optional `ace_address`
input is checked against the derived address, and `version` can stamp a chosen
`X.Y.Z` into every package manifest.

For each step, M0 creates, approves, and executes the listed payload before
moving to the next. Step 1 creates `@ace` and publishes `Publisher`; the
intermediate steps publish its dependencies through the one-shot M0 bootstrap
capability. The `Network` package is published last and takes that capability
in `init_module`. The final step starts E0 `INIT` with the initial committee.
Its workers then run the epoch protocol until E0 enters `SERVING`.

For later epoch changes, create an unsigned payload with
`ace governance payload epoch-config config.json --ace 0x...`. The JSON fields
are `nodes`, `threshold`, `epoch_duration_micros`, `secrets_to_retain`,
`new_secrets` (objects with `expected_usage` and `note`), `description`,
`target_epoch`, `next_admin_multisig`, and `features_to_activate`. The current
epoch's native multisig approves and executes it. Compatible package upgrades
use `ace governance payload publish-upgrade package.json --ace 0x...` where
`package.json` contains `metadata_hex` and `modules_hex`.
