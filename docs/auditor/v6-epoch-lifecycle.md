# ACE v6 epoch lifecycle

This document records the v6 protocol requirements used to implement the on-chain epoch state machine and the worker CLI. An epoch is a protocol instance, not only a number in `network::State`.

## Epoch instances and overlap

Each epoch has four phases: `INIT`, `SERVING`, `HANDOFF`, and `GRACE`.

```text
E5: INIT -> SERVING -> HANDOFF --------> GRACE -> retired
E6:                    INIT -----------> SERVING -> HANDOFF -> GRACE
                       one E5-to-E6 transition
```

`E5.HANDOFF` and `E6.INIT` are two roles in the **same** transition session. The old committee contributes to DKR while the new committee receives reshared secrets and participates in DKG for new secrets. When that transition completes, E6 starts serving and E5 enters grace at the same boundary. E5 remains available during grace for **all** of its secrets, including any omitted from E6. Grace defaults to 60 seconds. E5 is retired only after grace expires.

An operator in both committees runs two epoch CLI instances concurrently in the same worker process, keyed by distinct epoch/session IDs. The E5 instance proceeds through handoff and grace while the E6 instance proceeds through init and serving. Both instances refer to the same transition session for handoff/init. The upper epoch CLI runs the lower epoch-change, DKR, DKG, and VSS clients. The worker keeps one PKE-owning HTTP endpoint and chooses epoch-specific service logic after decrypting and parsing a request; authorization still verifies that the request proof binds its epoch.

The network supervisor may initiate a new transition only after the previous grace epoch has retired. This bounds concurrent epoch runtimes at two, even if the configured epoch duration is shorter than the 60-second grace. `discovery_view_v1_bcs` returns both serving and live grace epoch descriptors, including their node endpoints, secret session references, ready-node bitmaps, feature sets, and grace deadline. A worker restart during grace reconstructs the old epoch's shares from those references. The worker filters requests by the on-chain grace deadline even if a local share cache has not yet been evicted.

## Governance and activation

The admin committee of each epoch is exactly its serving-node committee. Its native multisig owners are those node addresses, and its approval quorum equals the epoch's secret-sharing threshold.

The initial committee creates M0 and uses it to authorize publication under a stable `@ace` resource account. ACE holds `@ace`'s signer capability privately. Each epoch points to the native multisig controlled by its serving nodes; an unchanged committee may carry the same multisig into the next epoch. The current committee approves a transition configuration containing the next committee, threshold, retained and new secrets, and features to activate. The transition protocol then runs to completion without a special final multisig approval. At the serving/grace boundary, the on-chain protocol changes the authorized multisig when necessary together with the active epoch and feature set. The `@ace` capability remains with ACE.

As in v5, expiration of the configured epoch duration may start a same-committee resharing automatically. It carries the existing committee, admin multisig, secret set, and feature set forward. A new automatic transition waits until the previous epoch's grace has ended.

When a current committee cannot complete handoff, its epoch remains the serving epoch. v5 has no epoch-transition timeout, cancel, or restart policy; v6 does not add one as part of the baseline lifecycle.

## Software rollout and feature scope

Operators first deploy binaries that understand both the old and new behavior. Compatible Move code is published with new behavior dormant. The transition configuration selects the features that become active for the next epoch at its serving boundary. The prepublished code must retain old behavior while those features are off.

Features that affect the handoff/init transcript are frozen in the shared transition session before it starts. Serving features are frozen in each epoch instance. During E5 grace, E5 requests continue to use E5 features; E6 requests use E6 features. The old and new CLI roles in a transition read the same transition feature snapshot.

`epoch_change::completed` proves on-chain DKR/DKG completion. Each E6 node reconstructs and verifies its shares, installs the complete batch in the maintainer's share store, then signs `epoch::acknowledge_ready`. Once the threshold of E6 nodes has acknowledged, `network::touch` changes E6 to `SERVING` and E5 to `GRACE` in one transaction. The ready-node bitmap records this acknowledgement; it is not a live health signal. Until E6 is serving, its preloaded shares stay hidden from the public handler. A split handler refreshes its 1-second share snapshot cache on a missing `(keypair, epoch)` lookup, rate-limited to once per 100 ms. The old epoch's session references and grace deadline remain on chain so a restarted node can restore grace service.

The `epoch-worker` CLI follows one epoch session and invokes the relevant lower protocol CLIs. `network-node` runs the instances for adjacent epochs concurrently and owns the in-process share sink and HTTP service. A standalone `epoch-worker` can drive the transition roles, but it does not claim readiness for an epoch with secrets unless a share sink confirms installation. The V5 maintainer path remains available when the contract exposes only the V0 state view.

`ace v6-bootstrap-plan` prepares the ordered unsigned M0 publication and E0 initialization payloads; `cli/V6_BOOTSTRAP.md` describes the inputs and execution sequence. No contract or worker is deployed by generating the plan.
