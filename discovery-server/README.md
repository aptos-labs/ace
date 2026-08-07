# @aptos-labs/ace-discovery-server

A tiny HTTP service that lets ACE clients operate **without a node API key and
without a backend proxy**.

It reads the on-chain aggregate view `ace::network::discovery_view_v0_bcs()` once
(with the operator's node API key), caches it, and serves the raw snapshot to any
client. Clients using `@aptos-labs/ace-sdk` point their `AceDeployment.discoveryUrl`
at this service; the SDK then makes **zero fullnode calls** for enc/dec/VRF
operations (it still POSTs directly to worker nodes for shares, which needs no key).

Because the snapshot is identical for every client and constant within an epoch, the
service caches it for a short TTL and is trivially CDN-cacheable.

## Endpoints

All responses are `Cache-Control: no-store` and `Access-Control-Allow-Origin: *`.
Clients fetch fresh per operation; the upstream fullnode is shielded by this
server's own short-TTL cache, not by client-side caching.

- `GET /bcs` (and `GET /` for convenience) → the `0x`-prefixed BCS hex of
  `DiscoveryViewV0` as a plain-text body. **This is what the SDK consumes** — point
  `AceDeployment.discoveryUrl` at `<base>/bcs`. Pure pass-through, authoritative.
- `GET /json` → a human-readable JSON projection of the same snapshot (epoch,
  threshold, nodes with endpoints + enc keys, keypairs with master/base/share PKs;
  all crypto material hex-encoded). For eyeballing/debugging — decoded via the
  SDK's `DiscoveryViewV0` so it can't drift from what the SDK reads.
- `GET /healthz` → `ok`.

## Configuration (env)

| Var | Required | Default | Meaning |
| --- | --- | --- | --- |
| `ACE_DISCOVERY_CONTRACT_ADDR` | yes | — | ACE contract address |
| `ACE_DISCOVERY_FULLNODE` | yes | — | Aptos fullnode REST base URL (…/v1) |
| `ACE_DISCOVERY_API_KEY` | no | — | node API key; held server-side, never exposed |
| `ACE_DISCOVERY_PORT` | no | `8080` | listen port |
| `ACE_DISCOVERY_CACHE_TTL_MS` | no | `1500` | how long a snapshot is served before refresh |

## Run

```bash
pnpm --filter @aptos-labs/ace-discovery-server build
ACE_DISCOVERY_CONTRACT_ADDR=0x… ACE_DISCOVERY_FULLNODE=https://…/v1 ACE_DISCOVERY_API_KEY=… \
  pnpm --filter @aptos-labs/ace-discovery-server start
```

Or via Docker (build context is the repo root):

```bash
docker build -f discovery-server/Dockerfile -t ace-discovery .
docker run -p 8080:8080 \
  -e ACE_DISCOVERY_CONTRACT_ADDR=0x… -e ACE_DISCOVERY_FULLNODE=https://…/v1 \
  -e ACE_DISCOVERY_API_KEY=… ace-discovery
```

> Requires the contract to expose `network::discovery_view_v0_bcs()` (added
> alongside this service). Against an older deployment, `GET /bcs` and `/json` return 502.
