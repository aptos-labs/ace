// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

// Group algebra (BLS12-381 G1 and other curves)
export * as group from "./group";

// Shamir secret sharing
export * as vss from "./vss";

export * as pedersenPolynomialCommitment from "./pedersen-polynomial-commitment";

export * as sigmaDlogLinear from "./sigma-dlog-linear";

export * as dkg from "./dkg";

export * as dkr from "./dkr";

export * as network from "./network";

// Result type for error handling
export { Result } from "./result";

// Public Key Encryption
export * as pke from "./pke";

// Generic (scheme-tagged) signatures
export * as sig from "./sig";

// Disaster-recovery master-secret reconstruction (admin-side)
export * as adminRecovery from "./admin-recovery";

// Threshold IBE primitives (encrypt / extract / decrypt) — used by the ibe CLI + validation
export * as tibe from "./t-ibe";

// Streaming + seekable threshold IBE (chunk-in / chunk-out + random-access decrypt)
export * as tibeStream from "./t-ibe-stream";

// Shared types
export { AceDeployment, ContractID } from "./_internal/common";

// Registry of known ACE deployments (testnet, mainnet, …)
export { knownDeployments } from "./known-deployments";

// Aggregated discovery snapshot (decoder + human-readable projection) — used by the discovery service.
export { DiscoveryViewV0 } from "./_internal/discovery";
export type { DiscoveryReadableV0, SessionPks } from "./_internal/discovery";

// Threshold IBE (encrypt + basic/custom-flow decrypt) — per chain
export * as IBE_Aptos  from "./ibe-for-aptos";
export * as IBE_Solana from "./ibe-for-solana";

// Streaming + seekable threshold IBE (encryptStream + streaming/seekable decrypt) — per chain
export * as StreamIBE_Aptos  from "./ibe-for-aptos-stream";
export * as StreamIBE_Solana from "./ibe-for-solana-stream";

// Threshold VRF (derive deterministic bytes from owner + label)
export * as VRF_Aptos from "./vrf-for-aptos";
