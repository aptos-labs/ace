// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import * as path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const REPO_ROOT = path.resolve(__dirname, '../..');

/**
 * Dummy `admin` address in each package `Move.toml` under `contracts/` for `aptos move compile` without CLI named-addresses.
 * E2e publish copies the tree to a temp dir and replaces this exact string with the real publisher address.
 */
export const ADMIN_PLACEHOLDER_FOR_MOVE_TOML =
    '0xcafe';
export const ACCESS_CONTROL_CONTRACT_DIR = path.join(REPO_ROOT, 'examples/shelby-access-control-aptos/contract');

/**
 * Path to the `worker-rs` debug binary after `cargo build`.
 * When `CARGO_TARGET_DIR` is set (e.g. Cursor agent / some CI), `cargo` writes
 * the artifact there — not under `worker-rs/target/` — so we must run that copy.
 */
const cargoDebugDir = process.env.CARGO_TARGET_DIR
    ? path.join(process.env.CARGO_TARGET_DIR, 'debug')
    : path.join(REPO_ROOT, 'target', 'debug');

export const WORKER_BINARY = process.env.CARGO_TARGET_DIR
    ? path.join(process.env.CARGO_TARGET_DIR, 'debug', 'worker-rs')
    : path.join(REPO_ROOT, 'worker-rs', 'target', 'debug', 'worker-rs');

/** `vss-dealer` binary from the repo-root Cargo workspace (`cargo build` at `REPO_ROOT`). */
export const VSS_DEALER_BINARY = path.join(cargoDebugDir, 'vss-dealer');

/** `vss-recipient` binary from the repo-root Cargo workspace. */
export const VSS_RECIPIENT_BINARY = path.join(cargoDebugDir, 'vss-recipient');

/** `dkg-worker` binary from the repo-root Cargo workspace. */
export const DKG_WORKER_BINARY = path.join(cargoDebugDir, 'dkg-worker');

/** `dkr-src` binary from the repo-root Cargo workspace. */
export const DKR_SRC_BINARY = path.join(cargoDebugDir, 'dkr-src');

/** `dkr-dst` binary from the repo-root Cargo workspace. */
export const DKR_DST_BINARY = path.join(cargoDebugDir, 'dkr-dst');

export const LOCALNET_URL = 'http://localhost:8080/v1';
export const FAUCET_URL = 'http://localhost:8081';
export const CHAIN_ID = 4; // localnet

export const NUM_WORKERS = 4;
export const THRESHOLD = 3;
export const WORKER_BASE_PORT = 9000;
