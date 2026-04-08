// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import * as path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const REPO_ROOT = path.resolve(__dirname, '../..');
export const CONTRACT_DIR = path.join(REPO_ROOT, 'contract');
export const ACCESS_CONTROL_CONTRACT_DIR = path.join(REPO_ROOT, 'examples/shelby-access-control-aptos/contract');
export const WORKER_BINARY = path.join(REPO_ROOT, 'worker-rs/target/debug/worker-rs');

export const LOCALNET_URL = 'http://localhost:8080/v1';
export const FAUCET_URL = 'http://localhost:8081';
export const CHAIN_ID = 4; // localnet

export const NUM_WORKERS = 4;
export const THRESHOLD = 3;
export const WORKER_BASE_PORT = 9000;
