// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/** Prepare the complete M0-governed v6 publication sequence offline. */
import { execFileSync } from 'child_process';
import { createHash } from 'crypto';
import { existsSync, readFileSync, readdirSync, writeFileSync } from 'fs';
import * as path from 'path';
import { AccountAddress } from '@aptos-labs/ts-sdk';
import { prepareContractsPublishScratch, rmContractsPublishScratch, REPO_ROOT } from '../deploy-contracts.js';
import { buildV6GovernancePayload } from './v6-governance.js';

const V6_PACKAGES = [
    'publisher', 'pke', 'worker_config', 'group', 'secret-usage',
    'fiat-shamir-transform', 'sigma-dlog-linear', 'pedersen-polynomial-commitment',
    'vss', 'dkg', 'dkr', 'epoch-change', 'epoch', 'voting', 'network',
] as const;

type BootstrapInput = {
    initial_multisig: string;
    seed_hex: string;
    ace_address?: string;
    version?: string;
    nodes: string[];
    threshold: number;
    resharing_interval_secs: number | string;
    initial_secret_requests?: Array<{ expected_usage: number | string; note: string }>;
    initial_features?: number[];
};

type PlanStep = {
    ordinal: number;
    action: string;
    package?: string;
    multisig: string;
    payload_hex: string;
};

export type V6BootstrapPlan = {
    schema: 'ace-v6-bootstrap-plan-v1';
    initial_multisig: string;
    ace_address: string;
    resource_seed_hex: string;
    steps: PlanStep[];
};

function parseHex(input: string, name: string): Buffer {
    if (typeof input !== 'string') throw new Error(`${name} must be hex`);
    const hex = input.replace(/^0x/, '');
    if (hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) throw new Error(`${name} must be even-length hex`);
    return Buffer.from(hex, 'hex');
}

export function deriveResourceAccount(multisig: string, seed: Uint8Array): string {
    const owner = AccountAddress.fromString(multisig);
    const hash = createHash('sha3-256')
        .update(Buffer.from(owner.toUint8Array()))
        .update(seed)
        .update(Buffer.from([0xff]))
        .digest('hex');
    return `0x${hash}`;
}

function patchInitialMultisig(scratchRoot: string, address: string): void {
    const tomlPath = path.join(scratchRoot, 'publisher', 'Move.toml');
    const original = readFileSync(tomlPath, 'utf8');
    if (!original.includes('initial_multisig = "0xfeed"')) {
        throw new Error('publisher Move.toml lacks the expected 0xfeed initial-multisig placeholder');
    }
    writeFileSync(tomlPath, original.replace('initial_multisig = "0xfeed"', `initial_multisig = "${address}"`));
}

function compilePackage(scratchRoot: string, folder: string): { metadata_hex: string; modules_hex: string[] } {
    const packageDir = path.join(scratchRoot, folder);
    const packageToml = readFileSync(path.join(packageDir, 'Move.toml'), 'utf8');
    const packageName = packageToml.match(/^name\s*=\s*"([^"]+)"/m)?.[1];
    if (!packageName) throw new Error(`Cannot read package name from ${folder}/Move.toml`);
    execFileSync('aptos', [
        'move', 'compile', '--package-dir', packageDir,
        '--skip-fetch-latest-git-deps', '--save-metadata',
    ], { cwd: REPO_ROOT, stdio: 'pipe', maxBuffer: 16 * 1024 * 1024 });
    const build = path.join(packageDir, 'build', packageName);
    const metadata = path.join(build, 'package-metadata.bcs');
    const modulesDir = path.join(build, 'bytecode_modules');
    if (!existsSync(metadata) || !existsSync(modulesDir)) {
        throw new Error(`${folder} compile did not produce package metadata and modules`);
    }
    const modules = readdirSync(modulesDir).filter(name => name.endsWith('.mv')).sort();
    if (!modules.length) throw new Error(`${folder} compiled no Move modules`);
    return {
        metadata_hex: readFileSync(metadata).toString('hex'),
        modules_hex: modules.map(name => readFileSync(path.join(modulesDir, name)).toString('hex')),
    };
}

/** Compile all v6 packages and return their unsigned native multisig payloads. */
export function buildV6BootstrapPlan(input: BootstrapInput): V6BootstrapPlan {
    const initialMultisig = AccountAddress.fromString(input.initial_multisig).toStringLong();
    const seed = parseHex(input.seed_hex, 'seed_hex');
    const ace = deriveResourceAccount(initialMultisig, seed);
    if (input.ace_address && AccountAddress.fromString(input.ace_address).toStringLong() !== ace) {
        throw new Error(`ace_address does not match resource account derived from M0 and seed: ${ace}`);
    }
    if (input.version && !/^\d+\.\d+\.\d+$/.test(input.version)) {
        throw new Error('version must be X.Y.Z');
    }
    const scratch = prepareContractsPublishScratch(path.join(REPO_ROOT, 'contracts'), ace, input.version);
    try {
        patchInitialMultisig(scratch.contractsDir, initialMultisig);
        const steps: PlanStep[] = [];
        for (const folder of V6_PACKAGES) {
            const pkg = compilePackage(scratch.contractsDir, folder);
            const kind = folder === 'publisher' ? 'resource-publish' : 'publisher-bootstrap';
            const doc = folder === 'publisher' ? { ...pkg, seed_hex: seed.toString('hex') } : pkg;
            const payload = buildV6GovernancePayload(kind, ace, doc);
            steps.push({
                ordinal: steps.length + 1,
                action: folder === 'publisher' ? 'M0 create resource account and publish Publisher' : `M0 publish ${folder}`,
                package: folder,
                multisig: initialMultisig,
                payload_hex: `0x${Buffer.from(payload).toString('hex')}`,
            });
        }
        const initialPayload = buildV6GovernancePayload('initial-epoch', ace, {
            nodes: input.nodes,
            threshold: input.threshold,
            resharing_interval_secs: input.resharing_interval_secs,
            initial_secret_requests: input.initial_secret_requests ?? [],
            initial_features: input.initial_features ?? [],
        });
        steps.push({
            ordinal: steps.length + 1,
            action: 'M0 start initial epoch',
            multisig: initialMultisig,
            payload_hex: `0x${Buffer.from(initialPayload).toString('hex')}`,
        });
        return {
            schema: 'ace-v6-bootstrap-plan-v1',
            initial_multisig: initialMultisig,
            ace_address: ace,
            resource_seed_hex: seed.toString('hex'),
            steps,
        };
    } finally {
        rmContractsPublishScratch(scratch);
    }
}

export function v6BootstrapPlanCommand(file: string, outputFile: string): void {
    const input = JSON.parse(readFileSync(file, 'utf8')) as BootstrapInput;
    const plan = buildV6BootstrapPlan(input);
    writeFileSync(outputFile, `${JSON.stringify(plan, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
    console.log(`Compiled ${V6_PACKAGES.length} packages and wrote ${plan.steps.length} unsigned M0 payloads to ${outputFile}`);
    console.log(`@ace resource account: ${plan.ace_address}`);
}
