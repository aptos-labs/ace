// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { input, select, confirm } from '@inquirer/prompts';
import { execSync } from 'child_process';
import { writeFileSync, mkdirSync } from 'fs';
import { homedir } from 'os';
import * as path from 'path';
import { generateProfile } from './new-profile.js';
import { registerOnChain } from './register.js';
import { selectImage } from './docker-hub.js';
import { loadConfig, makeNodeKey, type TrackedNode, type ChainRpcOverrides, type LocalConfig } from './config.js';
import { logFilePath, spawnLocalNode } from './local-process.js';

const LOGROTATE_DIR   = path.join(homedir(), '.ace', 'logrotate');
const LOGROTATE_STATE = path.join(LOGROTATE_DIR, 'logrotate.state');

export function writeLogrotateConf(logFile: string, maxMb: number): string {
    mkdirSync(LOGROTATE_DIR, { recursive: true });
    const confFile = path.join(LOGROTATE_DIR, path.basename(logFile) + '.conf');
    const conf = [
        `${logFile} {`,
        `    size ${maxMb}M`,
        `    rotate 1`,
        `    copytruncate`,
        `    nocompress`,
        `    missingok`,
        `    notifempty`,
        `}`,
    ].join('\n') + '\n';
    writeFileSync(confFile, conf);
    return confFile;
}

export function runLogrotate(confFile: string): void {
    try {
        execSync(`logrotate --state ${LOGROTATE_STATE} ${confFile}`, { stdio: 'ignore' });
    } catch { /* rotation errors are non-fatal */ }
}

const CHAIN_DEFAULTS = {
    aptosMainnet:      'https://api.mainnet.aptoslabs.com/v1',
    aptosTestnet:      'https://api.testnet.aptoslabs.com/v1',
    aptosLocalnet:     'http://127.0.0.1:8080/v1',
    solanaMainnetBeta: 'https://api.mainnet-beta.solana.com',
    solanaTestnet:     'https://api.testnet.solana.com',
    solanaDevnet:      'https://api.devnet.solana.com',
} as const;

function defaultGcpProject(): string | undefined {
    try {
        const out = execSync('gcloud config get-value project 2>/dev/null', { encoding: 'utf8' }).trim();
        return out || undefined;
    } catch {
        return undefined;
    }
}

export function dockerRpcUrl(rpcUrl: string): string {
    return rpcUrl.replace(/localhost/g, 'host.docker.internal')
                 .replace(/127\.0\.0\.1/g, 'host.docker.internal');
}

export function gcpDeployCmd(
    serviceName: string, image: string, project: string, region: string,
    node: { accountAddr: string; accountSk: string; pkeDk: string },
    rpcUrl: string, aceAddr: string, rpcApiKey?: string, gasStationKey?: string,
    chainRpc?: ChainRpcOverrides,
): string {
    const args = nodeRunArgs(node, rpcUrl, aceAddr, rpcApiKey, gasStationKey, chainRpc);
    return [
        `gcloud run deploy ${serviceName}`,
        `  --image docker.io/${image}`,
        `  --project ${project}`,
        `  --region ${region}`,
        `  --no-allow-unauthenticated`,
        `  --min-instances 1`,
        `  --no-cpu-throttling`,
        `  --args "${args.join(',')}"`,
    ].join(' \\\n');
}

export function dockerRunCmd(
    containerName: string, image: string, port: string,
    node: { accountAddr: string; accountSk: string; pkeDk: string },
    rpcUrl: string, aceAddr: string, rpcApiKey?: string, gasStationKey?: string,
    chainRpc?: ChainRpcOverrides,
): string {
    return [
        `docker run -d --platform linux/amd64 --restart unless-stopped`,
        `  --name ${containerName}`,
        `  -p ${port}:${port}`,
        `  ${image}`,
        `  run`,
        `  --ace-deployment-api=${rpcUrl}`,
        `  --ace-deployment-addr=${aceAddr}`,
        ...(rpcApiKey     ? [`  --ace-deployment-apikey=${rpcApiKey}`]     : []),
        ...(gasStationKey ? [`  --ace-deployment-gaskey=${gasStationKey}`] : []),
        `  --account-addr=${node.accountAddr}`,
        `  --account-sk=${node.accountSk}`,
        `  --pke-dk=${node.pkeDk}`,
        `  --port=${port}`,
        ...chainRpcArgs(chainRpc),
    ].join(' \\\n');
}

export function localBuildCmd(repoPath: string): string {
    return `cargo build --release -p network-node --manifest-path ${repoPath}/Cargo.toml`;
}

export function localRunCmd(
    repoPath: string, port: string,
    node: { accountAddr: string; accountSk: string; pkeDk: string },
    rpcUrl: string, aceAddr: string, rpcApiKey?: string, gasStationKey?: string,
    chainRpc?: ChainRpcOverrides,
): string {
    return [
        `${repoPath}/target/release/network-node run`,
        `  --ace-deployment-api=${rpcUrl}`,
        `  --ace-deployment-addr=${aceAddr}`,
        ...(rpcApiKey     ? [`  --ace-deployment-apikey=${rpcApiKey}`]     : []),
        ...(gasStationKey ? [`  --ace-deployment-gaskey=${gasStationKey}`] : []),
        `  --account-addr=${node.accountAddr}`,
        `  --account-sk=${node.accountSk}`,
        `  --pke-dk=${node.pkeDk}`,
        `  --port=${port}`,
        ...chainRpcArgs(chainRpc).map(a => `  ${a}`),
    ].join(' \\\n');
}

export function localRunArgs(
    port: string,
    node: { accountAddr: string; accountSk: string; pkeDk: string },
    rpcUrl: string, aceAddr: string, rpcApiKey?: string, gasStationKey?: string,
    chainRpc?: ChainRpcOverrides,
): string[] {
    return [
        'run',
        `--ace-deployment-api=${rpcUrl}`,
        `--ace-deployment-addr=${aceAddr}`,
        ...(rpcApiKey     ? [`--ace-deployment-apikey=${rpcApiKey}`]     : []),
        ...(gasStationKey ? [`--ace-deployment-gaskey=${gasStationKey}`] : []),
        `--account-addr=${node.accountAddr}`,
        `--account-sk=${node.accountSk}`,
        `--pke-dk=${node.pkeDk}`,
        `--port=${port}`,
        ...chainRpcArgs(chainRpc),
    ];
}

function defaultRepoPath(): string | undefined {
    try {
        const out = execSync('git rev-parse --show-toplevel 2>/dev/null', { encoding: 'utf8' }).trim();
        if (out && out.includes('ace')) return out;
    } catch { /* ignore */ }
    return undefined;
}

function nodeRunArgs(
    node: { accountAddr: string; accountSk: string; pkeDk: string },
    rpcUrl: string, aceAddr: string, rpcApiKey?: string, gasStationKey?: string,
    chainRpc?: ChainRpcOverrides,
): string[] {
    return [
        'run',
        `--ace-deployment-api=${rpcUrl}`,
        `--ace-deployment-addr=${aceAddr}`,
        ...(rpcApiKey     ? [`--ace-deployment-apikey=${rpcApiKey}`]     : []),
        ...(gasStationKey ? [`--ace-deployment-gaskey=${gasStationKey}`] : []),
        `--account-addr=${node.accountAddr}`,
        `--account-sk=${node.accountSk}`,
        `--pke-dk=${node.pkeDk}`,
        '--port=8080',
        ...chainRpcArgs(chainRpc),
    ];
}

function chainRpcArgs(r?: ChainRpcOverrides): string[] {
    if (!r) return [];
    const f = (flag: string, val?: string) => val ? [`${flag}${val}`] : [];
    return [
        ...f('--aptos-mainnet-api=',       r.aptosMainnetApi),
        ...f('--aptos-mainnet-apikey=',    r.aptosMainnetApikey),
        ...f('--aptos-testnet-api=',       r.aptosTestnetApi),
        ...f('--aptos-testnet-apikey=',    r.aptosTestnetApikey),
        ...f('--aptos-localnet-api=',      r.aptosLocalnetApi),
        ...f('--aptos-localnet-apikey=',   r.aptosLocalnetApikey),
        ...f('--solana-mainnet-beta-rpc=', r.solanaMainnetBetaRpc),
        ...f('--solana-testnet-rpc=',      r.solanaTestnetRpc),
        ...f('--solana-devnet-rpc=',       r.solanaDevnetRpc),
    ];
}

export async function promptChainRpcOverrides(
    current?: ChainRpcOverrides,
    transformDefault: (url: string) => string = u => u,
): Promise<ChainRpcOverrides> {
    console.log('\nPer-chain RPC endpoints  (Enter to use default)\n');

    const askUrl = async (msg: string, pubDefault: string, cur?: string): Promise<string | undefined> => {
        const effectiveDefault = cur ?? transformDefault(pubDefault);
        const val = (await input({ message: msg, default: effectiveDefault })).trim();
        return val === pubDefault ? undefined : val || undefined;
    };

    const askKey = async (msg: string, cur?: string): Promise<string | undefined> => {
        const hint = cur ? ' (Enter to keep, "none" to clear)' : ' (Enter to skip)';
        const val = (await input({ message: msg + hint, default: '' })).trim();
        if (val === 'none') return undefined;
        return val || cur;
    };

    const r: ChainRpcOverrides = {
        aptosMainnetApi:      await askUrl('Aptos mainnet API URL',        CHAIN_DEFAULTS.aptosMainnet,      current?.aptosMainnetApi),
        aptosMainnetApikey:   await askKey('Aptos mainnet API key',        current?.aptosMainnetApikey),
        aptosTestnetApi:      await askUrl('Aptos testnet API URL',        CHAIN_DEFAULTS.aptosTestnet,      current?.aptosTestnetApi),
        aptosTestnetApikey:   await askKey('Aptos testnet API key',        current?.aptosTestnetApikey),
        aptosLocalnetApi:     await askUrl('Aptos localnet API URL',       CHAIN_DEFAULTS.aptosLocalnet,     current?.aptosLocalnetApi),
        aptosLocalnetApikey:  await askKey('Aptos localnet API key',       current?.aptosLocalnetApikey),
        solanaMainnetBetaRpc: await askUrl('Solana mainnet-beta RPC URL',  CHAIN_DEFAULTS.solanaMainnetBeta, current?.solanaMainnetBetaRpc),
        solanaTestnetRpc:     await askUrl('Solana testnet RPC URL',       CHAIN_DEFAULTS.solanaTestnet,     current?.solanaTestnetRpc),
        solanaDevnetRpc:      await askUrl('Solana devnet RPC URL',        CHAIN_DEFAULTS.solanaDevnet,      current?.solanaDevnetRpc),
    };

    console.log();
    return Object.fromEntries(Object.entries(r).filter(([, v]) => v !== undefined)) as ChainRpcOverrides;
}

interface NetworkDetails {
    rpcUrl:     string;
    aceAddr:    string;
    rpcApiKey?: string;
    gasStationKey?: string;
}

async function probeEndpoint(url: string): Promise<boolean> {
    try {
        await fetch(url, { method: 'GET', signal: AbortSignal.timeout(3000) });
        return true;
    } catch {
        return false;
    }
}


async function promptEndpoint(message: string, defaultValue?: string): Promise<string> {
    let last = defaultValue;
    while (true) {
        const url = (await input({ message, default: last })).trim();
        if (!url) continue;
        last = url;

        process.stdout.write('  Checking node reachability...');
        if (await probeEndpoint(url)) {
            process.stdout.write(' ✓\n\n');
            return url;
        }
        process.stdout.write(' ✗  (not reachable)\n\n');
    }
}

/** Full guided wizard for adding a new node you control. */
export async function runOnboarding(): Promise<{ nodeKey: string; node: TrackedNode }> {
    const existingConfig = loadConfig();
    console.log('\n  ACE Node Setup\n');

    console.log('Generating node keys...\n');
    const profile = generateProfile();
    console.log(`  Account address : ${profile.accountAddr}`);
    console.log(`  PKE enc key     : ${profile.pkeEk}\n`);

    const net: NetworkDetails = await promptNetworkDetails();

    const platform = await select<'gcp' | 'docker' | 'local'>({
        message: 'Where will you run this node?',
        choices: [
            { name: 'Google Cloud Platform (Cloud Run)', value: 'gcp' },
            { name: 'My own machine (Docker)',            value: 'docker' },
            { name: 'Local build (from source, requires repo)', value: 'local' },
        ],
    });

    const image = platform !== 'local' ? (await selectImage() ?? 'aptoslabs/ace-node:latest') : undefined;
    if (platform !== 'local') console.log();

    let chainRpc: ChainRpcOverrides = {};
    if (await confirm({ message: 'Configure per-chain RPC overrides?', default: false })) {
        chainRpc = await promptChainRpcOverrides(undefined, platform === 'docker' ? dockerRpcUrl : undefined);
    } else {
        console.log();
    }

    let endpoint:    string;
    let nodeRpcUrl:  string | undefined;
    let gcpCfg:      TrackedNode['gcp'];
    let dockerCfg:   TrackedNode['docker'];
    let localCfg:    LocalConfig | undefined;

    if (platform === 'gcp') {
        const project     = await input({ message: 'GCP project ID', default: defaultGcpProject() });
        const region      = await input({ message: 'Region', default: 'us-central1' });
        const contractPrefix = net.aceAddr.replace(/^0x/i, '').slice(0, 6);
        const accountPrefix  = profile.accountAddr.replace(/^0x/i, '').slice(0, 6);
        const serviceName = await input({
            message: 'Service name',
            default: `ace-${contractPrefix}-${accountPrefix}`,
            validate: (val) => {
                if (!/^[a-z]/.test(val)) return 'Must begin with a lowercase letter';
                if (!/^[a-z][a-z0-9-]*$/.test(val)) return 'Only lowercase letters, digits, and hyphens are allowed';
                if (val.endsWith('-')) return 'Must not end with a hyphen';
                if (val.length >= 64) return 'Must be less than 64 characters';
                return true;
            },
        });
        gcpCfg = { project, region, serviceName };

        console.log('\nRun this command to deploy your node:\n');
        console.log(gcpDeployCmd(serviceName, image!, project, region, profile, net.rpcUrl, net.aceAddr, net.rpcApiKey, net.gasStationKey, chainRpc));
        console.log();
        endpoint = await promptEndpoint('Cloud Run service URL (paste after deploy completes)');
    } else if (platform === 'docker') {
        const usedPorts = new Set(
            Object.values(existingConfig.nodes).map(n => n.docker?.port).filter(Boolean),
        );
        let defaultPort = 19000;
        while (usedPorts.has(String(defaultPort))) defaultPort++;

        const usedContainerNames = new Set(
            Object.values(existingConfig.nodes).map(n => n.docker?.containerName).filter(Boolean),
        );
        const contractPrefix = net.aceAddr.replace(/^0x/i, '').slice(0, 6);
        const accountPrefix  = profile.accountAddr.replace(/^0x/i, '').slice(0, 6);
        const defaultContainerName = (() => {
            const base = `ace-${contractPrefix}-${accountPrefix}`;
            if (!usedContainerNames.has(base)) return base;
            let i = 2;
            while (usedContainerNames.has(`${base}-${i}`)) i++;
            return `${base}-${i}`;
        })();

        const port          = await input({ message: 'Port', default: String(defaultPort) });
        const containerName = await input({ message: 'Container name', default: defaultContainerName });
        nodeRpcUrl          = (await input({ message: 'Deployment API URL (as seen by the node)', default: dockerRpcUrl(net.rpcUrl) })).trim();
        dockerCfg = { containerName, port };

        console.log('\nRun this command to start your node:\n');
        console.log(dockerRunCmd(containerName, image!, port, profile, nodeRpcUrl, net.aceAddr, net.rpcApiKey, net.gasStationKey, chainRpc));
        console.log();

        const isLocalnet = /localhost|127\.0\.0\.1/.test(net.rpcUrl);
        const defaultEndpoint = isLocalnet ? `http://localhost:${port}` : undefined;
        endpoint = await promptEndpoint("Your node's public URL", defaultEndpoint);
    } else {
        // local build
        const usedPorts = new Set(
            Object.values(existingConfig.nodes).map(n => n.local?.port ?? n.docker?.port).filter(Boolean),
        );
        let defaultPort = 19000;
        while (usedPorts.has(String(defaultPort))) defaultPort++;

        const repoPath = (await input({
            message: 'Path to ACE repo',
            default: defaultRepoPath(),
        })).trim();
        const port = await input({ message: 'Port', default: String(defaultPort) });
        const logMaxMbStr = await input({ message: 'Max log file size (MB, for logrotate)', default: '50' });
        const logMaxMb = Math.max(1, parseInt(logMaxMbStr) || 50);

        console.log('\nBuilding node binary (this may take a minute)...\n');
        execSync(localBuildCmd(repoPath), { stdio: 'inherit' });

        const nodeKey = makeNodeKey(net.rpcUrl, net.aceAddr, profile.accountAddr);
        const logFile = logFilePath(nodeKey);
        const binaryPath = path.join(repoPath, 'target', 'release', 'network-node');
        const runArgs = localRunArgs(port, profile, net.rpcUrl, net.aceAddr, net.rpcApiKey, net.gasStationKey, chainRpc);
        const pid = spawnLocalNode(binaryPath, runArgs, logFile);
        console.log(`\nNode started in background  pid=${pid}  log=${logFile}\n`);

        const logrotateConf = writeLogrotateConf(logFile, logMaxMb);
        runLogrotate(logrotateConf);

        localCfg = { repoPath, port, pid, logFile, logMaxMb };

        endpoint = await promptEndpoint("Your node's public URL", `http://localhost:${port}`);
    }

    const alias = (await input({ message: 'Node alias (Enter to skip)', default: '' })).trim() || undefined;

    await ensureAccountFunded(net.rpcUrl, profile.accountAddr, net.rpcApiKey, net.gasStationKey);

    console.log('\nRegistering on-chain...\n');
    await registerOnChain(
        { ...profile, rpcUrl: net.rpcUrl, aceAddr: net.aceAddr, rpcApiKey: net.rpcApiKey, gasStationKey: net.gasStationKey },
        endpoint,
    );

    const node: TrackedNode = {
        rpcUrl:      net.rpcUrl,
        nodeRpcUrl:  nodeRpcUrl !== net.rpcUrl ? nodeRpcUrl : undefined,
        aceAddr:     net.aceAddr,
        rpcApiKey:   net.rpcApiKey,
        accountAddr: profile.accountAddr,
        accountSk:   profile.accountSk,
        pkeDk:       profile.pkeDk,
        pkeEk:       profile.pkeEk,
        alias,
        endpoint,
        image,
        platform,
        gcp:          gcpCfg,
        docker:       dockerCfg,
        local:        localCfg,
        gasStationKey: net.gasStationKey,
        chainRpc: Object.keys(chainRpc).length > 0 ? chainRpc : undefined,
    };

    const nodeKey = makeNodeKey(net.rpcUrl, net.aceAddr, profile.accountAddr);

    console.log('\nShare your account address with the ACE deployer to be added to the committee:\n');
    console.log(`  ${profile.accountAddr}\n`);

    return { nodeKey, node };
}

const OCTAS_PER_APT = 100_000_000n;

function detectAptosNetwork(rpcUrl: string): 'localnet' | 'devnet' | 'testnet' | 'mainnet' | 'other' {
    if (/localhost|127\.0\.0\.1/.test(rpcUrl)) return 'localnet';
    if (/devnet\.aptoslabs\.com/.test(rpcUrl))  return 'devnet';
    if (/testnet\.aptoslabs\.com/.test(rpcUrl)) return 'testnet';
    if (/mainnet\.aptoslabs\.com/.test(rpcUrl)) return 'mainnet';
    return 'other';
}

function aptFaucetUrl(rpcUrl: string): string | undefined {
    if (/localhost/.test(rpcUrl))    return rpcUrl.replace(/:\d+\/.*$/, ':8081');
    if (/127\.0\.0\.1/.test(rpcUrl)) return rpcUrl.replace(/:\d+\/.*$/, ':8081');
    if (/devnet\.aptoslabs\.com/.test(rpcUrl))  return 'https://faucet.devnet.aptoslabs.com';
    if (/testnet\.aptoslabs\.com/.test(rpcUrl)) return 'https://faucet.testnet.aptoslabs.com';
    return undefined;
}

async function getAptBalance(rpcUrl: string, addr: string, apiKey?: string): Promise<bigint> {
    try {
        const type = encodeURIComponent('0x1::coin::CoinStore<0x1::aptos_coin::AptosCoin>');
        const url   = `${rpcUrl}/accounts/${addr}/resource/${type}`;
        const headers: HeadersInit = apiKey ? { Authorization: `Bearer ${apiKey}` } : {};
        const res = await fetch(url, { headers, signal: AbortSignal.timeout(5000) });
        if (!res.ok) return 0n;
        const data = await res.json() as { data: { coin: { value: string } } };
        return BigInt(data.data.coin.value);
    } catch {
        return 0n;
    }
}

async function ensureAccountFunded(
    rpcUrl: string, accountAddr: string, apiKey?: string, gasStationKey?: string,
): Promise<void> {
    if (gasStationKey) return;

    const network = detectAptosNetwork(rpcUrl);
    const faucet  = aptFaucetUrl(rpcUrl);

    if (network === 'localnet' || network === 'devnet') {
        if (faucet) {
            process.stdout.write('\nFunding account with 10 APT via faucet...');
            try {
                const res = await fetch(
                    `${faucet}/mint?address=${accountAddr}&amount=${10n * OCTAS_PER_APT}`,
                    { method: 'POST', signal: AbortSignal.timeout(5000) },
                );
                if (res.ok) { process.stdout.write(' ✓\n'); return; }
            } catch { /* fall through */ }
            process.stdout.write(' ✗  (faucet unreachable — fund manually before registering)\n');
        }
        return;
    }

    if (network !== 'testnet' && network !== 'mainnet') return;

    console.log();
    if (network === 'testnet' && faucet) {
        console.log('Fund your account using the testnet faucet:');
        console.log(`  curl -X POST '${faucet}/mint?address=${accountAddr}&amount=1000000000'\n`);
    } else {
        console.log(`Fund your account (${accountAddr}) with APT to cover transaction fees.\n`);
    }

    process.stdout.write('Waiting for account to receive APT...');
    while (true) {
        const bal = await getAptBalance(rpcUrl, accountAddr, apiKey);
        if (bal > 0n) {
            const apt = (Number(bal) / Number(OCTAS_PER_APT)).toFixed(4);
            process.stdout.write(` ✓  (${apt} APT)\n`);
            return;
        }
        await new Promise(r => setTimeout(r, 2000));
        process.stdout.write('.');
    }
}

async function promptNetworkDetails(): Promise<NetworkDetails> {
    console.log('\nACE deployment details\n');
    const blob = (await input({ message: 'Paste deployment blob from admin (or Enter to fill manually)' })).trim();
    if (blob) {
        try {
            const p = JSON.parse(blob) as Record<string, string>;
            if (typeof p.rpcUrl === 'string' && typeof p.aceAddr === 'string') {
                console.log(`  ✓ Parsed — contract ${p.aceAddr.slice(0, 10)}...\n`);
                return {
                    rpcUrl:        p.rpcUrl,
                    aceAddr:       p.aceAddr,
                    rpcApiKey:     p.rpcApiKey     || undefined,
                    gasStationKey: p.gasStationKey || undefined,
                };
            }
        } catch {
            // fall through
        }
        console.log('  Could not parse blob — please fill in manually.\n');
    }

    const rpcUrl        = await input({ message: 'Deployment API URL' });
    const aceAddr       = await input({ message: 'Contract address' });
    const rpcApiKey     = (await input({ message: 'API key         (Enter to skip)' })) || undefined;
    const gasStationKey = (await input({ message: 'Gas station key (Enter to skip)' })) || undefined;
    console.log();
    return { rpcUrl, aceAddr, rpcApiKey, gasStationKey };
}
