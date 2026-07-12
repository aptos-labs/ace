import { spawnSync } from 'child_process';

const scenarios = [
    'test-vss-protocol',
    'test-vss-protocol-g1',
    'test-dkg-protocol',
    'test-dkg-protocol-g1',
    'test-dkr-protocol',
    'test-dkr-protocol-g1',
    'test-threshold-vrf-derive-flow',
    'test-ibe-aptos-basic',
    'test-ibe-aptos-custom',
    'test-network-protocol',
    'full-happy-path',
    'test-auto-epoch-change',
];

const env = {
    ...process.env,
    ACE_SKIP_CARGO_BUILD: '1',
    CARGO_TARGET_DIR: new URL('../target', import.meta.url).pathname,
};

for (const scenario of scenarios) {
    console.log(`===== RUNNING ${scenario} =====`);
    const result = spawnSync('npx', ['tsx', `${scenario}.ts`], {
        cwd: new URL('.', import.meta.url).pathname,
        env,
        stdio: 'inherit',
    });
    if (result.status !== 0) {
        console.error(`===== FAIL ${scenario} =====`);
        process.exit(result.status ?? 1);
    }
    console.log(`===== PASS ${scenario} =====`);
}

console.log('ALL SCENARIOS PASSED');
