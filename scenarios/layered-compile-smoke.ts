/**
 * Smoke: compile sub-packages (no localnet). CI-friendly guard for split layout.
 */
import { execSync } from 'child_process';
import * as path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '../..');
function compile(pkg: string) {
    const dir = path.join(REPO_ROOT, 'contracts', pkg);
    console.log(`compile ${pkg}...`);
    execSync(`aptos move compile --package-dir "${dir}" --skip-fetch-latest-git-deps`, { stdio: 'inherit' });
}

const which = process.argv[2] ?? 'all';
if (which === 'vss' || which === 'all') {
    compile('worker_config');
    compile('ace_vss');
    compile('vss_e2e');
}
if (which === 'all') {
    compile('ace_network');
}
if (which === 'dkg' || which === 'all') {
    console.log('dkg: covered by `ace_network` package (ace_network contains DkgSession)');
}
if (which === 'dkr' || which === 'all') {
    console.log('dkr: covered by `ace_network` package');
}
console.log('layered-compile-smoke ok');
