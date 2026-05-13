// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Render an ASCII line chart of latency percentiles vs QPS from a results CSV
 * via gnuplot's dumb terminal. No-op (with a hint) when gnuplot isn't on PATH.
 */

import { spawnSync } from 'child_process';

export function plotAsciiIfAvailable(csvPath: string): void {
    const found = spawnSync('gnuplot', ['--version'], { stdio: 'ignore' }).status === 0;
    if (!found) {
        console.log('  (install gnuplot to see an ASCII latency-vs-QPS chart here)');
        return;
    }
    const script = `
set terminal dumb 100 28
set datafile separator ","
set title "Worker decryption-share latency vs QPS"
set xlabel "QPS"
set ylabel "latency (ms)"
set logscale x
set logscale y
set key right top
set grid
plot \\
    "${csvPath}" every ::1 using 1:4 with linespoints title "p50",  \\
    "${csvPath}" every ::1 using 1:6 with linespoints title "p90",  \\
    "${csvPath}" every ::1 using 1:8 with linespoints title "p99"
`;
    spawnSync('gnuplot', ['-'], { input: script, stdio: ['pipe', 'inherit', 'inherit'] });
}
