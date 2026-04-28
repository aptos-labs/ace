// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

const REFRESH_MS = 2000;

/**
 * Run render() in a loop, printing to alt-screen, until user presses [Q].
 * render() is called immediately, then every REFRESH_MS.
 */
export async function runWatch(render: () => Promise<string>): Promise<void> {
    process.stdout.write('\x1b[?1049h'); // enter alt screen
    process.stdout.write('\x1b[?25l');   // hide cursor

    let running = true;

    if (process.stdin.isTTY) process.stdin.setRawMode(true);
    process.stdin.resume();
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (key: string) => {
        if (key === 'q' || key === 'Q' || key === '\x03') running = false;
    });

    const restore = () => {
        if (process.stdin.isTTY) process.stdin.setRawMode(false);
        process.stdin.pause();
        process.stdout.write('\x1b[?25h');   // show cursor
        process.stdout.write('\x1b[?1049l'); // exit alt screen
    };

    process.once('SIGINT',  () => { restore(); process.exit(0); });
    process.once('SIGTERM', () => { restore(); process.exit(0); });

    try {
        while (running) {
            let content: string;
            try {
                content = await render();
            } catch (e) {
                content = `Error: ${e instanceof Error ? e.message : String(e)}`;
            }

            process.stdout.write('\x1b[H\x1b[2J'); // move to top, clear screen
            process.stdout.write(content);
            process.stdout.write(`\n\n\x1b[2mRefreshing every ${REFRESH_MS / 1000}s  [Q] quit\x1b[0m\n`);

            const deadline = Date.now() + REFRESH_MS;
            while (running && Date.now() < deadline) {
                await new Promise(r => setTimeout(r, 100));
            }
        }
    } finally {
        restore();
    }
}
