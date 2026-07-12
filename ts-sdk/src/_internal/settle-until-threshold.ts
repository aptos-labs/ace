// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

export type ThresholdTask<T> = (signal: AbortSignal) => Promise<T>;

export type ThresholdSettledResult<T> =
    | PromiseSettledResult<T>
    | { status: "discarded" };

const THRESHOLD_REACHED = "ace.settle-until-threshold.threshold-reached";

/**
 * Run every task concurrently and settle once `threshold` tasks fulfill or all
 * tasks finish. Results retain task order; unfinished tasks are discarded and
 * receive an abort signal after the threshold is reached. Cancellation is
 * cooperative: a discarded task may still finish work it already started.
 */
export function settleUntilThreshold<T>(
    tasks: ThresholdTask<T>[],
    threshold: number,
): Promise<ThresholdSettledResult<T>[]> {
    if (!Number.isInteger(threshold) || threshold <= 0) {
        return Promise.reject(new RangeError(`settleUntilThreshold: threshold must be positive, got ${threshold}`));
    }
    if (tasks.length === 0) return Promise.resolve([]);

    const controllers = tasks.map(() => new AbortController());
    const results = new Array<ThresholdSettledResult<T> | undefined>(tasks.length);
    let fulfilled = 0;
    let settled = 0;
    let done = false;

    return new Promise<ThresholdSettledResult<T>[]>((resolve) => {
        const finish = () => {
            done = true;
            resolve(results as ThresholdSettledResult<T>[]);
        };

        const discardUnsettledAndFinish = () => {
            for (let i = 0; i < results.length; i += 1) {
                if (results[i] !== undefined) continue;
                results[i] = { status: "discarded" };
                controllers[i].abort(THRESHOLD_REACHED);
            }
            finish();
        };

        tasks.forEach((task, i) => {
            Promise.resolve()
                .then(() => task(controllers[i].signal))
                .then(
                    (value) => {
                        if (done) return;
                        results[i] = { status: "fulfilled", value };
                        fulfilled += 1;
                        settled += 1;
                        if (fulfilled >= threshold) {
                            discardUnsettledAndFinish();
                        } else if (settled === tasks.length) {
                            finish();
                        }
                    },
                    (reason) => {
                        if (done) return;
                        results[i] = { status: "rejected", reason };
                        settled += 1;
                        if (settled === tasks.length) finish();
                    },
                );
        });
    });
}
