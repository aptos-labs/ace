// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

export type ThresholdFetchTask<T> = (signal: AbortSignal) => Promise<T | null>;

const THRESHOLD_REACHED = "ace.fetch-until-threshold.threshold-reached";

export function wasAbortedAfterThreshold(signal: AbortSignal): boolean {
    return signal.aborted && signal.reason === THRESHOLD_REACHED;
}

/**
 * Run all tasks concurrently and return as soon as `threshold` valid results arrive.
 * Outstanding tasks are aborted after success; each task also has its own deadline.
 */
export function fetchUntilThreshold<Candidate, Result>({
    tasks,
    validate,
    threshold,
    timeoutMs,
}: {
    tasks: ThresholdFetchTask<Candidate>[],
    validate: (candidate: Candidate) => Result | null,
    threshold: number,
    timeoutMs: number,
}): Promise<Result[]> {
    if (!Number.isInteger(threshold) || threshold <= 0) {
        return Promise.reject(new Error(`fetchUntilThreshold: threshold must be positive, got ${threshold}`));
    }
    if (tasks.length < threshold) {
        return Promise.reject(new Error(`fetchUntilThreshold: need ${threshold} results, only ${tasks.length} tasks`));
    }

    const controllers = tasks.map(() => new AbortController());
    const timeoutIds: ReturnType<typeof setTimeout>[] = [];
    const results: Result[] = [];
    let settled = 0;
    let done = false;

    return new Promise<Result[]>((resolve, reject) => {
        tasks.forEach((task, i) => {
            const controller = controllers[i];
            const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
            timeoutIds.push(timeoutId);

            Promise.resolve()
                .then(() => task(controller.signal))
                .then((candidate) => {
                    if (done || candidate === null) return;
                    const result = validate(candidate);
                    if (result === null) return;

                    results.push(result);
                    if (results.length >= threshold) {
                        done = true;
                        timeoutIds.forEach(clearTimeout);
                        controllers.forEach((pending, pendingIdx) => {
                            if (pendingIdx !== i) pending.abort(THRESHOLD_REACHED);
                        });
                        resolve(results.slice(0, threshold));
                    }
                })
                .catch(() => {
                    // A failed worker contributes no result. The caller logs useful details.
                })
                .finally(() => {
                    clearTimeout(timeoutId);
                    settled += 1;
                    if (done) return;

                    if (settled === tasks.length) {
                        done = true;
                        reject(new Error(`fetchUntilThreshold: need ${threshold} results, got ${results.length}`));
                    }
                });
        });
    });
}
