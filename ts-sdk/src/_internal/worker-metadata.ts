// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

export function collectSettledWorkerMetadata<T>(
    settled: PromiseSettledResult<T>[],
    workerAddresses: string[],
): { values: T[], errors: string[] } {
    const values: T[] = [];
    const errors: string[] = [];
    settled.forEach((result, sdkIdx) => {
        if (result.status === "fulfilled") {
            values.push(result.value);
        } else {
            errors.push(`${workerAddresses[sdkIdx]}: ${String(result.reason)}`);
        }
    });
    return { values, errors };
}
