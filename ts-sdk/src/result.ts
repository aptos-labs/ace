// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

export class Result<T> {
    isOk: boolean;
    okValue?: T;
    errValue?: any;
    extra?: any;

    private constructor({ isOk, okValue, errValue, extra }: { isOk: boolean, okValue?: T, errValue?: any, extra?: any }) {
        this.isOk = isOk;
        this.okValue = okValue;
        this.errValue = errValue;
        this.extra = extra;
    }

    static Ok<T>(args: {value: T, extra?: any}): Result<T> {
        return new Result<T>({ isOk: true, okValue: args.value, extra: args.extra });
    }

    static Err<T>(args: {error: any, extra?: any}): Result<T> {
        return new Result<T>({ isOk: false, errValue: args.error, extra: args.extra });
    }

    /**
     * You write a closure that either returns a T or throws, and we wrap it to return a Result<T>.
     * Your closure is also given an `extra` dictionary to record additional context.
     */
    static capture<T>({task, recordsExecutionTimeMs = false}: {task: (extra: Record<string, any>) => T, recordsExecutionTimeMs: boolean}): Result<T> {
        const start = performance.now();
        var extra: Record<string, any> = {};
        var error;
        var okValue;

        try {
            okValue = task(extra);
        } catch (caught) {
            error = caught;
        } finally {
            if (recordsExecutionTimeMs) {
                extra['_sdk_execution_time_ms'] = performance.now() - start;
            }
            if (error !== undefined) {
                return Result.Err({ error, extra });
            } else {
                return Result.Ok({ value: okValue!, extra });
            }
        }
    }

    /**
     * You write an async closure that either returns a T or throws, and we wrap it to return a Result<T>.
     * Your closure is also given an `extra` dictionary to record additional context.
     */
    static async captureAsync<T>({task, recordsExecutionTimeMs = false}: {task: (extra: Record<string, any>) => Promise<T>, recordsExecutionTimeMs: boolean}): Promise<Result<T>> {
        var extra: Record<string, any> = {};
        const start = performance.now();
        var error;
        var okValue;
        try {
            okValue = await task(extra);
        } catch (caught) {
            error = caught;
        } finally {
            if (recordsExecutionTimeMs) {
                extra['_sdk_execution_time_ms'] = performance.now() - start;
            }
            if (error !== undefined) {
                return Result.Err({ error, extra });
            } else {
                return Result.Ok({ value: okValue!, extra });
            }
        }
    }

    unwrapOrThrow(tothrow: any): T {
        if (!this.isOk) throw tothrow;
        return this.okValue!;
    }

    unwrapErrOrThrow(tothrow: any): any | undefined {
        if (this.isOk) throw tothrow;
        return this.errValue;
    }
}

