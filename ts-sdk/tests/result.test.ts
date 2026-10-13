// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import { Result } from '../src/result';

describe('Result.unwrapOrThrow', () => {
    it('returns the value when successful', () => {
        expect(Result.Ok({ value: 42 }).unwrapOrThrow('unused')).toBe(42);
    });

    it('throws the supplied context with the original error as cause', () => {
        const cause = new Error('inner failure');
        const result = Result.Err<number>({ error: cause });

        try {
            result.unwrapOrThrow('outer failure');
            expect.fail('expected unwrapOrThrow to throw');
        } catch (thrown) {
            expect(thrown).toBeInstanceOf(Error);
            expect((thrown as Error).message).toBe('outer failure');
            expect((thrown as Error & { err: string }).err).toBe('outer failure');
            expect((thrown as Error).cause).toBe(cause);
        }
    });

    it('keeps a primitive Result error as the cause', () => {
        expect(() => Result.Err({ error: 'inner failure' }).unwrapOrThrow('outer failure'))
            .toThrowError(expect.objectContaining({ cause: 'inner failure' }));
    });
});
