// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import { Result } from '../src/result';

describe('Result.unwrapOrThrow', () => {
    it('returns the value when successful', () => {
        expect(Result.Ok({ value: 42 }).unwrapOrThrow('unused')).toBe(42);
    });

    it('throws the supplied value unchanged by default', () => {
        const thrown = new Error('existing behavior');
        try {
            Result.Err({ error: 'inner failure' }).unwrapOrThrow(thrown);
            expect.fail('expected unwrapOrThrow to throw');
        } catch (error) {
            expect(error).toBe(thrown);
        }
        try {
            Result.Err({ error: 'inner failure' }).unwrapOrThrow('existing behavior');
            expect.fail('expected unwrapOrThrow to throw');
        } catch (error) {
            expect(error).toBe('existing behavior');
        }
    });

    it('opt-in throws the supplied context with the original error as cause', () => {
        const cause = new Error('inner failure');
        const result = Result.Err<number>({ error: cause });

        try {
            result.unwrapOrThrow('outer failure', true);
            expect.fail('expected unwrapOrThrow to throw');
        } catch (thrown) {
            expect(thrown).toBeInstanceOf(Error);
            expect((thrown as Error).message).toBe('outer failure');
            expect((thrown as Error & { err: string }).err).toBe('outer failure');
            expect((thrown as Error).cause).toBe(cause);
        }
    });

    it('keeps a primitive Result error as the cause', () => {
        expect(() => Result.Err({ error: 'inner failure' }).unwrapOrThrow('outer failure', true))
            .toThrowError(expect.objectContaining({ cause: 'inner failure' }));
    });
});
