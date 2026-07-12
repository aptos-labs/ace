// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { network as aceNetwork } from '@aptos-labs/ace-sdk';

const MAX_NOTE_BYTES = 256;

type PrimitiveInfo = {
    id: number;
    usage: bigint;
    groupScheme: number;
    label: string;
};

const PRIMITIVES: PrimitiveInfo[] = [
    {
        id: aceNetwork.PRIMITIVE_BLS12381_G1_TEST_ONLY,
        usage: aceNetwork.USAGE_BLS12381_G1_TEST_ONLY,
        groupScheme: 0,
        label: 'BLS12381 G1 test-only',
    },
    {
        id: aceNetwork.PRIMITIVE_BLS12381_G2_TEST_ONLY,
        usage: aceNetwork.USAGE_BLS12381_G2_TEST_ONLY,
        groupScheme: 1,
        label: 'BLS12381 G2 test-only',
    },
    {
        id: aceNetwork.PRIMITIVE_BLS12381_THRESHOLD_VRF,
        usage: aceNetwork.USAGE_BLS12381_THRESHOLD_VRF,
        groupScheme: 1,
        label: 'BLS12381 threshold VRF',
    },
];

function primitiveInfo(id: number): PrimitiveInfo | undefined {
    return PRIMITIVES.find(p => p.id === id);
}

function groupLabel(groupScheme: number): string {
    if (groupScheme === 0) return 'BLS12-381 G1';
    if (groupScheme === 1) return 'BLS12-381 G2';
    return `unknown group ${groupScheme}`;
}

function parsePrimitiveId(raw: unknown, field: string): number {
    if (typeof raw !== 'number') throw new Error(`${field}: expected a primitive id number, got ${typeof raw}`);
    if (!Number.isInteger(raw) || raw < 0 || raw > 255) throw new Error(`${field}: must be an integer 0-255`);
    if (!primitiveInfo(raw)) throw new Error(`${field}: unsupported ACE primitive ${raw}`);
    return raw;
}

function noteBytes(note: string): number {
    return Buffer.byteLength(note, 'utf8');
}

export function primitiveCatalogLines(): string[] {
    return PRIMITIVES.map(p => `#   ${p.id} = ${p.label} (${groupLabel(p.groupScheme)})`);
}

export function primitiveLabel(id: number): string {
    const info = primitiveInfo(id);
    return info ? `${info.id}:${info.label}` : `${id}:unknown primitive`;
}

export function usagePrimitiveIds(expectedUsage: bigint): number[] {
    return PRIMITIVES
        .filter(p => (expectedUsage & p.usage) !== 0n)
        .map(p => p.id);
}

export function usageLabel(expectedUsage: bigint): string {
    const ids = usagePrimitiveIds(expectedUsage);
    const primitiveText = ids.length > 0
        ? ids.map(primitiveLabel).join(', ')
        : `unknown usage mask ${expectedUsage}`;
    const unknownBits = expectedUsage & ~PRIMITIVES.reduce((mask, p) => mask | p.usage, 0n);
    const knownGroups = new Set(
        ids
            .map(id => primitiveInfo(id)?.groupScheme)
            .filter((group): group is number => group !== undefined),
    );
    const groupText = knownGroups.size === 1 && unknownBits === 0n
        ? groupLabel([...knownGroups][0]!)
        : 'unknown/mixed group';
    const suffix = unknownBits === 0n ? '' : `, unknown bits ${unknownBits}`;
    return `${primitiveText} (${groupText}${suffix})`;
}

export function secretRequestLabel(request: aceNetwork.SecretRequest): string {
    const note = request.note.trim();
    return note
        ? `${usageLabel(request.expectedUsage)}; note: ${note}`
        : usageLabel(request.expectedUsage);
}

export function secretInfoLabel(secret: aceNetwork.SecretInfo): string {
    const note = secret.note.trim();
    const noteText = note ? `; note: ${note}` : '';
    return `${usageLabel(secret.expectedUsage)}${noteText}`;
}

export function secretRequestFromPrimitiveIds(
    primitiveIds: number[],
    note: string,
    field: string,
): aceNetwork.SecretRequest {
    if (primitiveIds.length === 0) throw new Error(`${field}: must include at least one primitive id`);
    if (noteBytes(note) > MAX_NOTE_BYTES)
        throw new Error(`${field}.note: exceeds ${MAX_NOTE_BYTES} UTF-8 bytes (got ${noteBytes(note)})`);

    let expectedUsage = 0n;
    let groupScheme: number | undefined;
    const seen = new Set<number>();
    for (const primitiveId of primitiveIds) {
        const info = primitiveInfo(primitiveId);
        if (!info) throw new Error(`${field}: unsupported ACE primitive ${primitiveId}`);
        if (seen.has(primitiveId)) throw new Error(`${field}: duplicate primitive ${primitiveId}`);
        seen.add(primitiveId);
        expectedUsage |= aceNetwork.usageForPrimitive(primitiveId);
        if (groupScheme === undefined) {
            groupScheme = info.groupScheme;
        } else if (groupScheme !== info.groupScheme) {
            throw new Error(`${field}: primitives [${primitiveIds.join(', ')}] span multiple DKG groups`);
        }
    }

    return new aceNetwork.SecretRequest(expectedUsage, note);
}

export function parseSecretRequestSpec(raw: unknown, field: string): aceNetwork.SecretRequest {
    if (typeof raw === 'number') {
        return secretRequestFromPrimitiveIds([parsePrimitiveId(raw, field)], '', field);
    }

    if (Array.isArray(raw)) {
        return secretRequestFromPrimitiveIds(
            raw.map((v, i) => parsePrimitiveId(v, `${field}[${i}]`)),
            '',
            field,
        );
    }

    if (typeof raw === 'object' && raw !== null) {
        const obj = raw as Record<string, unknown>;
        const keys = Object.keys(obj);
        for (const key of keys) {
            if (key !== 'primitive' && key !== 'primitives' && key !== 'note') {
                throw new Error(`${field}: unknown field "${key}"`);
            }
        }
        if ('primitive' in obj && 'primitives' in obj)
            throw new Error(`${field}: use either primitive or primitives, not both`);

        const rawPrimitives = 'primitives' in obj ? obj.primitives : obj.primitive;
        const primitiveIds = Array.isArray(rawPrimitives)
            ? rawPrimitives.map((v, i) => parsePrimitiveId(v, `${field}.primitives[${i}]`))
            : [parsePrimitiveId(rawPrimitives, `${field}.primitive`)];

        const rawNote = obj.note ?? '';
        if (typeof rawNote !== 'string') throw new Error(`${field}.note: expected a string, got ${typeof rawNote}`);
        return secretRequestFromPrimitiveIds(primitiveIds, rawNote, field);
    }

    throw new Error(`${field}: expected a primitive id, primitive id array, or request object`);
}
