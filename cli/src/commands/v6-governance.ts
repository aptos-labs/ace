// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/** Pure v6 governance payload encoding. These commands never sign or submit. */
import { readFileSync } from 'fs';
import { AccountAddress, Serializer } from '@aptos-labs/ts-sdk';

type ObjectMap = Record<string, unknown>;

function asObject(value: unknown, name: string): ObjectMap {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) {
        throw new Error(`${name} must be an object`);
    }
    return value as ObjectMap;
}

function asArray(value: unknown, name: string): unknown[] {
    if (!Array.isArray(value)) throw new Error(`${name} must be an array`);
    return value;
}

function asString(value: unknown, name: string): string {
    if (typeof value !== 'string') throw new Error(`${name} must be a string`);
    return value;
}

function asU64(value: unknown, name: string): bigint {
    if (typeof value === 'number' && !Number.isSafeInteger(value)) {
        throw new Error(`${name} must be a safe integer or decimal string`);
    }
    const raw = typeof value === 'number' || typeof value === 'string' ? String(value) : '';
    if (!/^\d+$/.test(raw)) throw new Error(`${name} must be an unsigned decimal integer`);
    const parsed = BigInt(raw);
    if (parsed >= (1n << 64n)) throw new Error(`${name} exceeds u64`);
    return parsed;
}

function asAddress(value: unknown, name: string): AccountAddress {
    try {
        return AccountAddress.fromString(asString(value, name));
    } catch {
        throw new Error(`${name} must be an Aptos address`);
    }
}

function asHexBytes(value: unknown, name: string): Uint8Array {
    const raw = asString(value, name).replace(/^0x/, '');
    if (raw.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(raw)) throw new Error(`${name} must be even-length hex`);
    return Uint8Array.from(Buffer.from(raw, 'hex'));
}

function serializeAddresses(ser: Serializer, value: unknown, name: string): AccountAddress[] {
    const addresses = asArray(value, name).map((v, i) => asAddress(v, `${name}[${i}]`));
    ser.serializeU32AsUleb128(addresses.length);
    for (const address of addresses) ser.serialize(address);
    return addresses;
}

function serializeSecretRequests(ser: Serializer, value: unknown): void {
    const requests = asArray(value, 'new_secrets');
    ser.serializeU32AsUleb128(requests.length);
    for (const [i, raw] of requests.entries()) {
        const request = asObject(raw, `new_secrets[${i}]`);
        const usage = asU64(request.expected_usage, `new_secrets[${i}].expected_usage`);
        if (usage === 0n || usage > 15n || (usage & 1n) !== 0n && (usage & 14n) !== 0n) {
            throw new Error(`new_secrets[${i}].expected_usage has unsupported or mixed-group bits`);
        }
        const note = asString(request.note, `new_secrets[${i}].note`);
        if (Buffer.byteLength(note, 'utf8') > 256) throw new Error(`new_secrets[${i}].note exceeds 256 UTF-8 bytes`);
        ser.serializeU64(usage);
        ser.serializeStr(note);
    }
}

function serializeFeatures(ser: Serializer, value: unknown, name: string): void {
    const values = asArray(value, name).map((v, i) => asU64(v, `${name}[${i}]`));
    if (new Set(values).size !== values.length || values.some(v => v >= 64n)) {
        throw new Error(`${name} must contain distinct feature IDs in [0, 63]`);
    }
    ser.serializeU32AsUleb128(values.length);
    for (const value of values) ser.serializeU64(value);
}

function validateCommittee(nodes: AccountAddress[], threshold: bigint): void {
    const strings = nodes.map(n => n.toStringLong());
    if (new Set(strings).size !== strings.length) throw new Error('nodes must be unique');
    if (threshold < 2n || threshold > BigInt(nodes.length) || 2n * threshold <= BigInt(nodes.length)) {
        throw new Error('threshold must be at least 2, a strict majority, and at most node count');
    }
}

/** Exact BCS order of ace::network::ProposedEpochConfig. */
export function serializeV6EpochConfig(doc: ObjectMap): Uint8Array {
    const ser = new Serializer();
    const nodes = serializeAddresses(ser, doc.nodes, 'nodes');
    const threshold = asU64(doc.threshold, 'threshold');
    validateCommittee(nodes, threshold);
    ser.serializeU64(threshold);
    const duration = asU64(doc.epoch_duration_micros, 'epoch_duration_micros');
    if (duration < 30_000_000n) throw new Error('epoch_duration_micros must be at least 30 seconds');
    ser.serializeU64(duration);
    const retained = serializeAddresses(ser, doc.secrets_to_retain, 'secrets_to_retain');
    if (new Set(retained.map(a => a.toStringLong())).size !== retained.length) {
        throw new Error('secrets_to_retain must contain unique session addresses');
    }
    serializeSecretRequests(ser, doc.new_secrets);
    const description = asString(doc.description, 'description');
    if (Buffer.byteLength(description, 'utf8') > 1024) throw new Error('description exceeds 1024 UTF-8 bytes');
    ser.serializeStr(description);
    ser.serializeU64(asU64(doc.target_epoch, 'target_epoch'));
    ser.serialize(asAddress(doc.next_admin_multisig, 'next_admin_multisig'));
    serializeFeatures(ser, doc.features_to_activate, 'features_to_activate');
    return ser.toUint8Array();
}

function serializeInitialEpochArgs(doc: ObjectMap): Uint8Array[] {
    const nodeSer = new Serializer();
    const nodes = serializeAddresses(nodeSer, doc.nodes, 'nodes');
    const threshold = asU64(doc.threshold, 'threshold');
    validateCommittee(nodes, threshold);
    const thresholdSer = new Serializer();
    thresholdSer.serializeU64(threshold);
    const interval = asU64(doc.resharing_interval_secs, 'resharing_interval_secs');
    if (interval < 30n) throw new Error('resharing_interval_secs must be at least 30');
    const intervalSer = new Serializer();
    intervalSer.serializeU64(interval);
    const requestSer = new Serializer();
    serializeSecretRequests(requestSer, doc.initial_secret_requests ?? []);
    const bytesSer = new Serializer();
    bytesSer.serializeBytes(requestSer.toUint8Array());
    const featuresSer = new Serializer();
    serializeFeatures(featuresSer, doc.initial_features ?? [], 'initial_features');
    return [nodeSer, thresholdSer, intervalSer, bytesSer, featuresSer].map(s => s.toUint8Array());
}

function packageArgs(doc: ObjectMap): Uint8Array[] {
    const metadata = asHexBytes(doc.metadata_hex, 'metadata_hex');
    const rawModules = asArray(doc.modules_hex, 'modules_hex');
    if (!metadata.length || !rawModules.length) throw new Error('package metadata and modules are required');
    const modules = rawModules.map((m, i) => asHexBytes(m, `modules_hex[${i}]`));
    if (modules.some(m => m.length === 0)) throw new Error('modules must be nonempty');
    const metadataSer = new Serializer();
    metadataSer.serializeBytes(metadata);
    const moduleSer = new Serializer();
    moduleSer.serializeU32AsUleb128(modules.length);
    for (const module of modules) moduleSer.serializeBytes(module);
    return [metadataSer.toUint8Array(), moduleSer.toUint8Array()];
}

/** Native MultisigTransactionPayload::EntryFunction, suitable for create_transaction. */
export function nativeMultisigEntryPayload(
    address: AccountAddress,
    module: string,
    func: string,
    args: Uint8Array[],
): Uint8Array {
    const ser = new Serializer();
    ser.serializeU32AsUleb128(0);
    ser.serialize(address);
    ser.serializeStr(module);
    ser.serializeStr(func);
    ser.serializeU32AsUleb128(0); // Type arguments.
    ser.serializeU32AsUleb128(args.length);
    for (const arg of args) ser.serializeBytes(arg);
    return ser.toUint8Array();
}

export type V6PayloadKind = 'resource-publish' | 'publisher-bootstrap' | 'initial-epoch' | 'epoch-config' | 'publish-upgrade';

export function buildV6GovernancePayload(kind: V6PayloadKind, aceAddress: string | undefined, doc: ObjectMap): Uint8Array {
    const ace = kind === 'resource-publish'
        ? AccountAddress.fromString('0x1')
        : asAddress(aceAddress, '--ace');
    switch (kind) {
        case 'resource-publish': {
            const seed = asHexBytes(doc.seed_hex, 'seed_hex');
            const seedSer = new Serializer();
            seedSer.serializeBytes(seed);
            return nativeMultisigEntryPayload(ace, 'resource_account', 'create_resource_account_and_publish_package', [seedSer.toUint8Array(), ...packageArgs(doc)]);
        }
        case 'publisher-bootstrap':
            return nativeMultisigEntryPayload(ace, 'publisher', 'bootstrap_publish', packageArgs(doc));
        case 'initial-epoch':
            return nativeMultisigEntryPayload(ace, 'network', 'start_initial_epoch', serializeInitialEpochArgs(doc));
        case 'epoch-config': {
            const inner = new Serializer();
            inner.serializeBytes(serializeV6EpochConfig(doc));
            return nativeMultisigEntryPayload(ace, 'network', 'execute_epoch_config', [inner.toUint8Array()]);
        }
        case 'publish-upgrade':
            return nativeMultisigEntryPayload(ace, 'network', 'publish_upgrade', packageArgs(doc));
    }
}

export function v6GovernancePayloadCommand(kind: V6PayloadKind, file: string, aceAddress?: string): void {
    const doc = asObject(JSON.parse(readFileSync(file, 'utf8')) as unknown, file);
    console.log(`0x${Buffer.from(buildV6GovernancePayload(kind, aceAddress, doc)).toString('hex')}`);
}
