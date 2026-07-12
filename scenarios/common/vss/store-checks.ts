// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { AccountAddress, Deserializer } from '@aptos-labs/ts-sdk';
import * as ace from '@aptos-labs/ace-sdk';
import { execFileSync } from 'child_process';
import * as path from 'path';

import { findPostgresBinDir } from '../postgres';

export function assertVSSHolderShareRows(opts: {
    storeUrls: string[];
    sessionAddr: AccountAddress;
    expectedRows: number;
}): void {
    const holderShareCounts = opts.storeUrls.map(storeUrl =>
        countVSSHolderSharesInStore({ vssStoreUrl: storeUrl, sessionAddr: opts.sessionAddr }),
    );
    holderShareCounts.forEach((count, i) => {
        if (count !== 1) {
            throw `expected exactly 1 holder share in store ${i}, got ${count}`;
        }
    });
    const totalHolderShareRows = holderShareCounts.reduce((acc, count) => acc + count, 0);
    if (totalHolderShareRows !== opts.expectedRows) {
        throw `expected ${opts.expectedRows} holder DB share rows, got ${totalHolderShareRows}`;
    }
}

export async function assertVSSSecretReconstruction(opts: {
    storeUrls: string[];
    sessionAddr: AccountAddress;
    threshold: number;
    scheme: number;
    expectedDealerSecret?: ace.vss.PrivateScalar;
    label?: string;
}): Promise<void> {
    const shares = await Promise.all(
        opts.storeUrls.slice(0, opts.threshold).map(async (storeUrl, i) => {
            const openingBytes = readVSSHolderShareFromStore({
                vssStoreUrl: storeUrl,
                sessionAddr: opts.sessionAddr,
                holderIndex: i,
            });
            const msg = ace.vss.PrivateShareMessage.fromBytes(openingBytes)
                .unwrapOrThrow('Failed to parse private share opening.');
            if (msg.share.scheme !== opts.scheme) {
                throw `expected share scheme = ${opts.scheme}, got ${msg.share.scheme}`;
            }
            return msg.share;
        }),
    );

    const reconstructedSecret = ace.vss.reconstruct({
        indexedShares: shares.map((share, i) => ({ index: i + 1, share })),
    }).unwrapOrThrow('Failed to reconstruct secret from holder shares.');
    if (reconstructedSecret.scheme !== opts.scheme) {
        throw `expected reconstructed scheme = ${opts.scheme}, got ${reconstructedSecret.scheme}`;
    }

    const dealerSecret = readVSSDealerSecretFromStore({
        vssStoreUrl: opts.storeUrls[0],
        sessionAddr: opts.sessionAddr,
        scheme: opts.scheme,
    });
    if (reconstructedSecret.toHex() !== dealerSecret.toHex()) {
        throw 'reconstructed VSS secret does not match dealer state poly_s[0]';
    }
    if (opts.expectedDealerSecret !== undefined && dealerSecret.toHex() !== opts.expectedDealerSecret.toHex()) {
        throw 'dealer state poly_s[0] does not match previous commitment secret override';
    }
    const suffix = opts.label === undefined ? '' : `, ${opts.label}`;
    console.log(`Reconstructed VSS secret scalar (${shares.length} shares${suffix}).`);
}

export function assertVSSPublicKeys(opts: {
    storeUrls: string[];
    sessionAddr: AccountAddress;
    session: ace.vss.Session;
    scheme: number;
}): void {
    const expectedLen = opts.storeUrls.length + 1;
    if (opts.session.publicKeys.length !== expectedLen) {
        throw `expected ${expectedLen} VSS public keys, got ${opts.session.publicKeys.length}`;
    }
    const dealerSecret = readVSSDealerSecretFromStore({
        vssStoreUrl: opts.storeUrls[0],
        sessionAddr: opts.sessionAddr,
        scheme: opts.scheme,
    });
    const expectedResultPk = opts.session.basePoint.scale(dealerSecret);
    if (!expectedResultPk.equals(opts.session.resultPk!)) {
        throw 'VSS result PK does not match dealer state poly_s[0]';
    }

    opts.storeUrls.forEach((storeUrl, holderIndex) => {
        const openingBytes = readVSSHolderShareFromStore({
            vssStoreUrl: storeUrl,
            sessionAddr: opts.sessionAddr,
            holderIndex,
        });
        const opening = ace.vss.PrivateShareMessage.fromBytes(openingBytes)
            .unwrapOrThrow(`Failed to parse holder ${holderIndex} private share opening.`)
            .opening;
        const expectedSharePk = opts.session.basePoint.scale(opening.evalValueP);
        if (!expectedSharePk.equals(opts.session.sharePks[holderIndex])) {
            throw `VSS share PK does not match holder ${holderIndex} DB opening`;
        }
    });
}

export function readVSSHolderShareFromStore(opts: {
    vssStoreUrl: string;
    sessionAddr: AccountAddress | string;
    holderIndex: number;
}): Uint8Array {
    const session = typeof opts.sessionAddr === 'string'
        ? AccountAddress.fromString(opts.sessionAddr).toStringLong()
        : opts.sessionAddr.toStringLong();
    const hex = opts.vssStoreUrl.startsWith('postgres://')
        ? queryPostgresHolderShare(opts.vssStoreUrl, session, opts.holderIndex)
        : querySqliteHolderShare(sqlitePathFromUrl(opts.vssStoreUrl), session, opts.holderIndex);
    if (hex.length === 0) {
        throw new Error(`No holder share in ${opts.vssStoreUrl} for ${session} holder ${opts.holderIndex}`);
    }
    return new Uint8Array(Buffer.from(hex, 'hex'));
}

function readVSSDealerSecretFromStore(opts: {
    vssStoreUrl: string;
    sessionAddr: AccountAddress | string;
    scheme: number;
}): ace.vss.PrivateScalar {
    const session = typeof opts.sessionAddr === 'string'
        ? AccountAddress.fromString(opts.sessionAddr).toStringLong()
        : opts.sessionAddr.toStringLong();
    const hex = opts.vssStoreUrl.startsWith('postgres://')
        ? queryPostgresDealerState(opts.vssStoreUrl, session)
        : querySqliteDealerState(sqlitePathFromUrl(opts.vssStoreUrl), session);
    if (hex.length === 0) {
        throw new Error(`No dealer state in ${opts.vssStoreUrl} for ${session}`);
    }
    const coefs = decodeDealerStatePolyS(new Uint8Array(Buffer.from(hex, 'hex')));
    if (coefs.length === 0) {
        throw new Error(`dealer state poly_s is empty in ${opts.vssStoreUrl} for ${session}`);
    }
    return ace.vss.PrivateScalar.fromBytes(wrapRawFrAsScalarBytes(opts.scheme, coefs[0]))
        .unwrapOrThrow('Failed to parse dealer state poly_s[0].');
}

function countVSSHolderSharesInStore(opts: {
    vssStoreUrl: string;
    sessionAddr: AccountAddress | string;
}): number {
    const session = typeof opts.sessionAddr === 'string'
        ? AccountAddress.fromString(opts.sessionAddr).toStringLong()
        : opts.sessionAddr.toStringLong();
    const out = opts.vssStoreUrl.startsWith('postgres://')
        ? queryPostgresHolderShareCount(opts.vssStoreUrl, session)
        : querySqliteHolderShareCount(sqlitePathFromUrl(opts.vssStoreUrl), session);
    const count = Number(out);
    if (!Number.isSafeInteger(count)) {
        throw new Error(`Invalid holder share count ${JSON.stringify(out)} from ${opts.vssStoreUrl}`);
    }
    return count;
}

function querySqliteHolderShare(dbPath: string, session: string, holderIndex: number): string {
    return execFileSync('sqlite3', [
        dbPath,
        `select hex(share_bcs) from vss_holder_shares where session_addr = '${session}' and holder_index = ${holderIndex};`,
    ], { encoding: 'utf8' }).trim().toLowerCase();
}

function querySqliteHolderShareCount(dbPath: string, session: string): string {
    return execFileSync('sqlite3', [
        dbPath,
        `select count(*) from vss_holder_shares where session_addr = '${session}';`,
    ], { encoding: 'utf8' }).trim();
}

function querySqliteDealerState(dbPath: string, session: string): string {
    return execFileSync('sqlite3', [
        dbPath,
        `select hex(state_bytes) from vss_dealer_states where session_addr = '${session}';`,
    ], { encoding: 'utf8' }).trim().toLowerCase();
}

function queryPostgresHolderShare(storeUrl: string, session: string, holderIndex: number): string {
    return execFileSync(path.join(findPostgresBinDir(), 'psql'), [
        storeUrl,
        '-At',
        '-c',
        `select encode(share_bcs, 'hex') from vss_holder_shares where session_addr = '${session}' and holder_index = ${holderIndex};`,
    ], { encoding: 'utf8' }).trim().toLowerCase();
}

function queryPostgresHolderShareCount(storeUrl: string, session: string): string {
    return execFileSync(path.join(findPostgresBinDir(), 'psql'), [
        storeUrl,
        '-At',
        '-c',
        `select count(*) from vss_holder_shares where session_addr = '${session}';`,
    ], { encoding: 'utf8' }).trim();
}

function queryPostgresDealerState(storeUrl: string, session: string): string {
    return execFileSync(path.join(findPostgresBinDir(), 'psql'), [
        storeUrl,
        '-At',
        '-c',
        `select encode(state_bytes, 'hex') from vss_dealer_states where session_addr = '${session}';`,
    ], { encoding: 'utf8' }).trim().toLowerCase();
}

function decodeDealerStatePolyS(bytes: Uint8Array): Uint8Array[] {
    const deserializer = new Deserializer(bytes);
    const version = deserializer.deserializeU8();
    if (version !== 1) {
        throw new Error(`unsupported dealer state version ${version}`);
    }
    const coefs = decodeRawFrPolynomial(deserializer);
    decodeRawFrPolynomial(deserializer);
    if (deserializer.remaining() !== 0) {
        throw new Error('trailing bytes after dealer state');
    }
    return coefs;
}

function decodeRawFrPolynomial(deserializer: Deserializer): Uint8Array[] {
    const len = deserializer.deserializeUleb128AsU32();
    const coefs: Uint8Array[] = [];
    for (let i = 0; i < len; i++) {
        const coef = deserializer.deserializeBytes();
        if (coef.length !== 32) {
            throw new Error(`dealer polynomial coefficient ${i} must be 32 bytes, got ${coef.length}`);
        }
        coefs.push(coef);
    }
    return coefs;
}

function wrapRawFrAsScalarBytes(scheme: number, rawFrLe32: Uint8Array): Uint8Array {
    if (rawFrLe32.length !== 32) {
        throw new Error(`raw scalar must be 32 bytes, got ${rawFrLe32.length}`);
    }
    return new Uint8Array([scheme, 32, ...rawFrLe32]);
}

function sqlitePathFromUrl(storeUrl: string): string {
    if (storeUrl.startsWith('sqlite://')) {
        const dbPath = storeUrl.slice('sqlite://'.length);
        if (dbPath.length > 0) return dbPath;
    }
    if (storeUrl.startsWith('sqlite:')) {
        const dbPath = storeUrl.slice('sqlite:'.length);
        if (dbPath.length > 0) return dbPath;
    }
    throw new Error(`Unsupported VSS store URL for scenario DB query: ${storeUrl}`);
}
