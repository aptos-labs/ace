// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * `ace ibe {encrypt, admin-extract, admin-decrypt}` — a small, self-contained
 * t-IBE toolkit for validating a reconstructed master secret (and for the
 * admin/disaster-recovery decrypt path).
 *
 * Validation loop:
 *   1. `ibe encrypt`       — encrypt a test message under (base, mpk) to an identity.
 *   2. `ibe admin-extract` — extract that identity's decryption key from the msk.
 *   3. `ibe admin-decrypt` — decrypt the ciphertext with the extracted key.
 * If step 3 returns the original message, the reconstructed msk is correct.
 *
 * The IBE identity is exactly the `--label` bytes (label-as-identity); encrypt
 * and admin-extract must use the same label. Scheme is BFIBE-BLS12381-ShortSig-AEAD
 * (production). base/mpk are BCS `group::Element` hex (as shown by the discovery
 * service); msk is the 32-byte LE Fr hex printed by `deployment reconstruct-secret`.
 */

import { readFileSync, writeFileSync } from 'fs';

import { group, tibe } from '@aptos-labs/ace-sdk';

import { escInput } from '../esc-select.js';

const G = '\x1b[32m', D = '\x1b[2m', B = '\x1b[1m', R = '\x1b[0m';

function hexToBytes(hex: string): Uint8Array {
    return new Uint8Array(Buffer.from(hex.trim().replace(/^0x/i, ''), 'hex'));
}
function bytesToHex(b: Uint8Array): string {
    return Buffer.from(b).toString('hex');
}
function leBytesToBigInt(b: Uint8Array): bigint {
    let x = 0n;
    for (let i = b.length - 1; i >= 0; i--) x = (x << 8n) | BigInt(b[i]!);
    return x;
}

/**
 * Resolve an input to raw bytes from, in order: `--x-path` (raw file bytes),
 * `--x-hex`, `--x` (string form), else an interactive prompt. `interactiveAs`
 * decides how a typed answer is interpreted.
 */
async function resolveBytes(spec: {
    label: string;
    str?: string;
    hex?: string;
    path?: string;
    interactiveAs: 'hex' | 'string';
    promptHint?: string;
}): Promise<Uint8Array> {
    if (spec.path !== undefined) return new Uint8Array(readFileSync(spec.path));
    if (spec.hex !== undefined) return hexToBytes(spec.hex);
    if (spec.str !== undefined) return new TextEncoder().encode(spec.str);
    const hint = spec.promptHint ? ` ${D}(${spec.promptHint})${R}` : '';
    const kind = spec.interactiveAs === 'hex' ? 'hex' : 'text';
    const answer = await escInput({ message: `Enter ${spec.label} [${kind}]${hint}` });
    if (answer === undefined) throw new Error(`${spec.label}: cancelled`);
    return spec.interactiveAs === 'hex'
        ? hexToBytes(answer)
        : new TextEncoder().encode(answer);
}

/** Write to `outPath` as raw bytes, else print to stdout (`hex` or decoded `utf8`). */
function emit(bytes: Uint8Array, outPath: string | undefined, stdoutMode: 'hex' | 'utf8'): void {
    if (outPath) {
        writeFileSync(outPath, Buffer.from(bytes));
        console.log(`${G}✔${R} wrote ${bytes.length} bytes to ${outPath}`);
        return;
    }
    if (stdoutMode === 'utf8') console.log(new TextDecoder().decode(bytes));
    else console.log('0x' + bytesToHex(bytes));
}

const SCHEME = tibe.SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD;

export async function ibeEncryptCommand(opts: {
    baseHex?: string; basePath?: string;
    mpkHex?: string; mpkPath?: string;
    label?: string; labelHex?: string; labelPath?: string;
    msg?: string; msgHex?: string; msgPath?: string;
    outPath?: string;
}): Promise<void> {
    const baseBytes = await resolveBytes({ label: 'base point', hex: opts.baseHex, path: opts.basePath, interactiveAs: 'hex', promptHint: 'BCS group element hex; see the discovery service' });
    const mpkBytes = await resolveBytes({ label: 'master public key', hex: opts.mpkHex, path: opts.mpkPath, interactiveAs: 'hex', promptHint: 'BCS group element hex; see the discovery service' });
    const id = await resolveBytes({ label: 'label (identity)', str: opts.label, hex: opts.labelHex, path: opts.labelPath, interactiveAs: 'string' });
    const message = await resolveBytes({ label: 'message', str: opts.msg, hex: opts.msgHex, path: opts.msgPath, interactiveAs: 'string' });

    const base = group.Element.fromBytes(baseBytes).unwrapOrThrow('parse --base as a BCS group element');
    const pk = group.Element.fromBytes(mpkBytes).unwrapOrThrow('parse --mpk as a BCS group element');
    const mpk = tibe.MasterPublicKey.fromGroupElements(SCHEME, base, pk)
        .unwrapOrThrow('build master public key (base/mpk must be G2 for shortsig-aead)');

    const ct = tibe.encrypt({ mpk, id, plaintext: message }).unwrapOrThrow('ibe encrypt');
    emit(ct.toBytes(), opts.outPath, 'hex');
}

export async function ibeAdminExtractCommand(opts: {
    mskHex?: string; mskPath?: string;
    label?: string; labelHex?: string; labelPath?: string;
    outPath?: string;
}): Promise<void> {
    const mskBytes = await resolveBytes({ label: 'master secret', hex: opts.mskHex, path: opts.mskPath, interactiveAs: 'hex', promptHint: '32-byte LE Fr hex from `deployment reconstruct-secret`' });
    const id = await resolveBytes({ label: 'label (identity)', str: opts.label, hex: opts.labelHex, path: opts.labelPath, interactiveAs: 'string' });

    if (mskBytes.length !== 32) throw new Error(`master secret must be 32 bytes (LE Fr), got ${mskBytes.length}`);
    const mskScalar = leBytesToBigInt(mskBytes);

    const idk = tibe.extract({ scheme: SCHEME, mskScalar, id }).unwrapOrThrow('ibe admin-extract');
    emit(idk.toBytes(), opts.outPath, 'hex');
}

export async function ibeAdminDecryptCommand(opts: {
    idkHex?: string; idkPath?: string;
    ciphertextHex?: string; ciphertextPath?: string;
    outPath?: string;
}): Promise<void> {
    const idkBytes = await resolveBytes({ label: 'identity decryption key', hex: opts.idkHex, path: opts.idkPath, interactiveAs: 'hex', promptHint: 'output of `ibe admin-extract`' });
    const ctBytes = await resolveBytes({ label: 'ciphertext', hex: opts.ciphertextHex, path: opts.ciphertextPath, interactiveAs: 'hex', promptHint: 'output of `ibe encrypt`' });

    const idk = tibe.IdentityDecryptionKeyShare.fromBytes(idkBytes).unwrapOrThrow('parse --idk');
    const ct = tibe.Ciphertext.fromBytes(ctBytes).unwrapOrThrow('parse --ciphertext');
    const plaintext = tibe.decrypt({ idkShares: [idk], ciphertext: ct })
        .unwrapOrThrow('ibe admin-decrypt (wrong key/ciphertext ⇒ AEAD tag mismatch)');
    emit(plaintext, opts.outPath, 'utf8');
}
