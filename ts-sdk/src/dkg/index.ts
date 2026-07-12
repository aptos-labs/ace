// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Distributedly generate a key-pair for OTP-HMAC Boneh-Franklin BLS12-381 (short public key):
 * Each worker use VSS-bls12381-fr to deal a sub-secret to the committee;
 * once t+1 VSS is done, the secret `s` should be finalized as the sum of the t+1 sub-secrets.
 * The DKG's Pedersen PCS generator G is the public base point, and `s`*G is the public key.
 */
export const SCHEME_0 = 0;

/**
 * Distributedly generate a key-pair for OTP-HMAC Boneh-Franklin BLS12-381 (short identity key).
 */
export const SCHEME_1 = 1;

import { AccountAddress, Deserializer } from "@aptos-labs/ts-sdk";
import { Result } from "../result";
import { PcsPublicParams, PublicPoint } from "../vss/index";

const STATE_DONE = 3;

export class Session {
    constructor(
        readonly caller: AccountAddress,
        readonly workers: AccountAddress[],
        readonly threshold: number,
        readonly scheme: number,
        readonly pcsContext: PcsPublicParams,
        readonly expectedUsage: bigint,
        readonly note: string,
        readonly state: number,
        readonly vssSessions: AccountAddress[],
        readonly doneFlags: boolean[],
        readonly commitmentPoints: PublicPoint[],
        readonly publicKeys: PublicPoint[],
    ) {}

    isCompleted(): boolean {
        return this.state === STATE_DONE;
    }

    get resultCommitment(): PublicPoint | undefined {
        return this.commitmentPoints[0];
    }

    get shareCommitments(): PublicPoint[] {
        return this.commitmentPoints.slice(1);
    }

    get basePoint(): PublicPoint {
        return this.pcsContext.generatorG;
    }

    get resultPk(): PublicPoint | undefined {
        return this.publicKeys[0];
    }

    get sharePks(): PublicPoint[] {
        return this.publicKeys.slice(1);
    }

    static deserialize(deserializer: Deserializer): Result<Session> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const caller = AccountAddress.deserialize(deserializer);

                const workersLen = deserializer.deserializeUleb128AsU32();
                const workers: AccountAddress[] = [];
                for (let i = 0; i < workersLen; i++) {
                    workers.push(AccountAddress.deserialize(deserializer));
                }

                const threshold = Number(deserializer.deserializeU64());

                const scheme = deserializer.deserializeU8();

                const pcsContext = PcsPublicParams.deserialize(deserializer)
                    .unwrapOrThrow('pcsContext deserialize failed');

                const expectedUsage = deserializer.deserializeU64();
                const note = deserializer.deserializeStr();

                const state = deserializer.deserializeU8();

                const vssLen = deserializer.deserializeUleb128AsU32();
                const vssSessions: AccountAddress[] = [];
                for (let i = 0; i < vssLen; i++) {
                    vssSessions.push(AccountAddress.deserialize(deserializer));
                }

                const doneFlagsLen = deserializer.deserializeUleb128AsU32();
                const doneFlags: boolean[] = [];
                for (let i = 0; i < doneFlagsLen; i++) doneFlags.push(deserializer.deserializeBool());

                const commitmentPointsLen = deserializer.deserializeUleb128AsU32();
                const commitmentPoints: PublicPoint[] = [];
                for (let i = 0; i < commitmentPointsLen; i++) {
                    commitmentPoints.push(PublicPoint.deserialize(deserializer).unwrapOrThrow(`commitmentPoints[${i}] deserialize failed`));
                }

                const publicKeysLen = deserializer.deserializeUleb128AsU32();
                const publicKeys: PublicPoint[] = [];
                for (let i = 0; i < publicKeysLen; i++) {
                    publicKeys.push(PublicPoint.deserialize(deserializer).unwrapOrThrow(`publicKeys[${i}] deserialize failed`));
                }

                return new Session(caller, workers, threshold, scheme, pcsContext, expectedUsage, note, state, vssSessions, doneFlags, commitmentPoints, publicKeys);
            },
        });
    }

    static fromBytes(bytes: Uint8Array): Result<Session> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const deserializer = new Deserializer(bytes);
                const obj = Session.deserialize(deserializer).unwrapOrThrow('deserialize failed');
                if (deserializer.remaining() !== 0) throw 'trailing bytes';
                return obj;
            },
        });
    }
}

export class PrivateKey {
    scheme: number;
    inner: any;

    constructor(scheme: number, inner: any) {
        this.scheme = scheme;
        this.inner = inner;
    }
}

export class PublicKey {
    scheme: number;
    inner: any;

    constructor(scheme: number, inner: any) {
        this.scheme = scheme;
        this.inner = inner;
    }
}
