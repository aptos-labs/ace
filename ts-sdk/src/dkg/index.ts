// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Distributedly generate a key-pair for OTP-HMAC Boneh-Franklin BLS12-381 (short public key):
 * Each worker use VSS-bls12381-fr to deal a sub-secret to the committee;
 * once t+1 VSS is done, the secret `s` should be finalized as the sum of the t+1 sub-secrets.
 * A base point is then publicly sampled (probably in the contract), then `s`*base is the public key.
 */
export const SCHEME_0 = 0;

/**
 * Distributedly generate a key-pair for OTP-HMAC Boneh-Franklin BLS12-381 (short identity key).
 */
export const SCHEME_1 = 1;

import { AccountAddress, Deserializer } from "@aptos-labs/ts-sdk";
import { Result } from "../result";
import { PublicPoint } from "../vss/index";

const STATE_DONE = 3;

export class Session {
    constructor(
        readonly caller: AccountAddress,
        readonly workers: AccountAddress[],
        readonly threshold: number,
        readonly basePoint: PublicPoint,
        readonly state: number,
        readonly vssSessions: AccountAddress[],
        readonly doneFlags: boolean[],
        readonly resultPk: PublicPoint | undefined,
        readonly sharePks: PublicPoint[],
    ) {}

    isCompleted(): boolean {
        return this.state === STATE_DONE;
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

                const basePoint = PublicPoint.deserialize(deserializer)
                    .unwrapOrThrow('basePoint deserialize failed');

                const state = deserializer.deserializeU8();

                const vssLen = deserializer.deserializeUleb128AsU32();
                const vssSessions: AccountAddress[] = [];
                for (let i = 0; i < vssLen; i++) {
                    vssSessions.push(AccountAddress.deserialize(deserializer));
                }

                const doneFlagsLen = deserializer.deserializeUleb128AsU32();
                const doneFlags: boolean[] = [];
                for (let i = 0; i < doneFlagsLen; i++) doneFlags.push(deserializer.deserializeBool());

                // result_pk: Option<PublicPoint> — encoded as vector<PublicPoint> of length 0 or 1
                const resultPkTag = deserializer.deserializeU8();
                let resultPk: PublicPoint | undefined;
                if (resultPkTag === 1) {
                    resultPk = PublicPoint.deserialize(deserializer)
                        .unwrapOrThrow('resultPk deserialize failed');
                } else if (resultPkTag !== 0) {
                    throw `resultPk option tag must be 0 or 1, got ${resultPkTag}`;
                }

                const sharePksLen = deserializer.deserializeUleb128AsU32();
                const sharePks: PublicPoint[] = [];
                for (let i = 0; i < sharePksLen; i++) {
                    sharePks.push(PublicPoint.deserialize(deserializer).unwrapOrThrow(`sharePks[${i}] deserialize failed`));
                }

                return new Session(caller, workers, threshold, basePoint, state, vssSessions, doneFlags, resultPk, sharePks);
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
