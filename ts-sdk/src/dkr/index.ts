// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { AccountAddress, Deserializer } from "@aptos-labs/ts-sdk";
import { Result } from "../result";
import { PublicPoint } from "../vss/index";
import { Scalar } from "../group";

const STATE_DONE = 4;

export class Session {
    constructor(
        readonly caller: AccountAddress,
        readonly publicBaseElement: PublicPoint,
        readonly secretlyScaledElement: PublicPoint,
        readonly originalSession: AccountAddress,
        readonly previousSession: AccountAddress,
        readonly currentNodes: AccountAddress[],
        readonly currentThreshold: number,
        readonly newNodes: AccountAddress[],
        readonly newThreshold: number,
        readonly stateCode: number,
        readonly vssSessions: AccountAddress[],
        readonly vssContributionFlags: boolean[],
        readonly sharePks: PublicPoint[],
    ) {}

    isCompleted(): boolean {
        return this.stateCode === STATE_DONE;
    }

    static deserialize(deserializer: Deserializer): Result<Session> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const caller = AccountAddress.deserialize(deserializer);

                const publicBaseElement = PublicPoint.deserialize(deserializer)
                    .unwrapOrThrow('publicBaseElement deserialize failed');

                const secretlyScaledElement = PublicPoint.deserialize(deserializer)
                    .unwrapOrThrow('secretlyScaledElement deserialize failed');

                const originalSession = AccountAddress.deserialize(deserializer);
                const previousSession = AccountAddress.deserialize(deserializer);

                const currentNodesLen = deserializer.deserializeUleb128AsU32();
                const currentNodes: AccountAddress[] = [];
                for (let i = 0; i < currentNodesLen; i++) {
                    currentNodes.push(AccountAddress.deserialize(deserializer));
                }

                const currentThreshold = Number(deserializer.deserializeU64());

                const newNodesLen = deserializer.deserializeUleb128AsU32();
                const newNodes: AccountAddress[] = [];
                for (let i = 0; i < newNodesLen; i++) {
                    newNodes.push(AccountAddress.deserialize(deserializer));
                }

                const newThreshold = Number(deserializer.deserializeU64());

                const stateCode = deserializer.deserializeU8();

                // src_share_pks: internal field for lazy VSS creation; read and discard.
                const srcSharePksLen = deserializer.deserializeUleb128AsU32();
                for (let i = 0; i < srcSharePksLen; i++) {
                    PublicPoint.deserialize(deserializer).unwrapOrThrow(`srcSharePks[${i}] deserialize failed`);
                }

                const vssLen = deserializer.deserializeUleb128AsU32();
                const vssSessions: AccountAddress[] = [];
                for (let i = 0; i < vssLen; i++) {
                    vssSessions.push(AccountAddress.deserialize(deserializer));
                }

                const flagsLen = deserializer.deserializeUleb128AsU32();
                const vssContributionFlags: boolean[] = [];
                for (let i = 0; i < flagsLen; i++) {
                    vssContributionFlags.push(deserializer.deserializeBool());
                }

                const lagrangeLen = deserializer.deserializeUleb128AsU32();
                for (let i = 0; i < lagrangeLen; i++) {
                    Scalar.deserialize(deserializer).unwrapOrThrow(`lagrangeCoeffsAtZero[${i}] deserialize failed`);
                }

                const sharePksLen = deserializer.deserializeUleb128AsU32();
                const sharePks: PublicPoint[] = [];
                for (let i = 0; i < sharePksLen; i++) {
                    sharePks.push(PublicPoint.deserialize(deserializer).unwrapOrThrow(`sharePks[${i}] deserialize failed`));
                }

                return new Session(
                    caller,
                    publicBaseElement,
                    secretlyScaledElement,
                    originalSession,
                    previousSession,
                    currentNodes,
                    currentThreshold,
                    newNodes,
                    newThreshold,
                    stateCode,
                    vssSessions,
                    vssContributionFlags,
                    sharePks,
                );
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
