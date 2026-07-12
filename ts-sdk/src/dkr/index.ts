// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { AccountAddress, Deserializer } from "@aptos-labs/ts-sdk";
import { Result } from "../result";
import { PcsPublicParams, PublicPoint } from "../vss/index";
import { Scalar } from "../group";

const STATE_DONE = 4;

export class Session {
    constructor(
        readonly caller: AccountAddress,
        readonly originalSession: AccountAddress,
        readonly previousSession: AccountAddress,
        readonly expectedUsage: bigint,
        readonly note: string,
        readonly currentNodes: AccountAddress[],
        readonly currentThreshold: number,
        readonly newNodes: AccountAddress[],
        readonly newThreshold: number,
        readonly pcsContext: PcsPublicParams,
        readonly srcPcsContext: PcsPublicParams,
        readonly srcCommitmentPoints: PublicPoint[],
        readonly srcPublicKeys: PublicPoint[],
        readonly stateCode: number,
        readonly vssSessions: AccountAddress[],
        readonly vssContributionFlags: boolean[],
        readonly commitmentPoints: PublicPoint[],
        readonly publicKeys: PublicPoint[],
    ) {}

    isCompleted(): boolean {
        return this.stateCode === STATE_DONE;
    }

    get resultCommitment(): PublicPoint {
        const point = this.commitmentPoints[0];
        if (!point) throw new Error('DKR result commitment is not available yet');
        return point;
    }

    get shareCommitments(): PublicPoint[] {
        return this.commitmentPoints.slice(1);
    }

    get publicBaseElement(): PublicPoint {
        return this.pcsContext.generatorG;
    }

    get basePoint(): PublicPoint {
        return this.publicBaseElement;
    }

    get secretlyScaledElement(): PublicPoint {
        const point = this.publicKeys[0];
        if (!point) throw new Error('DKR result public key is not available yet');
        return point;
    }

    get resultPk(): PublicPoint {
        return this.secretlyScaledElement;
    }

    get sharePks(): PublicPoint[] {
        return this.publicKeys.slice(1);
    }

    static deserialize(deserializer: Deserializer): Result<Session> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const caller = AccountAddress.deserialize(deserializer);

                const originalSession = AccountAddress.deserialize(deserializer);
                const previousSession = AccountAddress.deserialize(deserializer);
                const expectedUsage = deserializer.deserializeU64();
                const note = deserializer.deserializeStr();

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

                const pcsContext = PcsPublicParams.deserialize(deserializer)
                    .unwrapOrThrow('pcsContext deserialize failed');

                const srcPcsContext = PcsPublicParams.deserialize(deserializer)
                    .unwrapOrThrow('srcPcsContext deserialize failed');

                const srcCommitmentPointsLen = deserializer.deserializeUleb128AsU32();
                const srcCommitmentPoints: PublicPoint[] = [];
                for (let i = 0; i < srcCommitmentPointsLen; i++) {
                    srcCommitmentPoints.push(PublicPoint.deserialize(deserializer).unwrapOrThrow(`srcCommitmentPoints[${i}] deserialize failed`));
                }

                const srcPublicKeysLen = deserializer.deserializeUleb128AsU32();
                const srcPublicKeys: PublicPoint[] = [];
                for (let i = 0; i < srcPublicKeysLen; i++) {
                    srcPublicKeys.push(PublicPoint.deserialize(deserializer).unwrapOrThrow(`srcPublicKeys[${i}] deserialize failed`));
                }

                const stateCode = deserializer.deserializeU8();

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

                return new Session(
                    caller,
                    originalSession,
                    previousSession,
                    expectedUsage,
                    note,
                    currentNodes,
                    currentThreshold,
                    newNodes,
                    newThreshold,
                    pcsContext,
                    srcPcsContext,
                    srcCommitmentPoints,
                    srcPublicKeys,
                    stateCode,
                    vssSessions,
                    vssContributionFlags,
                    commitmentPoints,
                    publicKeys,
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
