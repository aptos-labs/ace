// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { AccountAddress, Deserializer } from "@aptos-labs/ts-sdk";
import { Result } from "../result";

export class EpochChangeState {
    constructor(
        readonly nxtNodes: AccountAddress[],
        readonly nxtThreshold: number,
        readonly nxtEpochDurationMicros: bigint,
        readonly dkgSession: AccountAddress | null,
        readonly dkrSessions: AccountAddress[],
    ) {}

    static deserialize(deserializer: Deserializer): EpochChangeState {
        const nxtNodesLen = deserializer.deserializeUleb128AsU32();
        const nxtNodes: AccountAddress[] = [];
        for (let i = 0; i < nxtNodesLen; i++) {
            nxtNodes.push(AccountAddress.deserialize(deserializer));
        }

        const nxtThreshold = Number(deserializer.deserializeU64());
        const nxtEpochDurationMicros = deserializer.deserializeU64();

        // Option<address>: 0x00 = None, 0x01 + payload = Some
        const dkgTag = deserializer.deserializeU8();
        let dkgSession: AccountAddress | null = null;
        if (dkgTag === 1) {
            dkgSession = AccountAddress.deserialize(deserializer);
        } else if (dkgTag !== 0) {
            throw `dkg_session option tag must be 0 or 1, got ${dkgTag}`;
        }

        const dkrSessionsLen = deserializer.deserializeUleb128AsU32();
        const dkrSessions: AccountAddress[] = [];
        for (let i = 0; i < dkrSessionsLen; i++) {
            dkrSessions.push(AccountAddress.deserialize(deserializer));
        }

        return new EpochChangeState(nxtNodes, nxtThreshold, nxtEpochDurationMicros, dkgSession, dkrSessions);
    }
}

export class State {
    constructor(
        readonly epoch: number,
        readonly epochStartTimeMicros: bigint,
        readonly epochDurationMicros: bigint,
        readonly curNodes: AccountAddress[],
        readonly curThreshold: number,
        readonly secrets: AccountAddress[],
        readonly pendingProposals: AccountAddress[],
        readonly epochChangeState: EpochChangeState | null,
    ) {}

    isEpochChanging(): boolean {
        return this.epochChangeState !== null;
    }

    static deserialize(deserializer: Deserializer): Result<State> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const epoch = Number(deserializer.deserializeU64());
                const epochStartTimeMicros = deserializer.deserializeU64();
                const epochDurationMicros = deserializer.deserializeU64();

                const curNodesLen = deserializer.deserializeUleb128AsU32();
                const curNodes: AccountAddress[] = [];
                for (let i = 0; i < curNodesLen; i++) {
                    curNodes.push(AccountAddress.deserialize(deserializer));
                }

                const curThreshold = Number(deserializer.deserializeU64());

                const secretsLen = deserializer.deserializeUleb128AsU32();
                const secrets: AccountAddress[] = [];
                for (let i = 0; i < secretsLen; i++) {
                    secrets.push(AccountAddress.deserialize(deserializer));
                }

                const pendingProposalsLen = deserializer.deserializeUleb128AsU32();
                const pendingProposals: AccountAddress[] = [];
                for (let i = 0; i < pendingProposalsLen; i++) {
                    pendingProposals.push(AccountAddress.deserialize(deserializer));
                }

                // Option<EpochChangeState>: 0x00 = None, 0x01 + payload = Some
                const optionTag = deserializer.deserializeU8();
                let epochChangeState: EpochChangeState | null = null;
                if (optionTag === 1) {
                    epochChangeState = EpochChangeState.deserialize(deserializer);
                } else if (optionTag !== 0) {
                    throw `epoch_change_state option tag must be 0 or 1, got ${optionTag}`;
                }

                return new State(
                    epoch,
                    epochStartTimeMicros,
                    epochDurationMicros,
                    curNodes,
                    curThreshold,
                    secrets,
                    pendingProposals,
                    epochChangeState,
                );
            },
        });
    }

    static fromBytes(bytes: Uint8Array): Result<State> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const deserializer = new Deserializer(bytes);
                const obj = State.deserialize(deserializer).unwrapOrThrow('deserialize failed');
                if (deserializer.remaining() !== 0) throw 'trailing bytes';
                return obj;
            },
        });
    }
}
