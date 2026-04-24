// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { AccountAddress, Deserializer } from "@aptos-labs/ts-sdk";
import { Result } from "../result";

export type ProposalVariant =
    | { kind: 'CommitteeChange'; nodes: AccountAddress[]; threshold: number }
    | { kind: 'ResharingIntervalUpdate'; newIntervalSecs: bigint }
    | { kind: 'NewSecret'; scheme: number }
    | { kind: 'SecretDeactivation'; originalDkgAddr: AccountAddress };

export class ProposalState {
    constructor(
        readonly epoch: number,
        readonly proposer: AccountAddress,
        readonly proposal: ProposalVariant,
        readonly voters: AccountAddress[],
        readonly executed: boolean,
    ) {}

    static deserialize(deserializer: Deserializer): Result<ProposalState> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const epoch = Number(deserializer.deserializeU64());
                const proposer = AccountAddress.deserialize(deserializer);

                const variant = deserializer.deserializeUleb128AsU32();
                let proposal: ProposalVariant;
                switch (variant) {
                    case 0: {
                        const len = deserializer.deserializeUleb128AsU32();
                        const nodes: AccountAddress[] = [];
                        for (let i = 0; i < len; i++) nodes.push(AccountAddress.deserialize(deserializer));
                        const threshold = Number(deserializer.deserializeU64());
                        proposal = { kind: 'CommitteeChange', nodes, threshold };
                        break;
                    }
                    case 1: {
                        const newIntervalSecs = deserializer.deserializeU64();
                        proposal = { kind: 'ResharingIntervalUpdate', newIntervalSecs };
                        break;
                    }
                    case 2: {
                        const scheme = deserializer.deserializeU8();
                        proposal = { kind: 'NewSecret', scheme };
                        break;
                    }
                    case 3: {
                        const originalDkgAddr = AccountAddress.deserialize(deserializer);
                        proposal = { kind: 'SecretDeactivation', originalDkgAddr };
                        break;
                    }
                    default:
                        throw `Unknown Proposal variant: ${variant}`;
                }

                const votersLen = deserializer.deserializeUleb128AsU32();
                const voters: AccountAddress[] = [];
                for (let i = 0; i < votersLen; i++) voters.push(AccountAddress.deserialize(deserializer));

                const executed = deserializer.deserializeBool();
                return new ProposalState(epoch, proposer, proposal, voters, executed);
            },
        });
    }

    static fromBytes(bytes: Uint8Array): Result<ProposalState> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const deserializer = new Deserializer(bytes);
                const obj = ProposalState.deserialize(deserializer).unwrapOrThrow('deserialize failed');
                if (deserializer.remaining() !== 0) throw 'trailing bytes';
                return obj;
            },
        });
    }
}

/** Mirrors `ace::network::EpochChangeInfo`. */
export class EpochChangeInfo {
    constructor(
        readonly nxtNodes: AccountAddress[],
        readonly session: AccountAddress,
    ) {}

    static deserialize(deserializer: Deserializer): EpochChangeInfo {
        const nxtNodesLen = deserializer.deserializeUleb128AsU32();
        const nxtNodes: AccountAddress[] = [];
        for (let i = 0; i < nxtNodesLen; i++) {
            nxtNodes.push(AccountAddress.deserialize(deserializer));
        }
        const session = AccountAddress.deserialize(deserializer);
        return new EpochChangeInfo(nxtNodes, session);
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
        readonly epochChangeInfo: EpochChangeInfo | null,
    ) {}

    isEpochChanging(): boolean {
        return this.epochChangeInfo !== null;
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

                // Option<EpochChangeInfo>: 0x00 = None, 0x01 + payload = Some
                const optionTag = deserializer.deserializeU8();
                let epochChangeInfo: EpochChangeInfo | null = null;
                if (optionTag === 1) {
                    epochChangeInfo = EpochChangeInfo.deserialize(deserializer);
                } else if (optionTag !== 0) {
                    throw `epoch_change_info option tag must be 0 or 1, got ${optionTag}`;
                }

                return new State(
                    epoch,
                    epochStartTimeMicros,
                    epochDurationMicros,
                    curNodes,
                    curThreshold,
                    secrets,
                    pendingProposals,
                    epochChangeInfo,
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
