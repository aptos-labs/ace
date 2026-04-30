// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { AccountAddress, Deserializer } from "@aptos-labs/ts-sdk";
import { Result } from "../result";

const SCHEME_NAMES: Record<number, string> = {
    0: 'bls12381_g1',
};

export function schemeName(scheme: number): string {
    return SCHEME_NAMES[scheme] ?? `scheme-${scheme}`;
}

/** Mirrors `ace::network::SecretInfo` from `state_view_v0_bcs`. */
export class SecretInfo {
    constructor(
        /** Address of the most recent DKG or DKR session — use this in secrets_to_retain. */
        readonly currentSession: AccountAddress,
        /** Address of the original DKG session that created this secret lineage. */
        readonly keypairId: AccountAddress,
        readonly scheme: number,
    ) {}

    schemeName(): string { return schemeName(this.scheme); }

    static deserialize(deserializer: Deserializer): SecretInfo {
        const currentSession = AccountAddress.deserialize(deserializer);
        const keypairId = AccountAddress.deserialize(deserializer);
        const scheme = deserializer.deserializeU8();
        return new SecretInfo(currentSession, keypairId, scheme);
    }
}

/** Mirrors `ace::network::ProposedEpochConfig`. */
export type ProposedEpochConfig = {
    nodes: AccountAddress[];
    threshold: number;
    epochDurationMicros: bigint;
    secretsToRetain: AccountAddress[];
    newSecrets: number[];
    description: string;
    targetEpoch: number;
};

/** Mirrors `ace::network::ProposalView` from `state_view_v0_bcs`. */
export class ProposalView {
    constructor(
        readonly proposal: ProposedEpochConfig,
        readonly votingSession: AccountAddress,
        /** votes[i] === true iff curNodes[i] has voted. */
        readonly votes: boolean[],
        /** true iff enough votes have been cast to pass. */
        readonly votingPassed: boolean,
    ) {}

    voteCount(): number {
        return this.votes.filter(Boolean).length;
    }

    hasVoted(nodeAddr: string, curNodes: AccountAddress[]): boolean {
        const idx = curNodes.findIndex(n => n.toStringLong() === nodeAddr);
        return idx >= 0 && this.votes[idx] === true;
    }

    static deserialize(deserializer: Deserializer): ProposalView {
        const nodesLen = deserializer.deserializeUleb128AsU32();
        const nodes: AccountAddress[] = [];
        for (let i = 0; i < nodesLen; i++) nodes.push(AccountAddress.deserialize(deserializer));
        const threshold = Number(deserializer.deserializeU64());
        const epochDurationMicros = deserializer.deserializeU64();

        const retainLen = deserializer.deserializeUleb128AsU32();
        const secretsToRetain: AccountAddress[] = [];
        for (let i = 0; i < retainLen; i++) secretsToRetain.push(AccountAddress.deserialize(deserializer));

        const newSecretsLen = deserializer.deserializeUleb128AsU32();
        const newSecrets: number[] = [];
        for (let i = 0; i < newSecretsLen; i++) newSecrets.push(deserializer.deserializeU8());

        const description = deserializer.deserializeStr();
        const targetEpoch = Number(deserializer.deserializeU64());

        const proposal: ProposedEpochConfig = {
            nodes, threshold, epochDurationMicros, secretsToRetain, newSecrets, description, targetEpoch,
        };

        const votingSession = AccountAddress.deserialize(deserializer);

        const votesLen = deserializer.deserializeUleb128AsU32();
        const votes: boolean[] = [];
        for (let i = 0; i < votesLen; i++) votes.push(deserializer.deserializeBool());

        const votingPassed = deserializer.deserializeBool();

        return new ProposalView(proposal, votingSession, votes, votingPassed);
    }
}

/** Mirrors `ace::network::EpochChangeView` from `state_view_v0_bcs`. */
export class EpochChangeView {
    constructor(
        readonly triggeringProposalIdx: number | null,
        readonly sessionAddr: AccountAddress,
        readonly nxtNodes: AccountAddress[],
        readonly nxtThreshold: number,
    ) {}

    static deserialize(deserializer: Deserializer): EpochChangeView {
        const idxTag = deserializer.deserializeU8();
        const triggeringProposalIdx = idxTag === 1 ? Number(deserializer.deserializeU64()) : null;

        const sessionAddr = AccountAddress.deserialize(deserializer);

        const nxtNodesLen = deserializer.deserializeUleb128AsU32();
        const nxtNodes: AccountAddress[] = [];
        for (let i = 0; i < nxtNodesLen; i++) nxtNodes.push(AccountAddress.deserialize(deserializer));

        const nxtThreshold = Number(deserializer.deserializeU64());

        return new EpochChangeView(triggeringProposalIdx, sessionAddr, nxtNodes, nxtThreshold);
    }
}

/** Mirrors `ace::network::StateViewV0` from `state_view_v0_bcs`. */
export class State {
    constructor(
        readonly epoch: number,
        readonly epochStartTimeMicros: bigint,
        readonly epochDurationMicros: bigint,
        readonly curNodes: AccountAddress[],
        readonly curThreshold: number,
        readonly secrets: SecretInfo[],
        /** proposals[i] is node i's active proposal, last slot is admin's. null = no proposal. */
        readonly proposals: (ProposalView | null)[],
        readonly epochChangeInfo: EpochChangeView | null,
    ) {}

    isEpochChanging(): boolean {
        return this.epochChangeInfo !== null;
    }

    activeProposals(): ProposalView[] {
        return this.proposals.filter((p): p is ProposalView => p !== null);
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
                for (let i = 0; i < curNodesLen; i++) curNodes.push(AccountAddress.deserialize(deserializer));

                const curThreshold = Number(deserializer.deserializeU64());

                const secretsLen = deserializer.deserializeUleb128AsU32();
                const secrets: SecretInfo[] = [];
                for (let i = 0; i < secretsLen; i++) secrets.push(SecretInfo.deserialize(deserializer));

                const proposalsLen = deserializer.deserializeUleb128AsU32();
                const proposals: (ProposalView | null)[] = [];
                for (let i = 0; i < proposalsLen; i++) {
                    const tag = deserializer.deserializeU8();
                    if (tag === 1) {
                        proposals.push(ProposalView.deserialize(deserializer));
                    } else if (tag === 0) {
                        proposals.push(null);
                    } else {
                        throw `proposals[${i}] option tag must be 0 or 1, got ${tag}`;
                    }
                }

                const ecTag = deserializer.deserializeU8();
                let epochChangeInfo: EpochChangeView | null = null;
                if (ecTag === 1) {
                    epochChangeInfo = EpochChangeView.deserialize(deserializer);
                } else if (ecTag !== 0) {
                    throw `epoch_change_info option tag must be 0 or 1, got ${ecTag}`;
                }

                return new State(
                    epoch,
                    epochStartTimeMicros,
                    epochDurationMicros,
                    curNodes,
                    curThreshold,
                    secrets,
                    proposals,
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
