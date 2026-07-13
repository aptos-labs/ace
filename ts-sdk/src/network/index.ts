// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { AccountAddress, Deserializer } from "@aptos-labs/ts-sdk";
import { Result } from "../result";

export const PRIMITIVE_BFIBE_BLS12381_SHORTPK_OTP_HMAC = 0;
export const PRIMITIVE_BFIBE_BLS12381_SHORTSIG_AEAD = 1;
export const PRIMITIVE_BLS12381_THRESHOLD_VRF = 2;

export const USAGE_BFIBE_BLS12381_SHORTPK_OTP_HMAC = 1n;
export const USAGE_BFIBE_BLS12381_SHORTSIG_AEAD = 2n;
export const USAGE_BLS12381_THRESHOLD_VRF = 4n;

export const PRIMITIVE_BLS12381_G1_TEST_ONLY = PRIMITIVE_BFIBE_BLS12381_SHORTPK_OTP_HMAC;
export const PRIMITIVE_BLS12381_G2_TEST_ONLY = PRIMITIVE_BFIBE_BLS12381_SHORTSIG_AEAD;
export const USAGE_BLS12381_G1_TEST_ONLY = USAGE_BFIBE_BLS12381_SHORTPK_OTP_HMAC;
export const USAGE_BLS12381_G2_TEST_ONLY = USAGE_BFIBE_BLS12381_SHORTSIG_AEAD;

export function usageForPrimitive(primitive: number): bigint {
    switch (primitive) {
        case PRIMITIVE_BFIBE_BLS12381_SHORTPK_OTP_HMAC:
            return USAGE_BFIBE_BLS12381_SHORTPK_OTP_HMAC;
        case PRIMITIVE_BFIBE_BLS12381_SHORTSIG_AEAD:
            return USAGE_BFIBE_BLS12381_SHORTSIG_AEAD;
        case PRIMITIVE_BLS12381_THRESHOLD_VRF:
            return USAGE_BLS12381_THRESHOLD_VRF;
        default:
            throw new Error(`unsupported ACE primitive ${primitive}`);
    }
}

const SCHEME_NAMES: Record<number, string> = {
    0: 'BLS12-381 G1 / BFIBE short-PK OTP-HMAC',
    1: 'BLS12-381 G2 / BFIBE short-signature AEAD',
    2: 'BLS12-381 threshold VRF',
};

export function schemeName(scheme: number): string {
    return SCHEME_NAMES[scheme] ?? `unknown scheme ${scheme}`;
}

/** Mirrors `ace::network::SecretInfo` from `state_view_v0_bcs`. */
export class SecretInfo {
    constructor(
        /** Address of the most recent DKG or DKR session — use this in secrets_to_retain. */
        readonly currentSession: AccountAddress,
        /** Address of the original DKG session that created this secret lineage. */
        readonly keypairId: AccountAddress,
        readonly scheme: number,
        readonly expectedUsage: bigint,
        readonly note: string,
    ) {}

    schemeName(): string { return schemeName(this.scheme); }

    static deserialize(deserializer: Deserializer): SecretInfo {
        const currentSession = AccountAddress.deserialize(deserializer);
        const keypairId = AccountAddress.deserialize(deserializer);
        const scheme = deserializer.deserializeU8();
        const expectedUsage = deserializer.deserializeU64();
        const note = deserializer.deserializeStr();
        return new SecretInfo(currentSession, keypairId, scheme, expectedUsage, note);
    }
}

/** Mirrors `ace::secret_usage::SecretRequest` inside `ProposedEpochConfig`. */
export class SecretRequest {
    constructor(
        readonly expectedUsage: bigint,
        readonly note: string = '',
    ) {}

    static deserialize(deserializer: Deserializer): SecretRequest {
        const expectedUsage = deserializer.deserializeU64();
        const note = deserializer.deserializeStr();
        return new SecretRequest(expectedUsage, note);
    }
}

/** Mirrors `ace::network::ProposedEpochConfig`. */
export type ProposedEpochConfig = {
    nodes: AccountAddress[];
    threshold: number;
    epochDurationMicros: bigint;
    secretsToRetain: AccountAddress[];
    newSecrets: SecretRequest[];
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
        const newSecrets: SecretRequest[] = [];
        for (let i = 0; i < newSecretsLen; i++) newSecrets.push(SecretRequest.deserialize(deserializer));

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

/** Mirrors `ace::network::EpochSnapshotView` from `state_view_v0_bcs`. */
export class EpochSnapshot {
    constructor(
        readonly nodes: AccountAddress[],
        readonly secrets: SecretInfo[],
    ) {}

    static deserialize(deserializer: Deserializer): EpochSnapshot {
        const nodesLen = deserializer.deserializeUleb128AsU32();
        const nodes: AccountAddress[] = [];
        for (let i = 0; i < nodesLen; i++) nodes.push(AccountAddress.deserialize(deserializer));

        const secretsLen = deserializer.deserializeUleb128AsU32();
        const secrets: SecretInfo[] = [];
        for (let i = 0; i < secretsLen; i++) secrets.push(SecretInfo.deserialize(deserializer));

        return new EpochSnapshot(
            nodes,
            secrets,
        );
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
        readonly previousEpochInfo: EpochSnapshot | null,
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

                const previousEpochTag = deserializer.deserializeU8();
                let previousEpochInfo: EpochSnapshot | null = null;
                if (previousEpochTag === 1) {
                    previousEpochInfo = EpochSnapshot.deserialize(deserializer);
                } else if (previousEpochTag !== 0) {
                    throw `previous_epoch_info option tag must be 0 or 1, got ${previousEpochTag}`;
                }

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
                    previousEpochInfo,
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
