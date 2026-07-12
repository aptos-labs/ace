// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import * as ace from '@aptos-labs/ace-sdk';

export type VSSProtocolScenarioOptions = {
    label: string;
    scheme: number;
    tmpPrefix: string;
    useCustomPcsContext?: boolean;
    usePreviousCommitment?: boolean;
};

export type PreviousCommitmentFixture = {
    commitment: ace.vss.PreviousCommitment;
    secret: ace.vss.PrivateScalar;
    secretRawFr: Uint8Array;
    blindingRawFr: Uint8Array;
};

export function makePcsContext(scheme: number): ace.vss.PcsPublicParams {
    const base = baseElement(scheme);
    const generatorG = base.scale(ace.vss.sample(scheme));
    const generatorH = base.scale(ace.vss.sample(scheme));
    return new ace.vss.PcsPublicParams(generatorG, generatorH);
}

export function makePreviousCommitmentFixture(scheme: number): PreviousCommitmentFixture {
    const secret = ace.vss.sample(scheme);
    const blinding = ace.vss.sample(scheme);
    const previousContext = makePcsContext(scheme);
    const oldC = previousContext.generatorG.scale(secret).add(previousContext.generatorH.scale(blinding));
    return {
        commitment: new ace.vss.PreviousCommitment(
            previousContext.generatorG,
            previousContext.generatorH,
            oldC,
        ),
        secret,
        secretRawFr: rawFrFromScalar(secret),
        blindingRawFr: rawFrFromScalar(blinding),
    };
}

export function rawFrHex(rawFr: Uint8Array): string {
    if (rawFr.length !== 32) {
        throw new Error(`raw scalar must be 32 bytes, got ${rawFr.length}`);
    }
    return Buffer.from(rawFr).toString('hex');
}

export function assertVSSSessionShape(opts: {
    session: ace.vss.Session;
    scenario: VSSProtocolScenarioOptions;
    customPcsContext: ace.vss.PcsPublicParams | undefined;
    previousFixture: PreviousCommitmentFixture | undefined;
}): void {
    const { session, scenario, customPcsContext, previousFixture } = opts;
    if (session.scheme !== scenario.scheme) {
        throw `expected VSS scheme = ${scenario.scheme}, got ${session.scheme}`;
    }
    if (customPcsContext !== undefined) {
        if (!session.pcsContext.generatorG.equals(customPcsContext.generatorG)) {
            throw 'session PCS generator_g does not match supplied context';
        }
        if (!session.pcsContext.generatorH.equals(customPcsContext.generatorH)) {
            throw 'session PCS generator_h does not match supplied context';
        }
    }
    if (previousFixture === undefined) {
        if (session.previousCommitment !== undefined) {
            throw 'fresh VSS should not store a previous commitment';
        }
        if (session.dealerContribution0?.consistencyProof !== undefined) {
            throw 'fresh VSS should not publish a consistency proof';
        }
    } else {
        if (session.previousCommitment === undefined) {
            throw 'reshare VSS should store a previous commitment';
        }
        if (!session.previousCommitment.oldC.equals(previousFixture.commitment.oldC)) {
            throw 'session previous commitment does not match supplied old_c';
        }
        if (session.dealerContribution0?.consistencyProof === undefined) {
            throw 'reshare VSS should publish a consistency proof';
        }
    }
}

function baseElement(scheme: number): ace.vss.PublicPoint {
    if (scheme === ace.vss.SCHEME_BLS12381G1) {
        return ace.group.Element.fromBls12381G1(ace.group.bls12381G1.g1Generator());
    }
    if (scheme === ace.vss.SCHEME_BLS12381G2) {
        return ace.group.Element.fromBls12381G2(ace.group.bls12381G2.g2Generator());
    }
    throw new Error(`unsupported VSS scheme ${scheme}`);
}

function rawFrFromScalar(scalar: ace.vss.PrivateScalar): Uint8Array {
    const bytes = scalar.toBytes();
    if (bytes.length !== 34 || bytes[0] !== scalar.scheme || bytes[1] !== 32) {
        throw new Error(`unexpected scalar encoding for scheme ${scalar.scheme}`);
    }
    return bytes.slice(2);
}
