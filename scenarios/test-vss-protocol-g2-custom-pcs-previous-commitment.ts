// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * VSS protocol e2e over BLS12-381 G2 with caller-supplied PCS context and a
 * previous commitment.
 */

import * as ace from '@aptos-labs/ace-sdk';
import { runVSSProtocolScenario } from './common/vss-protocol-runner';

await runVSSProtocolScenario({
    label: 'G2 supplied PCS context, previous commitment',
    scheme: ace.vss.SCHEME_BLS12381G2,
    tmpPrefix: 'ace-vss-g2-custom-pcs-previous-',
    useCustomPcsContext: true,
    usePreviousCommitment: true,
});
