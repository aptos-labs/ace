// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * VSS protocol e2e over BLS12-381 G2 with a previous commitment and fresh
 * on-chain PCS context.
 */

import * as ace from '@aptos-labs/ace-sdk';
import { runVSSProtocolScenario } from './common/vss-protocol-runner';

await runVSSProtocolScenario({
    label: 'G2 default PCS context, previous commitment',
    scheme: ace.vss.SCHEME_BLS12381G2,
    tmpPrefix: 'ace-vss-g2-previous-',
    usePreviousCommitment: true,
});
