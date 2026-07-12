// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * VSS protocol e2e — default group: BLS12-381 G2.
 *
 * Exercises the updated VSS path with private share delivery through signed
 * node-to-node messages and node-local VSS stores.
 */

import * as ace from '@aptos-labs/ace-sdk';
import { runVSSProtocolScenario } from './common/vss-protocol-runner';

await runVSSProtocolScenario({
    label: 'G2 default PCS context, fresh secret',
    scheme: ace.vss.SCHEME_BLS12381G2,
    tmpPrefix: 'ace-vss-',
});
