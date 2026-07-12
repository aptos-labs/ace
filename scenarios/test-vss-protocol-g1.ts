// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * VSS protocol e2e over BLS12-381 G1 (scheme = 0).
 *
 * Mirrors the default G2 VSS scenario while keeping the G1 commitment/share
 * path covered.
 */

import * as ace from '@aptos-labs/ace-sdk';
import { runVSSProtocolScenario } from './common/vss-protocol-runner';

await runVSSProtocolScenario({
    label: 'G1 default PCS context, fresh secret',
    scheme: ace.vss.SCHEME_BLS12381G1,
    tmpPrefix: 'ace-vss-g1-',
});
