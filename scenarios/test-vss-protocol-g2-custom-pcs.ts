// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * VSS protocol e2e over BLS12-381 G2 with caller-supplied PCS context.
 */

import * as ace from '@aptos-labs/ace-sdk';
import { runVSSProtocolScenario } from './common/vss-protocol-runner';

await runVSSProtocolScenario({
    label: 'G2 supplied PCS context, fresh secret',
    scheme: ace.vss.SCHEME_BLS12381G2,
    tmpPrefix: 'ace-vss-g2-custom-pcs-',
    useCustomPcsContext: true,
});
