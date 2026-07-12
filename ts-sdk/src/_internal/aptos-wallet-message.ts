// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { AccountAddress } from "@aptos-labs/ts-sdk";

/**
 * Builds the Aptos wallet-style fullMessage string accepted by ACE for
 * service-side or script-side signing.
 *
 * Browser apps should prefer wallet.signMessage({ application: true, ... }) and
 * pass through the wallet-returned fullMessage. Use this helper when your code
 * signs directly with an Aptos account but still needs the same application
 * origin binding that a wallet would provide.
 */
export function buildAptosWalletFullMessage(args: {
    accountAddress: AccountAddress | string;
    application: string;
    chainId: number;
    message: string;
    nonce: string;
}): string {
    const address = typeof args.accountAddress === "string"
        ? args.accountAddress
        : args.accountAddress.toStringLong();
    return [
        "APTOS",
        `address: ${address}`,
        `application: ${args.application}`,
        `chainId: ${args.chainId}`,
        `message: ${args.message}`,
        `nonce: ${args.nonce}`,
    ].join("\n");
}
