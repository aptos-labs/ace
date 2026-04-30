// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Utility Functions for Shelby Access Control Demo
 * 
 * This module provides helper functions for common operations in the demo,
 * including logging and transaction execution.
 */

import { Account, Aptos, EntryFunctionArgumentTypes, SimpleEntryFunctionArgumentTypes } from "@aptos-labs/ts-sdk";

/**
 * Log a message with an ISO timestamp prefix.
 * Useful for debugging and understanding the flow of operations.
 * 
 * @param args - Arguments to log (same as console.log)
 * 
 * @example
 * log("Starting test...");
 * // Output: [2024-01-15T10:30:00.000Z] Starting test...
 */
export function log(...args: any[]) {
    console.log(`[${new Date().toISOString()}]`, ...args);
}

/**
 * Build, sign, submit, and wait for a Move entry function transaction.
 * 
 * This is a convenience wrapper that handles the full transaction lifecycle:
 * 1. Build the transaction with the given function and arguments
 * 2. Sign it with the provided account
 * 3. Submit to the network
 * 4. Wait for confirmation
 * 5. Fetch and return the transaction details including events
 * 
 * @param aptos - The Aptos client instance
 * @param account - The account to sign the transaction
 * @param func - The fully qualified function name in format "address::module::function"
 * @param functionArguments - Array of arguments to pass to the function
 * @returns Object containing the transaction hash and emitted events
 * 
 * @example
 * // Initialize the access control contract
 * await runTxn(aptos, deployer, `${CONTRACT}::access_control::initialize`, []);
 * 
 * // Register a blob with serialized registration data
 * await runTxn(aptos, alice, `${CONTRACT}::access_control::register_blobs`, [regsToBytes([reg])]);
 * 
 * // Update access policy
 * await runTxn(aptos, alice, `${CONTRACT}::access_control::force_update_policy`, [fileName, policyBytes]);
 */
export async function runTxn(
    aptos: Aptos, 
    account: Account, 
    func: `${string}::${string}::${string}`, 
    functionArguments: Array<EntryFunctionArgumentTypes | SimpleEntryFunctionArgumentTypes>
): Promise<{ txnHash: string, events: Array<any> }> {
    // Step 1: Build the transaction
    const transaction = await aptos.transaction.build.simple({
        sender: account.accountAddress,
        data: {
            function: func,
            typeArguments: [],  // No generic type arguments needed for our functions
            functionArguments
        }
    });
  
    // Step 2 & 3: Sign and submit the transaction
    const response = await aptos.signAndSubmitTransaction({
        signer: account,
        transaction
    });
    
    // Step 4: Wait for the transaction to be confirmed
    await aptos.waitForTransaction({ transactionHash: response.hash });
    
    // Step 5: Fetch transaction details to get emitted events
    const txnDetails = await aptos.getTransactionByHash({ transactionHash: response.hash });
    const events = (txnDetails as any).events || [];
    
    return { txnHash: response.hash, events };
}
