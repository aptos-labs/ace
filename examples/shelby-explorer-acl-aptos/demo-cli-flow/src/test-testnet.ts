// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Shelby Access Control - Testnet End-to-End Test
 * 
 * This script demonstrates the complete flow of the Shelby Access Control system on testnet:
 * 1. Assumes the Move contract is already deployed to Aptos testnet
 * 2. Alice (content owner) encrypts data and registers a blob with restricted access
 * 3. Bob (consumer) attempts to decrypt without permission (fails)
 * 4. Alice grants Bob permission by updating the access policy
 * 5. Bob successfully decrypts the content
 * 
 * Prerequisites:
 * 1. Deploy the contract to testnet first: 
 *    cd ../contract && aptos move publish --network testnet --named-addresses admin=default
 * 2. Run this test: pnpm test:testnet
 * 
 * Note: This test uses public ACE workers by default. Override with WORKER_0/WORKER_1 env vars.
 */

import * as readline from "readline";
import { Account, AccountAddress, Aptos, AptosConfig, Network } from "@aptos-labs/ts-sdk";
import * as ACE from "@aptos-labs/ace-sdk";
import { Result } from "@aptos-labs/ace-sdk";
import { AccessPolicy, RegistrationInfo, regsToBytes } from "./policy";

// ============================================================================
// Configuration
// ============================================================================

/**
 * Contract address on testnet (matches 'admin' in Move.toml).
 */
const CONTRACT_ADDRESS = "0x147e4d3a5b10eaed2a93536e284c23096dfcea9ac61f0a8420e5d01fbd8f0ea8";

// Text encoding utilities for converting between strings and bytes
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Log a message with an ISO timestamp prefix for debugging.
 */
function log(...args: any[]) {
    console.log(`[${new Date().toISOString()}]`, ...args);
}

/**
 * Wait for the user to press Enter to continue.
 * Used to pause execution while user manually funds accounts.
 */
async function waitForEnter(message: string): Promise<void> {
    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout,
    });

    return new Promise((resolve) => {
        rl.question(message, () => {
            rl.close();
            resolve();
        });
    });
}

/**
 * Build, sign, submit, and wait for a Move transaction.
 * 
 * @param aptos - Aptos client
 * @param account - Signing account
 * @param func - Fully qualified function name (address::module::function)
 * @param functionArguments - Arguments to pass to the function
 */
async function runTxn(
    aptos: Aptos, 
    account: Account, 
    func: `${string}::${string}::${string}`, 
    functionArguments: any[]
): Promise<{ txnHash: string }> {
    const transaction = await aptos.transaction.build.simple({
        sender: account.accountAddress,
        data: {
            function: func,
            typeArguments: [],
            functionArguments
        }
    });
    const response = await aptos.signAndSubmitTransaction({ signer: account, transaction });
    await aptos.waitForTransaction({ transactionHash: response.hash });
    return { txnHash: response.hash };
}

// ============================================================================
// Main Test Flow
// ============================================================================

async function main() {
    log("=== Shelby Access Control - Aptos Testnet Test ===");
    log(`Contract address: ${CONTRACT_ADDRESS}`);
    
    // ========================================================================
    // Step 2: Connect to Testnet
    // ========================================================================
    
    const aptos = new Aptos(new AptosConfig({
        network: Network.TESTNET,
    }));
    
    // Verify testnet connectivity
    try {
        const ledgerInfo = await aptos.getLedgerInfo();
        log(`✓ Connected to Aptos testnet (chain_id: ${ledgerInfo.chain_id})`);
    } catch (e) {
        console.error("ERROR: Failed to connect to Aptos testnet");
        console.error(e);
        process.exit(1);
    }
    
    // ========================================================================
    // Step 3: Create Test Accounts
    // ========================================================================
    
    // Alice: Content owner who will encrypt and register a blob
    const alice = Account.generate();
    // Bob: Consumer who wants to access Alice's content
    const bob = Account.generate();
    
    log(`Alice (owner): ${alice.accountAddress.toStringLong()}`);
    log(`Bob (consumer): ${bob.accountAddress.toStringLong()}`);
    
    // ========================================================================
    // Step 4: Wait for Manual Funding
    // ========================================================================
    
    console.log("\n" + "=".repeat(70));
    console.log("MANUAL FUNDING REQUIRED");
    console.log("=".repeat(70));
    console.log("\nPlease fund the following accounts using the Aptos testnet faucet:");
    console.log("Faucet URL: https://aptos.dev/en/network/faucet\n");
    console.log(`  Alice: ${alice.accountAddress.toStringLong()}`);
    console.log(`  Bob:   ${bob.accountAddress.toStringLong()}`);
    console.log("\nEach account needs at least 0.1 APT for transaction fees.");
    console.log("=".repeat(70) + "\n");
    
    await waitForEnter("Press Enter once both accounts have been funded...");
    
    // Verify accounts are funded
    log("Verifying account balances...");
    try {
        const aliceBalance = await aptos.getAccountAPTAmount({ accountAddress: alice.accountAddress });
        const bobBalance = await aptos.getAccountAPTAmount({ accountAddress: bob.accountAddress });
        log(`  Alice balance: ${aliceBalance / 100_000_000} APT`);
        log(`  Bob balance: ${bobBalance / 100_000_000} APT`);
        
        if (aliceBalance === 0 || bobBalance === 0) {
            console.error("ERROR: One or both accounts have zero balance. Please fund them first.");
            process.exit(1);
        }
        log("✓ Accounts funded");
    } catch (e) {
        console.error("ERROR: Failed to check account balances. Make sure accounts are funded.");
        console.error(e);
        process.exit(1);
    }
    
    // ========================================================================
    // Step 5: Setup ACE
    // ========================================================================

    // ACE_CONTRACT and KEYPAIR_ID must be set for testnet.
    if (!process.env.ACE_CONTRACT || !process.env.KEYPAIR_ID) {
        console.error("ERROR: Set ACE_CONTRACT and KEYPAIR_ID env vars for testnet.");
        process.exit(1);
    }
    const aceContractStr: string = process.env.ACE_CONTRACT;
    const keypairId = AccountAddress.fromString(process.env.KEYPAIR_ID);
    const rpcUrl = "https://api.testnet.aptoslabs.com/v1";
    log(`ACE contract: ${aceContractStr}`);
    log(`Keypair ID:   ${keypairId.toString()}`);

    const aceDeployment = new ACE.AceDeployment({
        apiEndpoint: rpcUrl,
        contractAddr: AccountAddress.fromString(aceContractStr),
    });

    const chainId = await aptos.getChainId();
    
    // ========================================================================
    // Step 6: Alice Encrypts and Registers Content
    // ========================================================================
    
    const fileName = "star-wars.mov";
    // Full blob name format: @<owner_address_without_0x>/<file_name>
    // The @ replaces 0x to make it more readable and URL-friendly
    const fullBlobName = `${alice.accountAddress.toStringLong()}/${fileName}`.replaceAll("0x", "@");
    const plaintext = "A long time ago in a galaxy far, far away....";
    
    log("Alice encrypting content...");
    const ciphertext = (await ACE.AptosBasicFlow.encrypt({
        aceDeployment,
        keypairId,
        chainId,
        moduleAddr: AccountAddress.fromString(CONTRACT_ADDRESS),
        moduleName: "access_control",
        functionName: "check_permission",
        domain: textEncoder.encode(fullBlobName),
        plaintext: textEncoder.encode(plaintext),
    })).unwrapOrThrow("encryption failed");
    log("✓ Content encrypted");
    
    // Register the blob on-chain with an empty allowlist (only Alice can access)
    log("Alice registering blob on-chain...");
    const initialAccessPolicy = AccessPolicy.newAllowlist([]);  // Empty = owner only
    const reg = new RegistrationInfo(fileName, initialAccessPolicy);
    await runTxn(aptos, alice, `${CONTRACT_ADDRESS}::access_control::register_blobs`, [regsToBytes([reg])]);
    log("✓ Blob registered with empty allowlist");
    
    // ========================================================================
    // Step 7: Bob Attempts to Decrypt (Should Fail)
    // ========================================================================
    
    /**
     * Helper function for Bob to attempt decryption.
     * 
     * The flow is:
     * 1. Bob signs the decryption domain to prove his identity
     * 2. Bob requests decryption key shares from workers
     * 3. Workers call check_permission(bob, domain) on-chain
     * 4. If check_permission returns true, workers release their key shares
     * 5. Bob aggregates key shares and decrypts
     */
    async function bobAttemptToDecrypt(): Promise<Result<Uint8Array>> {
        const session = await ACE.AptosBasicFlow.DecryptionSession.create({
            aceDeployment,
            keypairId,
            chainId,
            moduleAddr: AccountAddress.fromString(CONTRACT_ADDRESS),
            moduleName: "access_control",
            functionName: "check_permission",
            domain: textEncoder.encode(fullBlobName),
            ciphertext,
        });
        const msgToSign = await session.getRequestToSign();
        return session.decryptWithProof({
            userAddr: bob.accountAddress,
            publicKey: bob.publicKey,
            signature: bob.sign(msgToSign),
        });
    }
    
    // Bob tries to decrypt without permission - should fail
    log("Bob attempting to decrypt (should fail - not in allowlist)...");
    const attempt0 = await bobAttemptToDecrypt();
    if (attempt0.isOk) {
        console.error("ERROR: Bob should not be able to decrypt without permission!");
        process.exit(1);
    }
    log("✓ Correctly denied - Bob is not in the allowlist");
    
    // ========================================================================
    // Step 8: Alice Grants Bob Permission
    // ========================================================================
    
    log("Alice updating allowlist to include Bob...");
    const newPolicy = AccessPolicy.newAllowlist([bob.accountAddress]).toBytes();
    await runTxn(aptos, alice, `${CONTRACT_ADDRESS}::access_control::force_update_policy`, [fileName, newPolicy]);
    log("✓ Permission granted to Bob");
    
    // Wait for state to propagate
    log("Waiting for state propagation...");
    await new Promise(resolve => setTimeout(resolve, 3000));
    
    // ========================================================================
    // Step 9: Bob Successfully Decrypts
    // ========================================================================
    
    log("Bob attempting to decrypt (should succeed - now in allowlist)...");
    const attempt1 = await bobAttemptToDecrypt();
    if (!attempt1.isOk) {
        console.error("ERROR: Bob should be able to decrypt now!");
        console.error(attempt1);
        process.exit(1);
    }
    
    // Verify the decrypted content matches the original
    const decryptedText = textDecoder.decode(attempt1.okValue!);
    if (decryptedText !== plaintext) {
        console.error("ERROR: Decrypted text doesn't match original!");
        console.error(`Expected: "${plaintext}"`);
        console.error(`Got: "${decryptedText}"`);
        process.exit(1);
    }
    log(`✓ Decrypted successfully: "${decryptedText}"`);
    
    // ========================================================================
    // Test Complete
    // ========================================================================
    
    log("=== All tests passed! ===");
    log("");
    log("Summary:");
    log("  1. ✓ Connected to Aptos testnet");
    log("  2. ✓ Alice encrypted content with ACE");
    log("  3. ✓ Alice registered blob with empty allowlist");
    log("  4. ✓ Bob was denied decryption (not in allowlist)");
    log("  5. ✓ Alice updated allowlist to include Bob");
    log("  6. ✓ Bob successfully decrypted content");
}

// Run the main function and handle any errors
main().catch(console.error);

