// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Shelby Access Control - Localnet End-to-End Test
 * 
 * This script demonstrates the complete flow of the Shelby Access Control system:
 * 1. Deploy the Move contract to Aptos localnet
 * 2. Alice (content owner) encrypts data and registers a blob with restricted access
 * 3. Bob (consumer) attempts to decrypt without permission (fails)
 * 4. Alice grants Bob permission by updating the access policy
 * 5. Bob successfully decrypts the content
 * 
 * Prerequisites:
 * 1. Start ACE local network: cd scenarios && pnpm run-local-network-forever
 *    (wait for "ACE local network is READY" banner)
 * 2. Run this test: pnpm test:localnet
 */

import { execSync } from "child_process";
import { readFileSync } from "fs";
import { Account, AccountAddress, Aptos, AptosConfig, Ed25519PrivateKey, Network } from "@aptos-labs/ts-sdk";
import * as ACE from "@aptos-labs/ace-sdk";
import { Result } from "@aptos-labs/ace-sdk";
import { AccessPolicy, RegistrationInfo, regsToBytes } from "./policy";

// ============================================================================
// Configuration
// ============================================================================

/**
 * Fixed deployer private key for reproducible deployments.
 * The corresponding address (derived from this key) must match the 'admin' 
 * address in Move.toml for the contract to deploy correctly.
 */
const DEPLOYER_PRIVATE_KEY_HEX = "0x1111111111111111111111111111111111111111111111111111111111111111";

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
 * Fund an account using the localnet faucet.
 * 
 * @param address - The account address to fund
 * @param amount - Amount in octas (1 APT = 100,000,000 octas)
 */
async function fundViaFaucet(address: AccountAddress, amount: number): Promise<void> {
    const faucetUrl = "http://localhost:8081";
    const response = await fetch(`${faucetUrl}/mint?amount=${amount}&address=${address.toStringLong()}`, {
        method: "POST",
    });
    if (!response.ok) {
        throw new Error(`Faucet request failed: ${response.status} ${await response.text()}`);
    }
    // Wait for the transaction to be processed by the node
    await new Promise(r => setTimeout(r, 2000));
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
    log("=== Shelby Access Control - Aptos Localnet Test ===");
    
    // ========================================================================
    // Step 1: Connect to Localnet
    // ========================================================================
    
    const aptos = new Aptos(new AptosConfig({
        network: Network.LOCAL,
        fullnode: "http://localhost:8080/v1",
        faucet: "http://localhost:8081",
    }));
    
    // Verify localnet is running
    try {
        await aptos.getLedgerInfo();
        log("✓ Connected to Aptos localnet");
    } catch {
        console.error("ERROR: Localnet not running. Start it first with: pnpm localnet");
        process.exit(1);
    }
    
    // ========================================================================
    // Step 2: Setup Deployer Account
    // ========================================================================
    
    // Create deployer from fixed private key (matches 'admin' in Move.toml)
    const deployerPrivateKey = new Ed25519PrivateKey(DEPLOYER_PRIVATE_KEY_HEX);
    console.log("deployerPrivateKey", deployerPrivateKey.toString());
    const deployer = Account.fromPrivateKey({ privateKey: deployerPrivateKey });
    console.log("publicKey", deployer.publicKey.toString());
    log(`Deployer address: ${deployer.accountAddress.toStringLong()}`);
    log(`(This address must match 'admin' in Move.toml)`);
    
    // Fund the deployer account
    log("Funding deployer account...");
    await fundViaFaucet(deployer.accountAddress, 500_000_000); // 5 APT
    log("✓ Deployer funded");
    
    // ========================================================================
    // Step 3: Deploy and Initialize Contract
    // ========================================================================
    
    log("Deploying Move contract...");
    const contractDir = new URL("../../contract", import.meta.url).pathname;
    try {
        // Clean build directory to avoid cached compilation issues
        execSync(`rm -rf build`, { cwd: contractDir, stdio: "inherit" });
        // Deploy the contract using Aptos CLI
        execSync(
            `aptos move publish --language-version 2.2 --assume-yes --url http://localhost:8080 --private-key ${deployer.privateKey.toString()}`,
            { cwd: contractDir, stdio: "inherit" }
        );
    } catch (e) {
        console.error("Failed to deploy contract:", e);
        process.exit(1);
    }
    log("✓ Contract deployed");
    
    // Wait for the indexer to catch up
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    const CONTRACT_ADDRESS = deployer.accountAddress.toStringLong();
    
    // Initialize the access control module
    log("Initializing contract...");
    await runTxn(aptos, deployer, `${CONTRACT_ADDRESS}::access_control::initialize`, []);
    log("✓ Contract initialized");
    
    // ========================================================================
    // Step 4: Create Test Accounts
    // ========================================================================
    
    // Alice: Content owner who will encrypt and register a blob
    const alice = Account.generate();
    // Bob: Consumer who wants to access Alice's content
    const bob = Account.generate();
    
    log(`Alice (owner): ${alice.accountAddress.toStringLong()}`);
    log(`Bob (consumer): ${bob.accountAddress.toStringLong()}`);
    
    // Fund test accounts
    log("Funding test accounts...");
    await fundViaFaucet(alice.accountAddress, 100_000_000); // 1 APT
    await fundViaFaucet(bob.accountAddress, 100_000_000);   // 1 APT
    log("✓ Test accounts funded");
    
    // ========================================================================
    // Step 5: Setup ACE
    // ========================================================================

    // Read ACE global network config written by `pnpm run-local-network-forever`.
    // Env vars ACE_CONTRACT + KEYPAIR_ID override the config file.
    let apiEndpoint: string;
    let contractAddr: string;
    let keypairId: AccountAddress;
    if (process.env.ACE_CONTRACT && process.env.KEYPAIR_ID) {
        apiEndpoint = "http://localhost:8080/v1";
        contractAddr = process.env.ACE_CONTRACT;
        keypairId = AccountAddress.fromString(process.env.KEYPAIR_ID);
    } else {
        const cfg = JSON.parse(readFileSync('/tmp/ace-localnet-config.json', 'utf8')) as
            { apiEndpoint: string; contractAddr: string; keypairId: string };
        apiEndpoint = cfg.apiEndpoint;
        contractAddr = cfg.contractAddr;
        keypairId = AccountAddress.fromString(cfg.keypairId);
    }
    log(`ACE contract: ${contractAddr}`);
    log(`Keypair ID:   ${keypairId.toString()}`);

    const aceDeployment = new ACE.AceDeployment({
        apiEndpoint,
        contractAddr: AccountAddress.fromString(contractAddr),
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
    
    async function bobAttemptToDecrypt(): Promise<Result<Uint8Array>> {
        const session = ACE.AptosBasicFlow.DecryptionSession.create({
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
    
    // Wait for state to propagate (localnet indexer may have slight delay)
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
    log("  1. ✓ Deployed access_control contract to localnet");
    log("  2. ✓ Alice encrypted content with ACE");
    log("  3. ✓ Alice registered blob with empty allowlist");
    log("  4. ✓ Bob was denied decryption (not in allowlist)");
    log("  5. ✓ Alice updated allowlist to include Bob");
    log("  6. ✓ Bob successfully decrypted content");
}

// Run the main function and handle any errors
main().catch(console.error);
