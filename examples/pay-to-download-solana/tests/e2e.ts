// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Shelby Access Control - Solana End-to-End Test
 * 
 * This test demonstrates the complete pay-to-access content flow:
 * 
 * 1. Alice (content owner) encrypts a symmetric key (RedKey) using ACE
 * 2. Alice registers the encrypted key (GreenBox) on-chain with a price
 * 3. Bob (consumer) tries to decrypt without payment (fails)
 * 4. Bob purchases access by paying Alice
 * 5. Bob creates a proof-of-permission by signing a transaction
 * 6. Bob requests decryption key shares from workers (they verify access on-chain)
 * 7. Bob decrypts the GreenBox to recover the RedKey
 * 
 * Prerequisites:
 * - ACE global network running (Aptos localnet + workers):
 *   cd scenarios && pnpm run-local-network-forever
 *   (wait for "ACE local network is READY" banner)
 * - Then in a second terminal:
 *   cd examples/pay-to-download-solana
 *   anchor test --provider.cluster localnet
 */

import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { AccessControl } from "../target/types/access_control";
import { AceHook } from "../target/types/ace_hook";
import { Connection, Keypair, LAMPORTS_PER_SOL, PublicKey, TransactionMessage, VersionedTransaction } from "@solana/web3.js";
import { expect } from "chai";
import * as ACE from "@aptos-labs/ace-sdk";
import { Result } from "@aptos-labs/ace-sdk";
import { AccountAddress, Serializer, DerivableAbstractedAccount } from "@aptos-labs/ts-sdk";
import { readFileSync } from "fs";

// ============================================================================
// Test Suite
// ============================================================================

describe("access-control", () => {
  // Setup Anchor provider and programs
  anchor.setProvider(anchor.AnchorProvider.env());

  /** Main program for registering blobs and processing purchases */
  const program = anchor.workspace.accessControl as Program<AccessControl>;
  
  /** Hook program that workers call to verify access permission */
  const accessControlProgram = anchor.workspace.aceHook as Program<AceHook>;
  
  const provider = anchor.AnchorProvider.env();

  // ============================================================================
  // Test: Pay-to-Access Content Flow
  // ============================================================================

  /**
   * Main test demonstrating the complete flow:
   * 
   * UPLOAD FLOW (Alice):
   * 1. Generate a symmetric key (RedKey) for file encryption
   * 2. Encrypt RedKey with ACE → GreenBox
   * 3. Register GreenBox on-chain with a price
   * 
   * DOWNLOAD FLOW (Bob):
   * 1. Try to decrypt without payment (should fail)
   * 2. Purchase access by paying Alice
   * 3. Create proof-of-permission (signed transaction)
   * 4. Request decryption key from workers
   * 5. Decrypt GreenBox → RedKey
   */
  it("Pay-to-access content flow", async () => {
    // ========================================================================
    // Step 1: Setup Test Accounts
    // ========================================================================
    
    /** Alice: Content owner who registers encrypted content */
    const alice = Keypair.generate();
    /** Alice's Aptos address (derived from Solana address for cross-chain compatibility) */
    const aliceAptosAddr = solanaAddrToAptosAddr(alice.publicKey);
    /** Bob: Consumer who wants to access Alice's content */
    const bob = Keypair.generate();
    
    const connection = provider.connection;
    const minBalance = 0.1 * LAMPORTS_PER_SOL;

    // Fund both accounts (airdrop on localnet, manual on testnet)
    await fundAccounts(connection, [alice, bob], minBalance);

    // ========================================================================
    // Step 2: Setup ACE (read config from run-local-network-forever)
    // ========================================================================

    console.log("=== Setting up ACE ===");
    const fileName = "start-wars.mov";

    // RedKey: The symmetric encryption key for the actual file content
    // In a real app, this would be used to encrypt the file (RedBox)
    const redKeyHex = "a3f7b2c9e1d84f6a0b5c3e2d1f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a";
    const redKey = hexToBytes(redKeyHex);

    // Detect network for knownChainName (used in ContractID)
    const isLocalnet = connection.rpcEndpoint.includes('localhost') || connection.rpcEndpoint.includes('127.0.0.1');
    const knownChainName = isLocalnet ? "localnet" : "testnet";

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
    console.log(`ACE contract: ${contractAddr}`);
    console.log(`Keypair ID:   ${keypairId.toString()}`);

    const aceDeployment = new ACE.AceDeployment({
      apiEndpoint,
      contractAddr: AccountAddress.fromString(contractAddr),
    });
    
    // ========================================================================
    // Step 3: Alice Encrypts RedKey → GreenBox
    // ========================================================================
    
    console.log("\n=== Alice: Encrypt and Register ===");
    console.log("(2a.1) Encrypting RedKey into GreenBox...");
    
    const aliceAptosAddrBytes = aliceAptosAddr.toUint8Array();
    
    // Full blob name format: "0x" + owner_aptos_addr (32 bytes) + "/" + blob_name
    // This uniquely identifies the blob across the system
    const fullBlobNameBytes = Buffer.concat([
      Buffer.from("0x"),                      // 2 bytes: prefix
      Buffer.from(aliceAptosAddrBytes),       // 32 bytes: owner address
      Buffer.from("/"),                       // 1 byte: separator
      Buffer.from(fileName),                  // N bytes: file name
    ]);

    // Encrypt RedKey with ACE.
    // The result (GreenBox) can only be decrypted by users who pass the access check.
    const greenBox = (await ACE.SolanaBasicFlow.encrypt({
      aceDeployment,
      keypairId,
      knownChainName,
      programId: accessControlProgram.programId.toBase58(),
      domain: fullBlobNameBytes,  // Unique identifier for this blob
      plaintext: redKey,          // The symmetric key to encrypt
    })).unwrapOrThrow('failed to encrypt');
    // greenBox is Uint8Array
    console.log("✓ RedKey encrypted into GreenBox");

    // ========================================================================
    // Step 4: Alice Registers GreenBox On-Chain
    // ========================================================================
    
    console.log("(2a.2) Alice registering GreenBox on-chain...");
    
    const greenBoxScheme = 2;  // Encryption scheme version
    const greenBoxBytes = greenBox; // already Uint8Array
    const price = new anchor.BN(0.0005 * LAMPORTS_PER_SOL);  // 0.0005 SOL per download
    
    // Register creates a BlobMetadata PDA storing:
    // - owner: Alice's Solana address
    // - green_box_bytes: The encrypted symmetric key
    // - price: Cost to purchase access
    // - seqnum: Sequence number for access verification
    const fileRegTxn = await program.methods
      .registerBlob(
        Array.from(aliceAptosAddrBytes),  // Owner's Aptos address
        fileName,                          // Blob name (used in PDA seed)
        greenBoxScheme,                    // Encryption scheme
        Buffer.from(greenBoxBytes),        // Encrypted key
        price                              // Price in lamports
      )
      .accounts({
        owner: alice.publicKey,
      })
      .signers([alice])
      .rpc();
    await confirmTransaction(connection, fileRegTxn);
    console.log("✓ GreenBox registered on-chain");
    
    // NOTE: In a real application, Alice would also:
    // (2b.1) Encrypt the file content with RedKey → RedBox
    // (2b.2) Upload RedBox to Shelby storage

    // ========================================================================
    // Step 5: Bob Attempts to Decrypt Without Payment (Should Fail)
    // ========================================================================

    /**
     * Helper function for Bob to attempt decryption using a legacy transaction.
     * 
     * The flow is:
     * 1. Build a transaction calling ace_hook::assert_access
     * 2. Sign the transaction with Bob's key
     * 3. Create a proof-of-permission from the signed transaction
     * 4. Request decryption key shares from workers
     * 5. Aggregate key shares and decrypt
     * 
     * Workers will:
     * - Verify the transaction calls the correct program (ace_hook)
     * - Simulate the transaction to check if assert_access would succeed
     * - Only release key shares if verification passes
     */
    async function bobOpenGreenBoxV0(): Promise<Result<Uint8Array>> {
      const session = await ACE.SolanaBasicFlow.DecryptionSession.create({
        aceDeployment,
        keypairId,
        knownChainName,
        programId: accessControlProgram.programId.toBase58(),
        domain: fullBlobNameBytes,
        ciphertext: greenBox,
      });
      const fullRequestBytes = await session.getRequestToSign();

      const txn = await accessControlProgram.methods
        .assertAccess(Buffer.from(fullRequestBytes))
        .accounts({
          blobMetadata: deriveBlobMetadataPda(aliceAptosAddrBytes, fileName, program.programId),
          receipt: deriveAccessReceiptPda(aliceAptosAddrBytes, fileName, bob.publicKey, program.programId),
          user: bob.publicKey,
        })
        .transaction();
      txn.feePayer = bob.publicKey;
      const { blockhash } = await connection.getLatestBlockhash();
      txn.recentBlockhash = blockhash;
      txn.sign(bob);

      return session.decryptWithProof({ txn: txn.serialize() });
    }

    async function bobOpenGreenBoxV1(): Promise<Result<Uint8Array>> {
      const session = await ACE.SolanaBasicFlow.DecryptionSession.create({
        aceDeployment,
        keypairId,
        knownChainName,
        programId: accessControlProgram.programId.toBase58(),
        domain: fullBlobNameBytes,
        ciphertext: greenBox,
      });
      const fullRequestBytes = await session.getRequestToSign();

      const instruction = await accessControlProgram.methods
        .assertAccess(Buffer.from(fullRequestBytes))
        .accounts({
          blobMetadata: deriveBlobMetadataPda(aliceAptosAddrBytes, fileName, program.programId),
          receipt: deriveAccessReceiptPda(aliceAptosAddrBytes, fileName, bob.publicKey, program.programId),
          user: bob.publicKey,
        })
        .instruction();
      const { blockhash } = await connection.getLatestBlockhash();
      const messageV0 = new TransactionMessage({
        payerKey: bob.publicKey,
        recentBlockhash: blockhash,
        instructions: [instruction],
      }).compileToV0Message();
      const versionedTxn = new VersionedTransaction(messageV0);
      versionedTxn.sign([bob]);

      return session.decryptWithProof({ txn: versionedTxn.serialize() });
    }

    console.log("\n=== Bob: Attempt Decryption Without Payment ===");
    console.log("Bob attempting to decrypt (should fail - no receipt)...");
    const bobAttempt0Result = await bobOpenGreenBoxV0();
    console.log('Result:', bobAttempt0Result.isOk ? 'SUCCESS' : 'FAILED (expected)');
    bobAttempt0Result.unwrapErrOrThrow('attempt 0 should fail');
    console.log("✓ Correctly denied - Bob has not purchased access");

    // ========================================================================
    // Step 6: Bob Purchases Access
    // ========================================================================
    
    console.log("\n=== Bob: Purchase Access ===");
    console.log("Bob sending purchase transaction...");
    
    // Purchase transfers SOL from Bob to Alice and creates a Receipt PDA
    // The Receipt stores the seqnum at time of purchase
    const purchaseTxn = await program.methods
      .purchase(Array.from(aliceAptosAddrBytes), fileName)
      .accounts({
        buyer: bob.publicKey,
        owner: alice.publicKey,
      })
      .signers([bob])
      .rpc();

    await confirmTransaction(connection, purchaseTxn);
    // Extra delay to ensure state is propagated to RPC
    await new Promise(resolve => setTimeout(resolve, 1000));
    console.log("✓ Purchase complete - Receipt PDA created");

    // ========================================================================
    // Step 7: Bob Successfully Decrypts
    // ========================================================================
    
    console.log("\n=== Bob: Decrypt with Permission ===");
    
    // Test with legacy transaction format
    console.log("Bob attempting to decrypt with legacy transaction...");
    const bobAttempt1Result = await bobOpenGreenBoxV0();
    console.log('Result:', bobAttempt1Result.isOk ? 'SUCCESS' : 'FAILED');
    const plaintext1 = bobAttempt1Result.unwrapOrThrow('attempt 1 should succeed');
    expect(bytesToHex(plaintext1)).to.equal(redKeyHex);
    console.log("✓ Decrypted successfully with legacy transaction");

    // Test with versioned transaction format
    console.log("Bob attempting to decrypt with versioned transaction...");
    const bobAttempt2Result = await bobOpenGreenBoxV1();
    console.log('Result:', bobAttempt2Result.isOk ? 'SUCCESS' : 'FAILED');
    const plaintext2 = bobAttempt2Result.unwrapOrThrow('attempt 2 should succeed');
    expect(bytesToHex(plaintext2)).to.equal(redKeyHex);
    console.log("✓ Decrypted successfully with versioned transaction");

    // ========================================================================
    // Test Complete
    // ========================================================================
    
    console.log("\n=== All tests passed! ===");
    console.log("Summary:");
    console.log("  1. ✓ Alice encrypted RedKey into GreenBox");
    console.log("  2. ✓ Alice registered GreenBox on-chain with price");
    console.log("  3. ✓ Bob was denied decryption (no receipt)");
    console.log("  4. ✓ Bob purchased access (Receipt created)");
    console.log("  5. ✓ Bob decrypted GreenBox → RedKey (legacy tx)");
    console.log("  6. ✓ Bob decrypted GreenBox → RedKey (versioned tx)");
  });
});

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Fund accounts with SOL.
 * - On localnet: Uses airdrop
 * - On testnet: Waits for manual funding and prints CLI commands
 * 
 * @param connection - Solana RPC connection
 * @param accounts - Keypairs to fund
 * @param minBalance - Minimum balance required in lamports
 */
async function fundAccounts(
  connection: Connection,
  accounts: Keypair[],
  minBalance: number
): Promise<void> {
  const isLocalnet = connection.rpcEndpoint.includes('localhost') || connection.rpcEndpoint.includes('127.0.0.1');
  console.log('Network:', isLocalnet ? 'localnet' : 'testnet');
  
  if (isLocalnet) {
    // Localnet: Airdrop SOL automatically
    console.log("\n=== Airdropping SOL on localnet ===");
    for (const account of accounts) {
      console.log("Funding:", account.publicKey.toString());
      const airdropSig = await connection.requestAirdrop(account.publicKey, minBalance);
      await connection.confirmTransaction(airdropSig);
    }
    console.log("✓ All accounts funded\n");
  } else {
    // Testnet: Wait for manual funding
    console.log("\n=== Please fund these addresses manually ===");
    for (const account of accounts) {
      console.log("Address:", account.publicKey.toString());
    }
    console.log(`Minimum required: ${minBalance / LAMPORTS_PER_SOL} SOL each`);
    console.log("==============================================\n");

    console.log("To fund using Solana CLI:");
    for (const account of accounts) {
      console.log(`  solana transfer --allow-unfunded-recipient ${account.publicKey.toString()} ${minBalance / LAMPORTS_PER_SOL}`);
    }
    console.log("");

    // Poll for funding
    let waitMs = 10000;
    const maxWaitMs = 60000;
    while (true) {
      const balances = await Promise.all(accounts.map(a => connection.getBalance(a.publicKey)));
      const allFunded = balances.every(b => b >= minBalance);
      
      console.log("Balances:", balances.map(b => `${b / LAMPORTS_PER_SOL} SOL`).join(", "));
      
      if (allFunded) {
        console.log("✓ All accounts funded\n");
        break;
      }

      await new Promise(resolve => setTimeout(resolve, waitMs));
      waitMs = Math.min(waitMs * 2, maxWaitMs);
    }
  }
}

/**
 * Derive the BlobMetadata PDA for a given owner and blob name.
 * 
 * Seeds: ["blob_metadata", owner_aptos_addr, blob_name]
 * 
 * @param ownerAptosAddr - Owner's Aptos address (32 bytes)
 * @param blobName - Name of the blob
 * @param programId - access_control program ID
 */
function deriveBlobMetadataPda(
  ownerAptosAddr: Uint8Array,
  blobName: string,
  programId: PublicKey
): PublicKey {
  const [pda] = PublicKey.findProgramAddressSync(
    [
      Buffer.from("blob_metadata"),
      Buffer.from(ownerAptosAddr),
      Buffer.from(blobName)
    ],
    programId
  );
  return pda;
}

/**
 * Derive the access Receipt PDA for a given owner, blob, and user.
 * 
 * Seeds: ["access", owner_aptos_addr, blob_name, user_pubkey]
 * 
 * @param ownerAptosAddr - Owner's Aptos address (32 bytes)
 * @param blobName - Name of the blob
 * @param user - User who purchased access
 * @param programId - access_control program ID
 */
function deriveAccessReceiptPda(
  ownerAptosAddr: Uint8Array,
  blobName: string,
  user: PublicKey,
  programId: PublicKey
): PublicKey {
  const [pda] = PublicKey.findProgramAddressSync(
    [
      Buffer.from("access"),
      Buffer.from(ownerAptosAddr),
      Buffer.from(blobName),
      user.toBuffer()
    ],
    programId
  );
  return pda;
}

/**
 * Wait for a transaction to be fully confirmed.
 * 
 * @param connection - Solana RPC connection
 * @param signature - Transaction signature to confirm
 */
async function confirmTransaction(connection: Connection, signature: string): Promise<void> {
  const latestBlockhash = await connection.getLatestBlockhash();
  await connection.confirmTransaction({
    signature,
    blockhash: latestBlockhash.blockhash,
    lastValidBlockHeight: latestBlockhash.lastValidBlockHeight,
  });
}

/**
 * Convert a hex string to bytes.
 * 
 * @param hex - Hex string (without 0x prefix)
 */
function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error("Invalid hex string");
  }

  const bytes = new Uint8Array(hex.length / 2);

  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }

  return bytes;
}

/**
 * Convert bytes to a hex string.
 * 
 * @param bytes - Byte array
 */
function bytesToHex(bytes: Uint8Array): string {
  return bytes.reduce((str, byte) => str + byte.toString(16).padStart(2, '0'), '');
}

/**
 * Convert a Solana address to an Aptos Derivable Abstracted Account (DAA) address.
 * 
 * This allows Solana users to have a corresponding Aptos identity without
 * needing an actual Aptos account. The derivation uses:
 * - Authentication function: 0x1::solana_derivable_account::authenticate
 * - Domain: explorer.shelby.xyz
 * 
 * @param solanaAddr - Solana public key
 * @returns Aptos account address
 */
function solanaAddrToAptosAddr(solanaAddr: PublicKey): AccountAddress {
  // The authentication function that would validate this derived account
  const functionInfo = "0x1::solana_derivable_account::authenticate";
  // Domain separator for this application
  const domain = "explorer.shelby.xyz";
  
  // Serialize the account identifier: BCS(solana_base58) + BCS(domain)
  const serializer = new Serializer();
  serializer.serializeStr(solanaAddr.toBase58());
  serializer.serializeStr(domain);
  const accountIdentifier = serializer.toUint8Array();
  
  // Compute the Aptos address from the function info and identifier
  const addressBytes = DerivableAbstractedAccount.computeAccountAddress(functionInfo, accountIdentifier);
  return AccountAddress.from(addressBytes);
}

// ============================================================================
// Unit Tests
// ============================================================================

describe("solanaAddrToAptosAddr", () => {
  /**
   * Verify that the Solana→Aptos address derivation matches the expected output.
   * This test case is shared between TypeScript and Rust implementations.
   */
  it("should convert F9E3oTFhkvY5WdjsV33E1pb3FyBe7PHwpT9TVtG7tei7 to 0x9ee58f972ab7e54dfe650b1150cfff406ac6d7de25392540ef4046ca19a5aaab", () => {
    const solanaAddr = new PublicKey("F9E3oTFhkvY5WdjsV33E1pb3FyBe7PHwpT9TVtG7tei7");
    const aptosAddr = solanaAddrToAptosAddr(solanaAddr);
    expect(aptosAddr.toString()).to.equal("0x9ee58f972ab7e54dfe650b1150cfff406ac6d7de25392540ef4046ca19a5aaab");
  });
});
