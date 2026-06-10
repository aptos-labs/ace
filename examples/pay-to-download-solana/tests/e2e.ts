// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Pay-to-Download Solana — end-to-end test.
 *
 * Demonstrates ACE direct-encryption + Solana on-chain access control:
 *
 *  1. Alice (content owner) encrypts a content payload directly with ACE.
 *  2. Alice registers the ciphertext on-chain with a price.
 *  3. Bob (consumer) tries to decrypt without payment → fails.
 *  4. Bob purchases access by paying Alice.
 *  5. Bob builds a proof-of-permission by signing a Solana transaction
 *     that calls `ace_hook::assert_access`.
 *  6. Bob requests decryption key shares from ACE workers (they simulate
 *     the txn against Solana to verify on-chain access).
 *  7. Bob aggregates the shares and decrypts the ciphertext back to the
 *     original content.
 *
 * Note on the encryption model: ACE encrypts the content directly. There
 * is *no* intermediate symmetric-key wrapping layer — with ACE's current
 * default t-IBE scheme, direct encryption of reasonable-sized payloads is
 * the recommended pattern.
 *
 * Prerequisites:
 * - ACE global network running (Aptos localnet + workers):
 *   `cd scenarios && pnpm run-local-network-forever`
 *   (wait until the terminal prints "ACE local network is READY")
 * - Then in a second terminal:
 *   `cd examples/pay-to-download-solana && pnpm test:localnet`
 */

import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { AccessControl } from "../target/types/access_control";
import { AceHook } from "../target/types/ace_hook";
import {
  Connection,
  Keypair,
  LAMPORTS_PER_SOL,
  PublicKey,
  TransactionMessage,
  VersionedTransaction,
} from "@solana/web3.js";
import { expect } from "chai";
import * as ACE from "@aptos-labs/ace-sdk";
import { Result } from "@aptos-labs/ace-sdk";
import { AccountAddress, Serializer, DerivableAbstractedAccount } from "@aptos-labs/ts-sdk";
import { existsSync, readFileSync } from "fs";

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
   * 1. Encrypt a content payload directly with ACE → ciphertext
   * 2. Register the ciphertext on-chain with a price
   *
   * DOWNLOAD FLOW (Bob):
   * 1. Try to decrypt without payment (should fail)
   * 2. Purchase access by paying Alice
   * 3. Create proof-of-permission (signed transaction)
   * 4. Request decryption key shares from ACE workers
   * 5. Decrypt ciphertext → original content
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

    // The content payload Alice is selling. For demo purposes this is a
    // fixed 32-byte blob; in a real app it could be a license code, a
    // signed download token, a premium-content payload, etc. — anything
    // small enough to encrypt directly with ACE.
    const secretContentHex = "a3f7b2c9e1d84f6a0b5c3e2d1f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a";
    const secretContent = hexToBytes(secretContentHex);

    // Load ACE config (aceDeployment, keypair_ids, knownChainName) via the
    // shared loader — same one the failures suite uses below.
    const { aceDeployment, keypairIds, knownChainName } = loadAceConfig(connection);
    const keypairId = keypairIds[0]!;
    console.log(`ACE contract: ${aceDeployment.contractAddr.toStringLong()}`);
    console.log(`IBE keypair:  ${keypairId.toString()}`);
    
    // ========================================================================
    // Step 3: Alice Encrypts Content with ACE
    // ========================================================================

    console.log("\n=== Alice: Encrypt and Register ===");
    console.log("(2a.1) Encrypting content directly with ACE...");

    const aliceAptosAddrBytes = aliceAptosAddr.toUint8Array();

    // Full blob name format: "0x" + owner_aptos_addr (32 bytes) + "/" + blob_name
    // This uniquely identifies the blob across the system
    const fullBlobNameBytes = Buffer.concat([
      Buffer.from("0x"),                      // 2 bytes: prefix
      Buffer.from(aliceAptosAddrBytes),       // 32 bytes: owner address
      Buffer.from("/"),                       // 1 byte: separator
      Buffer.from(fileName),                  // N bytes: file name
    ]);

    // Encrypt the content directly with ACE. The ciphertext can only be
    // decrypted by users who pass the on-chain access check.
    const ciphertext: Uint8Array = unwrapResult(await ACE.IBE_Solana.encrypt({
      aceDeployment,
      keypairId,
      knownChainName,
      programId: accessControlProgram.programId.toBase58(),
      label: fullBlobNameBytes,
      plaintext: secretContent,
    }), `failed to encrypt via ACE at ${aceDeployment.apiEndpoint}`);

    // ========================================================================
    // Step 4: Alice Registers the Listing On-Chain
    // ========================================================================
    //
    // Only the listing metadata (price + seqnum) goes on-chain. The
    // ciphertext stays in Alice's local possession — in a real app she'd
    // upload it to her chosen storage (CDN / IPFS / direct upload after
    // purchase / etc.) and Bob would retrieve it from there. For this
    // test we just keep it as a closure variable.

    console.log("(2a.2) Alice registering listing on-chain...");

    const price = new anchor.BN(0.0005 * LAMPORTS_PER_SOL);  // 0.0005 SOL

    await registerBlobListing({
      owner: alice,
      ownerAptosAddrBytes: aliceAptosAddrBytes,
      fileName,
      price,
      program,
      connection,
    });
    console.log("✓ Listing registered on-chain (ciphertext kept off-chain)");

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
    async function bobDecryptLegacyTxn(): Promise<Result<Uint8Array>> {
      const session = await ACE.IBE_Solana.BasicDecryptionSession.create({
        aceDeployment,
        keypairId,
        knownChainName,
        programId: accessControlProgram.programId.toBase58(),
        label: fullBlobNameBytes,
        ciphertext,
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

    async function bobDecryptVersionedTxn(): Promise<Result<Uint8Array>> {
      const session = await ACE.IBE_Solana.BasicDecryptionSession.create({
        aceDeployment,
        keypairId,
        knownChainName,
        programId: accessControlProgram.programId.toBase58(),
        label: fullBlobNameBytes,
        ciphertext,
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
    const bobAttempt0Result = await bobDecryptLegacyTxn();
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

    // Wait until the worker's view of the receipt PDA shows program ownership.
    // `confirmTransaction` returns at "confirmed" commitment, but Solana account-state
    // propagation to the simulator can lag behind the txn confirmation by several seconds
    // on slow runners — workers see receipt.owner = system program (11111...111) and
    // assert_access fails with InvalidAccountOwner. Poll until the program owns it,
    // then a small grace delay for any remaining replicas.
    const receiptPda = deriveAccessReceiptPda(aliceAptosAddrBytes, fileName, bob.publicKey, program.programId);
    const expectedOwner = accessControlProgram.programId.toBase58();
    const pollDeadlineMs = Date.now() + 30_000;
    while (Date.now() < pollDeadlineMs) {
      const info = await connection.getAccountInfo(receiptPda, 'confirmed');
      if (info && info.owner.toBase58() === expectedOwner) break;
      await new Promise(r => setTimeout(r, 250));
    }
    // Small extra grace for the worker's RPC view (independent connection).
    await new Promise(resolve => setTimeout(resolve, 500));
    console.log("✓ Purchase complete - Receipt PDA created");

    // ========================================================================
    // Step 7: Bob Successfully Decrypts
    // ========================================================================
    
    console.log("\n=== Bob: Decrypt with Permission ===");
    
    // Test with legacy transaction format
    console.log("Bob attempting to decrypt with legacy transaction...");
    const bobAttempt1Result = await bobDecryptLegacyTxn();
    console.log('Result:', bobAttempt1Result.isOk ? 'SUCCESS' : 'FAILED');
    const plaintext1 = bobAttempt1Result.unwrapOrThrow('attempt 1 should succeed');
    expect(bytesToHex(plaintext1)).to.equal(secretContentHex);
    console.log("✓ Decrypted successfully with legacy transaction");

    // Test with versioned transaction format
    console.log("Bob attempting to decrypt with versioned transaction...");
    const bobAttempt2Result = await bobDecryptVersionedTxn();
    console.log('Result:', bobAttempt2Result.isOk ? 'SUCCESS' : 'FAILED');
    const plaintext2 = bobAttempt2Result.unwrapOrThrow('attempt 2 should succeed');
    expect(bytesToHex(plaintext2)).to.equal(secretContentHex);
    console.log("✓ Decrypted successfully with versioned transaction");

    // ========================================================================
    // Test Complete
    // ========================================================================

    console.log("\n=== All tests passed! ===");
    console.log("Summary:");
    console.log("  1. ✓ Alice encrypted content directly with ACE");
    console.log("  2. ✓ Alice registered ciphertext on-chain with price");
    console.log("  3. ✓ Bob was denied decryption (no receipt)");
    console.log("  4. ✓ Bob purchased access (Receipt created)");
    console.log("  5. ✓ Bob decrypted ciphertext → content (legacy tx)");
    console.log("  6. ✓ Bob decrypted ciphertext → content (versioned tx)");
  });
});

// ============================================================================
// Access-Control Failures (worker-side rejection)
// ============================================================================
//
// Solana counterpart to the Aptos 5-step access-failure matrix used by
// `scenarios/test-access-failures-*.ts`. The worker must reject when:
//   A. The `keypair_id` in the request doesn't correspond to any DKG'd secret.
//   B. The caller has no on-chain access record. (Already covered by "Bob
//      attempts to decrypt without payment" inside the happy-path test above.)
//   C. The session's `domain` doesn't match what the ciphertext was encrypted
//      under — the in-program PDA derivation no longer matches the supplied
//      `blob_metadata` / `receipt` accounts, so chain simulation aborts.
//   D. (happy path — covered above)
//   E. The submitted Solana txn carries a mauled signature — `simulateTransaction`
//      runs with `sigVerify: true` (see `worker-components/network-node/src/verify/solana.rs::simulate_txn`),
//      so the RPC rejects before program execution.
//
// One `before()` sets up Alice + Bob + a registered blob + Bob's paid receipt
// (everything needed for a *valid* request); each `it()` mutates one input
// and asserts worker rejection.

describe("access-control failures (worker-side rejection)", () => {
  anchor.setProvider(anchor.AnchorProvider.env());
  const program = anchor.workspace.accessControl as Program<AccessControl>;
  const accessControlProgram = anchor.workspace.aceHook as Program<AceHook>;
  const provider = anchor.AnchorProvider.env();

  let connection: Connection;
  let alice: Keypair;
  let bob: Keypair;
  let aliceAptosAddrBytes: Uint8Array;
  // `domain` is the ACE SDK term (passed to `SolanaBasicFlow.encrypt({domain})`).
  // For pay-to-download specifically, the bytes encode `"0x" + owner_aptos_addr
  // + "/" + blob_name` so the on-chain program can recover the blob identity.
  let domain: Buffer;
  let ciphertext: Uint8Array;
  let aceDeployment: ACE.AceDeployment;
  // Two DKG'd keypair_ids — both real and on-chain-known. This suite uses
  // [0] for encryption / happy-path verification and [1] as the
  // "mismatching" identifier in step A (drives the worker's keypair_id
  // check rather than the SDK's pre-flight `fetchCurrentSessionPks` throw).
  // Populated by `test-solana-example.ts` (writes the list into the config).
  let keypairId: AccountAddress;
  let mismatchingKeypairId: AccountAddress | undefined;
  let knownChainName: string;

  // Distinct from the happy-path file name so the two suites' PDAs don't
  // collide on the same localnet validator.
  const FILE_NAME = "failure-test.mov";

  before(async function () {
    this.timeout(180_000);
    connection = provider.connection;
    alice = Keypair.generate();
    bob = Keypair.generate();
    aliceAptosAddrBytes = solanaAddrToAptosAddr(alice.publicKey).toUint8Array();
    await fundAccounts(connection, [alice, bob], 0.1 * LAMPORTS_PER_SOL);
    let keypairIds: AccountAddress[];
    ({ aceDeployment, keypairIds, knownChainName } = loadAceConfig(connection));
    if (!keypairIds[0]) {
      throw new Error("ACE config must include at least one IBE keypair ID");
    }
    keypairId = keypairIds[0];
    mismatchingKeypairId = keypairIds[1];
    ({ ciphertext, domain } = await aliceEncryptAndRegisterBlob({
      alice, aliceAptosAddrBytes, fileName: FILE_NAME,
      aceDeployment, keypairId, knownChainName,
      accessControlProgramId: accessControlProgram.programId,
      program, connection,
    }));
    await bobPurchaseAndWaitForReceipt({
      bob, alice, aliceAptosAddrBytes, fileName: FILE_NAME,
      program, accessControlProgram, connection,
    });
  });

  /** Build a (well-formed, signed) `assert_access` txn for Bob → Alice's
   *  blob. Returns the session + raw bytes so individual `it()` blocks can
   *  override `sessionKeypairId` / `sessionDomain` (steps A and C) or maul
   *  the bytes after signing (step E). */
  async function buildBobAccessTxn(args: {
    sessionDomain?: Buffer;
    sessionKeypairId?: AccountAddress;
  } = {}): Promise<{
    session: ACE.IBE_Solana.BasicDecryptionSession;
    txnBytes: Uint8Array;
  }> {
    const session = await ACE.IBE_Solana.BasicDecryptionSession.create({
      aceDeployment,
      keypairId: args.sessionKeypairId ?? keypairId,
      knownChainName,
      programId: accessControlProgram.programId.toBase58(),
      label: args.sessionDomain ?? domain,
      ciphertext,
    });
    const fullRequestBytes = await session.getRequestToSign();
    const txn = await accessControlProgram.methods
      .assertAccess(Buffer.from(fullRequestBytes))
      .accounts({
        blobMetadata: deriveBlobMetadataPda(aliceAptosAddrBytes, FILE_NAME, program.programId),
        receipt: deriveAccessReceiptPda(aliceAptosAddrBytes, FILE_NAME, bob.publicKey, program.programId),
        user: bob.publicKey,
      })
      .transaction();
    txn.feePayer = bob.publicKey;
    const { blockhash } = await connection.getLatestBlockhash();
    txn.recentBlockhash = blockhash;
    txn.sign(bob);
    return { session, txnBytes: txn.serialize() };
  }

  it("step A: rejects decrypt under a real but mismatching keypair_id", async function () {
    this.timeout(60_000);
    // `mismatchingKeypairId` is a real, DKG'd on-chain secret — just not
    // the one the ciphertext was encrypted under. This drives the request
    // past the SDK's pre-flight network-state check and into the actual
    // share-aggregation / TIBE-decrypt path; the resulting IDK is for the
    // wrong identity, so decrypt fails on the integrity check.
    if (!mismatchingKeypairId) {
      this.skip();
      return;
    }
    const { session, txnBytes } = await buildBobAccessTxn({ sessionKeypairId: mismatchingKeypairId });
    const result = await session.decryptWithProof({ txn: txnBytes });
    expect(result.isOk).to.equal(
      false,
      `Expected decrypt to fail under a mismatching keypair_id, but it succeeded`,
    );
    console.log(`  ✓ rejected (${result.errValue})`);
  });

  it("step C: rejects decrypt with wrong domain (wrong blob name in session)", async function () {
    this.timeout(60_000);
    // Ciphertext was encrypted under the registered blob's `domain` bytes
    // (which encode `0x<owner>/<blob_name>` for pay-to-download). A session
    // that claims a different blob name builds a request whose embedded
    // `full_request_bytes` reference the wrong blob; the chain's
    // `assert_access` derives the expected PDA from those bytes and finds
    // it doesn't match the supplied `blob_metadata` account.
    const wrongDomain = Buffer.concat([
      Buffer.from("0x"),
      Buffer.from(aliceAptosAddrBytes),
      Buffer.from("/"),
      Buffer.from("other-blob"),
    ]);
    const { session, txnBytes } = await buildBobAccessTxn({ sessionDomain: wrongDomain });
    const result = await session.decryptWithProof({ txn: txnBytes });
    expect(result.isOk).to.equal(
      false,
      `Expected decrypt to fail with wrong domain, but it succeeded`,
    );
    console.log(`  ✓ rejected (${result.errValue})`);
  });

  it("step E: rejects decrypt with mauled txn signature", async function () {
    this.timeout(60_000);
    const { session, txnBytes } = await buildBobAccessTxn();
    // Solana legacy txn layout: [compact-u16 sig_count][N * 64B signatures][message].
    // For one signer sig_count = 0x01 (1 byte), so the first signature byte
    // lives at offset 1. Flipping a bit there leaves the structural shape
    // intact — the worker's `validate_txn` parses cleanly — but breaks the
    // Ed25519 verify the Solana RPC performs during `simulateTransaction`
    // (we run with `sigVerify: true`).
    const mauled = new Uint8Array(txnBytes);
    mauled[1] ^= 0x01;
    const result = await session.decryptWithProof({ txn: mauled });
    expect(result.isOk).to.equal(
      false,
      `Expected decrypt to fail with mauled txn signature, but it succeeded`,
    );
    console.log(`  ✓ rejected (${result.errValue})`);
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
  const isLocalnet = isLocalnetConnection(connection);
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

function isLocalnetConnection(connection: Connection): boolean {
  return connection.rpcEndpoint.includes('localhost') ||
    connection.rpcEndpoint.includes('127.0.0.1');
}

/** Load ACE config (aceDeployment + the list of DKG'd IBE keypair IDs +
 *  knownChainName). Sources, in order:
 *    - env vars: ACE_CONTRACT + KEYPAIR_IDS (comma-separated), IBE_KEYPAIR_ID,
 *      or legacy KEYPAIR_ID.
 *    - testnet: SDK known deployment preview20260610.
 *    - localnet: /tmp/ace-localnet-config.json written by either
 *      `test-solana-example.ts` (writes `keypairIds: string[]`, two entries)
 *      or `run-local-network-forever.ts` (writes `keypairId: string`, one).
 *  Returns a `keypairIds: AccountAddress[]` list; callers index per their own
 *  convention (happy-path uses [0]; failures step A uses [1] when present). */
function loadAceConfig(connection: Connection): {
  aceDeployment: ACE.AceDeployment;
  keypairIds: AccountAddress[];
  knownChainName: string;
} {
  const isLocalnet = isLocalnetConnection(connection);
  const knownChainName = isLocalnet ? "localnet" : "testnet";
  const envKeypairIds = process.env.KEYPAIR_IDS ?? process.env.IBE_KEYPAIR_ID ?? process.env.KEYPAIR_ID;
  if (process.env.ACE_CONTRACT && envKeypairIds) {
    return {
      aceDeployment: new ACE.AceDeployment({
        apiEndpoint: process.env.ACE_API_ENDPOINT ??
          (isLocalnet ? "http://localhost:8080/v1" : "https://api.testnet.aptoslabs.com/v1"),
        contractAddr: AccountAddress.fromString(process.env.ACE_CONTRACT),
      }),
      keypairIds: envKeypairIds.split(',').map(s => AccountAddress.fromString(s.trim())),
      knownChainName,
    };
  }

  if (!isLocalnet) {
    const known = ACE.knownDeployments.preview20260610;
    return {
      aceDeployment: known.aceDeployment,
      keypairIds: [known.ibeKeypairId],
      knownChainName,
    };
  }

  const localnetConfigPath = '/tmp/ace-localnet-config.json';
  if (!existsSync(localnetConfigPath)) {
    throw new Error(
      `Missing ${localnetConfigPath}. Start ACE with ` +
      '`cd scenarios && pnpm run-local-network-forever` before running `pnpm test:localnet`.',
    );
  }
  const cfg = JSON.parse(readFileSync(localnetConfigPath, 'utf8')) as
    Partial<{ apiEndpoint: string; contractAddr: string; keypairIds: string[]; ibeKeypairId: string; keypairId: string }>;
  const idStrings = cfg.keypairIds ?? (cfg.ibeKeypairId ? [cfg.ibeKeypairId] : cfg.keypairId ? [cfg.keypairId] : []);
  if (!cfg.apiEndpoint || !cfg.contractAddr || idStrings.length === 0) {
    throw new Error(
      'Malformed /tmp/ace-localnet-config.json. Start ACE with ' +
      '`cd scenarios && pnpm run-local-network-forever` before running `pnpm test:localnet`.',
    );
  }
  return {
    aceDeployment: new ACE.AceDeployment({
      apiEndpoint: cfg.apiEndpoint,
      contractAddr: AccountAddress.fromString(cfg.contractAddr),
    }),
    keypairIds: idStrings.map(s => AccountAddress.fromString(s)),
    knownChainName,
  };
}

/** Alice encrypts a fixed plaintext under (keypairId, domain) via ACE,
 *  then registers the resulting ciphertext on-chain with a small price.
 *  Returns the ciphertext + the ACE-SDK `domain` bytes (for pay-to-download
 *  these bytes encode `0x<owner_aptos_addr>/<file_name>`) so callers can
 *  build matching decryption sessions. */
async function aliceEncryptAndRegisterBlob(args: {
  alice: Keypair;
  aliceAptosAddrBytes: Uint8Array;
  fileName: string;
  aceDeployment: ACE.AceDeployment;
  keypairId: AccountAddress;
  knownChainName: string;
  accessControlProgramId: PublicKey;
  program: Program<AccessControl>;
  connection: Connection;
}): Promise<{ ciphertext: Uint8Array; domain: Buffer }> {
  const plaintext = hexToBytes(
    "a3f7b2c9e1d84f6a0b5c3e2d1f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a",
  );
  const domain = Buffer.concat([
    Buffer.from("0x"), Buffer.from(args.aliceAptosAddrBytes),
    Buffer.from("/"), Buffer.from(args.fileName),
  ]);
  const ciphertext: Uint8Array = unwrapResult(await ACE.IBE_Solana.encrypt({
    aceDeployment: args.aceDeployment,
    keypairId: args.keypairId,
    knownChainName: args.knownChainName,
    programId: args.accessControlProgramId.toBase58(),
    label: domain,
    plaintext,
  }), `aliceEncryptAndRegisterBlob: encrypt failed via ACE at ${args.aceDeployment.apiEndpoint}`);
  // Only the listing (price + seqnum) goes on-chain; the ciphertext stays
  // in-memory (returned to caller so it can be handed to Bob — modeling
  // the "Alice delivers ciphertext to Bob off-chain" step).
  await registerBlobListing({
    owner: args.alice,
    ownerAptosAddrBytes: args.aliceAptosAddrBytes,
    fileName: args.fileName,
    price: new anchor.BN(0.0005 * LAMPORTS_PER_SOL),
    program: args.program,
    connection: args.connection,
  });
  return { ciphertext, domain };
}

async function registerBlobListing(args: {
  owner: Keypair;
  ownerAptosAddrBytes: Uint8Array;
  fileName: string;
  price: anchor.BN;
  program: Program<AccessControl>;
  connection: Connection;
}): Promise<void> {
  const signature = await args.program.methods
    .registerBlob(
      Array.from(args.ownerAptosAddrBytes),
      args.fileName,
      args.price,
    )
    .accounts({ owner: args.owner.publicKey })
    .signers([args.owner])
    .rpc();
  await confirmTransaction(args.connection, signature);
}

function unwrapResult<T>(result: Result<T>, context: string): T {
  if (result.isOk) return result.okValue!;
  const detail = formatError(result.errValue);
  const hint = detail.includes('ECONNREFUSED')
    ? ' Hint: start ACE with `cd scenarios && pnpm run-local-network-forever`, wait until the terminal prints `ACE local network is READY`, then run `pnpm test:localnet` in this example.'
    : '';
  throw new Error(`${context}: ${detail}${hint}`);
}

function formatError(err: unknown): string {
  if (err instanceof Error) {
    const code = 'code' in err ? ` ${(err as { code?: string }).code}` : '';
    return `${err.name}${code}: ${err.message}`;
  }
  if (typeof err === 'object' && err !== null) {
    const maybe = err as { name?: string; code?: string; message?: string };
    if (maybe.name || maybe.code || maybe.message) {
      return [maybe.name, maybe.code, maybe.message].filter(Boolean).join(' ');
    }
  }
  return String(err);
}

/** Bob calls `purchase` on `access_control` (transfers SOL to Alice +
 *  creates the Receipt PDA), then polls until the Receipt PDA's on-chain
 *  owner reflects program ownership. The poll matches the happy-path
 *  test's propagation-lag mitigation: confirmTransaction returns at
 *  "confirmed" commitment, but workers' RPC view can take a few extra
 *  seconds to see the new account-state. */
async function bobPurchaseAndWaitForReceipt(args: {
  bob: Keypair;
  alice: Keypair;
  aliceAptosAddrBytes: Uint8Array;
  fileName: string;
  program: Program<AccessControl>;
  accessControlProgram: Program<AceHook>;
  connection: Connection;
}): Promise<void> {
  const purchaseTxn = await args.program.methods
    .purchase(Array.from(args.aliceAptosAddrBytes), args.fileName)
    .accounts({ buyer: args.bob.publicKey, owner: args.alice.publicKey })
    .signers([args.bob]).rpc();
  await confirmTransaction(args.connection, purchaseTxn);
  const receiptPda = deriveAccessReceiptPda(
    args.aliceAptosAddrBytes, args.fileName, args.bob.publicKey, args.program.programId,
  );
  const expectedOwner = args.accessControlProgram.programId.toBase58();
  const pollDeadline = Date.now() + 30_000;
  while (Date.now() < pollDeadline) {
    const info = await args.connection.getAccountInfo(receiptPda, 'confirmed');
    if (info && info.owner.toBase58() === expectedOwner) break;
    await new Promise(r => setTimeout(r, 250));
  }
  await new Promise(r => setTimeout(r, 500));
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
