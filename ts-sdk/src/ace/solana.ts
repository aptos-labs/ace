// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { Deserializer, Serializer } from "@aptos-labs/ts-sdk";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import { Connection, PublicKey, Transaction, VersionedTransaction } from "@solana/web3.js";
import { Result } from "../result";
import type { FullDecryptionDomain } from "./index";

export class ContractID {
    knownChainName: string; // mainnet-beta/testnet/devnet
    programId: PublicKey;

    constructor({knownChainName, programId}: {knownChainName: string, programId: string}) {
        this.knownChainName = knownChainName;
        this.programId = new PublicKey(programId);
    }

    static deserialize(deserializer: Deserializer): Result<ContractID> {
        const task = (_extra: Record<string, any>) => {
            const knownChainName = deserializer.deserializeStr();
            const programId = new PublicKey(deserializer.deserializeBytes());
            return new ContractID({knownChainName, programId: programId.toBase58()});
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    static fromBytes(bytes: Uint8Array): Result<ContractID> {
        const task = (_extra: Record<string, any>) => {
            const deserializer = new Deserializer(bytes);
            return ContractID.deserialize(deserializer).unwrapOrThrow('SolanaContractID.fromBytes failed with deserialization error');
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    static fromHex(hex: string): Result<ContractID> {
        const task = (_extra: Record<string, any>) => {
            return ContractID.fromBytes(hexToBytes(hex)).unwrapOrThrow('SolanaContractID.fromHex failed with fromBytes error');
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    serialize(serializer: Serializer): void {
        serializer.serializeStr(this.knownChainName);
        serializer.serializeBytes(this.programId.toBytes());
    }

    toBytes(): Uint8Array {
        const serializer = new Serializer();
        this.serialize(serializer);
        return serializer.toUint8Array();
    }

    toHex(): string {
        return bytesToHex(this.toBytes());
    }

    toPrettyMessage(indent: number = 0): string {
        const pad = '  '.repeat(indent);
        return `\n${pad}knownChainName: ${this.knownChainName}\n${pad}programId: ${this.programId.toBase58()}`;
    }
}

export class ProofOfPermission {
    static readonly SCHEME_UNVERSIONED = 0;
    static readonly SCHEME_VERSIONED = 1;

    scheme: number;
    inner: Transaction | VersionedTransaction;

    private constructor(scheme: number, inner: Transaction | VersionedTransaction) {
        this.scheme = scheme;
        this.inner = inner;
    }
    
    static newVersioned(txn: VersionedTransaction): ProofOfPermission {
        return new ProofOfPermission(ProofOfPermission.SCHEME_VERSIONED, txn);
    }

    static newUnversioned(txn: Transaction): ProofOfPermission {
        return new ProofOfPermission(ProofOfPermission.SCHEME_UNVERSIONED, txn);
    }

    static deserialize(deserializer: Deserializer): Result<ProofOfPermission> {
        const task = (extra: Record<string, any>) => {
            const scheme = deserializer.deserializeU8();
            extra['scheme'] = scheme;
            const bytes = deserializer.deserializeBytes();
            if (scheme == ProofOfPermission.SCHEME_VERSIONED) {
                const inner = VersionedTransaction.deserialize(bytes);
                return new ProofOfPermission(ProofOfPermission.SCHEME_VERSIONED, inner);
            } else if (scheme == ProofOfPermission.SCHEME_UNVERSIONED) {
                const inner = Transaction.from(Buffer.from(bytes));
                return new ProofOfPermission(ProofOfPermission.SCHEME_UNVERSIONED, inner);
            } else {
                throw 'SolanaProofOfPermission.deserialize failed with unknown scheme';
            }
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    static fromBytes(bytes: Uint8Array): Result<ProofOfPermission> {
        const task = (_extra: Record<string, any>) => {
            const deserializer = new Deserializer(bytes);
            return ProofOfPermission.deserialize(deserializer).unwrapOrThrow('SolanaProofOfPermission.fromBytes failed with deserialization error');
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    static fromHex(hex: string): Result<ProofOfPermission> {
        const task = (_extra: Record<string, any>) => {
            return ProofOfPermission.fromBytes(hexToBytes(hex)).unwrapOrThrow('SolanaProofOfPermission.fromHex failed with fromBytes error');
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    serialize(serializer: Serializer): void {
        serializer.serializeU8(this.scheme);
        if (this.scheme == ProofOfPermission.SCHEME_VERSIONED) {
            serializer.serializeBytes((this.inner as VersionedTransaction).serialize());
        } else if (this.scheme == ProofOfPermission.SCHEME_UNVERSIONED) {
            serializer.serializeBytes((this.inner as Transaction).serialize());
        }
    }

    toBytes(): Uint8Array {
        const serializer = new Serializer();
        this.serialize(serializer);
        return serializer.toUint8Array();
    }

    toHex(): string {
        return bytesToHex(this.toBytes());
    }
}

export async function verifyPermission({fullDecryptionDomain, proof, rpcEndpoint}: {fullDecryptionDomain: FullDecryptionDomain, proof: ProofOfPermission, rpcEndpoint?: string}): Promise<Result<void>> {
    var extra: Record<string, any> = {};
    try {
        const txn = proof.inner as Transaction | VersionedTransaction;
        const validateTxnResult = validateTxn({txn, fullDecryptionDomain});
        if (!validateTxnResult.isOk) {
          extra['causedBy'] = validateTxnResult.extra;
          throw 'Solana.verifyPermission failed with invalid transaction';
        }
    
        const chainName = fullDecryptionDomain.getSolanaContractID().knownChainName;
        const simulationResult = await assertTransactionSimulationPasses(txn, chainName, rpcEndpoint);
        if (!simulationResult.isOk) {
          extra['causedBy'] = simulationResult.extra;
          throw 'Solana.verifyPermission failed with transaction simulation error';
        }

        return Result.Ok({ value: undefined, extra });
    } catch (error) {
        return Result.Err({ error, extra });
    }
}

/**
 * Ensure the proof-of-permission transaction is valid and matches the decryption domain.
 */
function validateTxn({txn, fullDecryptionDomain}: {txn: Transaction | VersionedTransaction, fullDecryptionDomain: FullDecryptionDomain}): Result<void> {
    try {
      let instructions: Array<{ programId: PublicKey; data: Buffer }>;
  
      if (txn instanceof VersionedTransaction) {
        const message = txn.message;
        instructions = message.compiledInstructions.map(ix => {
          if (ix.programIdIndex >= message.staticAccountKeys.length) {
            throw 'Solana.validateTxn failed with program ID index out of bounds';
          }
          const programId = message.staticAccountKeys[ix.programIdIndex];
          return { programId, data: Buffer.from(ix.data) };
        });
      } else {
        instructions = txn.instructions.map(ix => ({
          programId: ix.programId,
          data: Buffer.from(ix.data)
        }));
      }
    
      if (instructions.length !== 1) throw 'Solana.validateTxn failed with wrong instruction count';
    
      const instruction = instructions[0];
    
      // Check: Ensure txn program matches contractIDV0.programId
      if (!instruction.programId.equals(fullDecryptionDomain.getSolanaContractID().programId)) {
        throw 'Solana.validateTxn failed with program ID mismatch';
      }
    
      // Parse instruction data and ensure parameter equals decryptionContext.domain
      // Anchor instruction format:
      // - First 8 bytes: discriminator (method selector)
      // - Remaining bytes: Borsh-serialized parameters
      // For assert_access(full_blob_name_bytes: Vec<u8>):
      // - After discriminator: 4 bytes (u32 little-endian) for Vec length, then the Vec bytes
      const instructionData = instruction.data;
    
      if (instructionData.length < 12) {
        // must be at least 12 bytes: 8-byte discriminator + 4-byte Vec length
        throw 'Solana.validateTxn failed with instruction data too short';
      }
    
      // Skip 8-byte discriminator
      const paramData = instructionData.slice(8);
      const vecLength = paramData.readUInt32LE(0);
    
      if (paramData.length < 4 + vecLength) throw 'Solana.validateTxn failed with incomplete instruction data';
    
      const domainAsTxnParam = paramData.slice(4, 4 + vecLength);
    
      // Ensure there are no extra bytes after the parameter
      const expectedParamDataLength = 4 + vecLength;
      if (paramData.length > expectedParamDataLength) {
        throw 'Solana.validateTxn failed with extra instruction data bytes';
      }
    
      // Compare with decryptionContext.domain
      if (bytesToHex(domainAsTxnParam) !== bytesToHex(fullDecryptionDomain.domain)) {
        throw 'Solana.validateTxn failed with domain mismatch';
      }

      return Result.Ok({ value: undefined });
    } catch (error) {
      return Result.Err({ error });
    }
}
  
async function assertTransactionSimulationPasses(
    txn: Transaction | VersionedTransaction,
    chainName: string,
    customEndpoint?: string
): Promise<Result<void>> {
    var extra: Record<string, any> = {};
    var error;
    const start = performance.now();
    try {
        let rpcUrl: string;
        if (customEndpoint) {
            rpcUrl = customEndpoint;
        } else if (chainName === 'localnet' || chainName === 'localhost') {
            rpcUrl = 'http://127.0.0.1:8899';
        } else if (chainName === 'devnet') {
            rpcUrl = 'https://api.devnet.solana.com';
        } else if (chainName === 'testnet') {
            rpcUrl = 'https://api.testnet.solana.com';
        } else if (chainName === 'mainnet-beta') {
            rpcUrl = 'https://api.mainnet-beta.solana.com';
        } else {
            extra['chainName'] = chainName;
            throw 'Solana.assertTransactionSimulationPasses failed with unsupported chain name';
        }
        const connection = new Connection(rpcUrl, 'confirmed');
      
        let simulation;
        if (txn instanceof VersionedTransaction) {
            simulation = await connection.simulateTransaction(txn, {
              sigVerify: true,
            });
        } else {
            simulation = await connection.simulateTransaction(txn);
        }
      
        if (simulation.value.err) {
            extra['simulationError'] = simulation.value.err;
            throw 'Solana.assertTransactionSimulationPasses failed with simulation error';
        }
    
    } catch (caught) {
        error = caught;
    } finally {
        extra['executionTimeMs'] = performance.now() - start;
        if (error !== undefined) {
            return Result.Err({ error, extra });
        } else {
            return Result.Ok({ value: undefined, extra });
        }
    }
}

