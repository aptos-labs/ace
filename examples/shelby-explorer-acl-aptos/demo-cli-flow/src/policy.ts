// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Access Policy Types for Shelby Access Control
 * 
 * This module provides TypeScript types that mirror the Move contract's data structures.
 * These are used to serialize access policies and registration info into BCS format
 * for on-chain transactions.
 * 
 * The serialization format must match exactly what the Move contract expects in its
 * deserialization functions (access_policy_from_bytes, regs_from_bytes).
 */

import { AccountAddress, Serializer } from "@aptos-labs/ts-sdk";

// ============================================================================
// Access Policy Scheme Constants
// ============================================================================
// These must match the constants in access_control.move

/** Allowlist mode: only addresses in the list can decrypt */
export const SCHEME_ALLOWLIST = 0;

/** TimeLock mode: anyone can decrypt after the locked_until timestamp */
export const SCHEME_TIMELOCK = 1;

/** PayToDownload mode: users must pay the price to gain access */
export const SCHEME_PAY_TO_DOWNLOAD = 2;

// ============================================================================
// AccessPolicy Class
// ============================================================================

/**
 * Represents an access control policy for an encrypted blob.
 * 
 * This is the TypeScript equivalent of the Move enum:
 * ```move
 * enum AccessPolicy {
 *     Allowlist { addresses: vector<address> }
 *     TimeLock { locked_until: u64 }
 *     PayToDownload { price: u64 }
 * }
 * ```
 * 
 * BCS serialization format:
 * - 1 byte: scheme (variant tag)
 * - N bytes: variant-specific data
 */
export class AccessPolicy {
    /** The scheme/variant tag (SCHEME_ALLOWLIST, SCHEME_TIMELOCK, or SCHEME_PAY_TO_DOWNLOAD) */
    scheme: number;
    
    /** The inner policy data (type depends on scheme) */
    inner: Allowlist | TimeLock | PayToDownload;

    constructor(scheme: number, inner: Allowlist | TimeLock | PayToDownload) {
        this.scheme = scheme;
        this.inner = inner;
    }

    /**
     * Create an allowlist policy.
     * Only the owner and addresses in the list can decrypt.
     * 
     * @param addresses - Array of addresses allowed to decrypt (empty = owner only)
     */
    static newAllowlist(addresses: AccountAddress[]): AccessPolicy {
        return new AccessPolicy(SCHEME_ALLOWLIST, new Allowlist(addresses));
    }

    /**
     * Create a time lock policy.
     * Anyone can decrypt after the specified timestamp.
     * 
     * @param lockedUntil - Unix timestamp in microseconds after which decryption is allowed
     */
    static newTimeLock(lockedUntil: number): AccessPolicy {
        return new AccessPolicy(SCHEME_TIMELOCK, new TimeLock(lockedUntil));
    }

    /**
     * Create a pay-to-download policy.
     * Users must purchase access to decrypt.
     * 
     * @param price - Price in octas (1 APT = 100,000,000 octas)
     */
    static newPayToDownload(price: number): AccessPolicy {
        return new AccessPolicy(SCHEME_PAY_TO_DOWNLOAD, new PayToDownload(price));
    }

    /**
     * Serialize the policy to BCS format.
     * Format: [scheme: u8][inner data]
     */
    serialize(serializer: Serializer): void {
        serializer.serializeU8(this.scheme);
        this.inner.serialize(serializer);   
    }

    /**
     * Convert to BCS bytes for passing to Move entry functions.
     */
    toBytes(): Uint8Array {
        const serializer = new Serializer();
        this.serialize(serializer);
        return serializer.toUint8Array();
    }
}

// ============================================================================
// Policy Variant Classes
// ============================================================================

/**
 * Allowlist policy data.
 * Contains a list of addresses that are allowed to decrypt.
 * 
 * BCS serialization format:
 * - ULEB128: length of addresses array
 * - For each address: 32 bytes (account address)
 */
export class Allowlist {
    /** Addresses allowed to decrypt (owner is always implicitly allowed) */
    addresses: AccountAddress[];

    constructor(addresses: AccountAddress[]) {
        this.addresses = addresses;
    }

    serialize(serializer: Serializer): void {
        // Serialize as a vector: length prefix + elements
        serializer.serializeU32AsUleb128(this.addresses.length);
        for (const address of this.addresses) {
            serializer.serialize(address);
        }
    }

    toBytes(): Uint8Array {
        const serializer = new Serializer();
        this.serialize(serializer);
        return serializer.toUint8Array();
    }
}

/**
 * TimeLock policy data.
 * Specifies a timestamp after which anyone can decrypt.
 * 
 * BCS serialization format:
 * - u64: locked_until timestamp in microseconds
 */
export class TimeLock {
    /** Timestamp (in microseconds) after which decryption is allowed for everyone */
    lockedUntil: number;

    constructor(lockedUntil: number) {
        this.lockedUntil = lockedUntil;
    }

    serialize(serializer: Serializer): void {
        serializer.serializeU64(this.lockedUntil);
    }

    toBytes(): Uint8Array {
        const serializer = new Serializer();
        this.serialize(serializer);
        return serializer.toUint8Array();
    }
}

/**
 * PayToDownload policy data.
 * Specifies a price users must pay to gain access.
 * 
 * BCS serialization format:
 * - u64: price in octas
 */
export class PayToDownload {
    /** Price in octas (1 APT = 100,000,000 octas) */
    price: number;

    constructor(price: number) {
        this.price = price;
    }

    serialize(serializer: Serializer): void {
        serializer.serializeU64(this.price);
    }

    toBytes(): Uint8Array {
        const serializer = new Serializer();
        this.serialize(serializer);
        return serializer.toUint8Array();
    }
}

// ============================================================================
// Registration Info
// ============================================================================

/**
 * Information needed to register a new blob on-chain.
 * 
 * This is the TypeScript equivalent of the Move struct:
 * ```move
 * struct RegistrationInfo {
 *     blob_name_suffix: String,
 *     access_policy: AccessPolicy,
 * }
 * ```
 * 
 * The full blob name is constructed on-chain as:
 * `@<owner_address_without_0x>/<blob_name_suffix>`
 * 
 * BCS serialization format:
 * - String: blob_name_suffix (ULEB128 length + UTF-8 bytes)
 * - AccessPolicy: access_policy
 */
export class RegistrationInfo {
    /** 
     * The blob name suffix (e.g., "star-wars.mov" or "movies/star-wars.mov").
     * Combined with owner address on-chain to form the full blob name.
     */
    blobNameSuffix: string;
    
    /** The initial access policy for this blob */
    accessPolicy: AccessPolicy;

    constructor(blobNameSuffix: string, accessPolicy: AccessPolicy) {
        this.blobNameSuffix = blobNameSuffix;
        this.accessPolicy = accessPolicy;
    }

    serialize(serializer: Serializer): void {
        serializer.serializeStr(this.blobNameSuffix);
        this.accessPolicy.serialize(serializer);
    }

    toBytes(): Uint8Array {
        const serializer = new Serializer();
        this.serialize(serializer);
        return serializer.toUint8Array();
    }
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Serialize an array of RegistrationInfo to BCS bytes.
 * Used for batch registration of multiple blobs in a single transaction.
 * 
 * BCS serialization format:
 * - ULEB128: length of array
 * - For each RegistrationInfo: serialized registration data
 * 
 * @param regs - Array of registration info objects
 * @returns BCS-serialized bytes to pass to register_blobs entry function
 */
export function regsToBytes(regs: RegistrationInfo[]): Uint8Array {
    const serializer = new Serializer();
    // Serialize as a vector: length prefix + elements
    serializer.serializeU32AsUleb128(regs.length);
    for (const reg of regs) {
        reg.serialize(serializer);
    }
    return serializer.toUint8Array();
}
