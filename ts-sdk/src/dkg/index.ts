/**
 * Distributedly generate a key-pair for OTP-HMAC Boneh-Franklin BLS12-381 (short public key):
 * Each worker use VSS-bls12381-fr to deal a sub-secret to the committee;
 * once t+1 VSS is done, the secret `s` should be finalized as the sum of the t+1 sub-secrets.
 * A base point is then publicly sampled (probably in the contract), then `s`*base is the public key.
 */
export const SCHEME_0 = 0;

/**
 * Distributedly generate a key-pair for OTP-HMAC Boneh-Franklin BLS12-381 (short identity key).
 */
export const SCHEME_1 = 1;

export class PrivateKey {
    scheme: number;
    inner: any;

    constructor(scheme: number, inner: any) {
        this.scheme = scheme;
        this.inner = inner;
    }
}

export class PublicKey {
    scheme: number;
    inner: any;

    constructor(scheme: number, inner: any) {
        this.scheme = scheme;
        this.inner = inner;
    }
}

export class Session {
    publicKey: PublicKey | undefined;
    //TODO

    constructor(publicKey: PublicKey) {
        this.publicKey = publicKey;
    }
}
