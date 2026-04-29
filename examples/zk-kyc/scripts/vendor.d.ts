// Minimal type declarations for libraries without bundled TypeScript types.

declare module 'circomlibjs' {
    interface EddsaSignature {
        R8: [unknown, unknown];
        S: bigint;
    }
    interface Eddsa {
        F: {
            toObject(v: unknown): bigint;
            e(v: bigint | number): unknown;
        };
        prv2pub(privKey: Buffer | Uint8Array): [unknown, unknown];
        signPoseidon(privKey: Buffer | Uint8Array, msg: unknown): EddsaSignature;
    }
    interface Poseidon {
        (inputs: bigint[]): unknown;
        F: {
            toObject(v: unknown): bigint;
        };
    }
    export function buildEddsa(): Promise<Eddsa>;
    export function buildPoseidon(): Promise<Poseidon>;
    export function buildBabyjub(): Promise<unknown>;
}

declare module 'snarkjs' {
    interface Groth16Proof {
        pi_a: string[];
        pi_b: string[][];
        pi_c: string[];
        protocol: string;
        curve: string;
    }
    export const groth16: {
        fullProve(
            input: Record<string, unknown>,
            wasmFile: string,
            zkeyFile: string,
        ): Promise<{ proof: Groth16Proof; publicSignals: string[] }>;
    };
}
