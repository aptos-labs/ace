// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

pragma circom 2.0.0;

include "circomlib/circuits/poseidon.circom";

//
// MemberVaultProof proves:
//
//   1. The prover knows a private member_secret.
//   2. Poseidon(member_secret) is included in the public Merkle root.
//   3. The proof is bound to one ACE label and one ACE request enc_pk through
//      public inputs verified by the Move hook.
//
// Public output:
//   nullifier = Poseidon(member_secret, label_fr, enc_pk_p0, enc_pk_p1, enc_pk_p2)
//               A demo app prints it; a production app can record it if a
//               one-claim-per-request policy is desired.
//
// Public inputs:
//   root
//   label_fr
//   enc_pk_p0, enc_pk_p1, enc_pk_p2
//
// Private inputs:
//   member_secret
//   path_elements[DEPTH]
//   path_indices[DEPTH]  (0 = current node is left child, 1 = right child)
//
template MemberVaultProof(DEPTH) {
    signal input root;
    signal input label_fr;
    signal input enc_pk_p0;
    signal input enc_pk_p1;
    signal input enc_pk_p2;

    signal input member_secret;
    signal input path_elements[DEPTH];
    signal input path_indices[DEPTH];

    signal output nullifier;

    component leaf_hash = Poseidon(1);
    leaf_hash.inputs[0] <== member_secret;

    signal nodes[DEPTH + 1];
    nodes[0] <== leaf_hash.out;

    component hashes[DEPTH];
    signal left[DEPTH];
    signal right[DEPTH];

    for (var i = 0; i < DEPTH; i++) {
        path_indices[i] * (path_indices[i] - 1) === 0;

        left[i] <== nodes[i] + path_indices[i] * (path_elements[i] - nodes[i]);
        right[i] <== path_elements[i] + path_indices[i] * (nodes[i] - path_elements[i]);

        hashes[i] = Poseidon(2);
        hashes[i].inputs[0] <== left[i];
        hashes[i].inputs[1] <== right[i];
        nodes[i + 1] <== hashes[i].out;
    }

    nodes[DEPTH] === root;

    component nullifier_hash = Poseidon(5);
    nullifier_hash.inputs[0] <== member_secret;
    nullifier_hash.inputs[1] <== label_fr;
    nullifier_hash.inputs[2] <== enc_pk_p0;
    nullifier_hash.inputs[3] <== enc_pk_p1;
    nullifier_hash.inputs[4] <== enc_pk_p2;
    nullifier <== nullifier_hash.out;
}

component main {public [root, label_fr, enc_pk_p0, enc_pk_p1, enc_pk_p2]} = MemberVaultProof(3);
