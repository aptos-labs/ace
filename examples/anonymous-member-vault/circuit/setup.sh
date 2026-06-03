#!/usr/bin/env bash
# Compile the anonymous membership circuit and run a local Groth16 setup.
#
# Outputs:
#   member_vault_js/member_vault.wasm
#   member_vault_final.zkey
#   vk.json
#
# Prerequisites: circom 2.x on PATH.
set -euo pipefail
cd "$(dirname "$0")"

echo "=== Step 1: install circomlib + snarkjs ==="
npm install

echo ""
echo "=== Step 2: compile circuit ==="
circom member_vault.circom --r1cs --wasm --sym --output . -l node_modules
echo "    -> member_vault.r1cs  member_vault_js/member_vault.wasm  member_vault.sym"

echo ""
echo "=== Step 3: Powers of Tau ceremony (local, BN128, 2^12 constraints) ==="
ENTROPY="anonymous-member-vault-demo-$(date +%s)"
npx snarkjs powersoftau new bn128 12 pot12_0000.ptau -v
npx snarkjs powersoftau contribute pot12_0000.ptau pot12_0001.ptau \
    --name="anonymous member vault demo contribution" -v -e="${ENTROPY}"
npx snarkjs powersoftau prepare phase2 pot12_0001.ptau pot12_final.ptau -v
echo "    -> pot12_final.ptau"

echo ""
echo "=== Step 4: Groth16 Phase 2 setup ==="
npx snarkjs groth16 setup member_vault.r1cs pot12_final.ptau member_vault_0000.zkey
npx snarkjs zkey contribute member_vault_0000.zkey member_vault_final.zkey \
    --name="anonymous member vault demo phase-2 contribution" -v -e="${ENTROPY}-phase2"
echo "    -> member_vault_final.zkey"

echo ""
echo "=== Step 5: export verification key ==="
npx snarkjs zkey export verificationkey member_vault_final.zkey vk.json
echo "    -> vk.json"

echo ""
echo "================================================"
echo "  Circuit setup complete!"
echo ""
echo "  Proving key : circuit/member_vault_final.zkey"
echo "  Verif. key  : circuit/vk.json"
echo "================================================"
