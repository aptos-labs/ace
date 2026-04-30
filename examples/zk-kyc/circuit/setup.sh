#!/usr/bin/env bash
# Compile the KYC circuit and run a local Groth16 trusted setup.
#
# Outputs (all in this directory):
#   kyc_js/kyc.wasm   — WebAssembly witness generator (used at proof time)
#   kyc_final.zkey    — proving key
#   vk.json           — verification key (published on-chain by script 2)
#
# Prerequisites: circom 2.x on PATH.  Install via:
#   curl --proto '=https' --tlsv1.2 https://sh.rustup.rs -sSf | sh
#   cargo install --git https://github.com/iden3/circom.git circom
set -euo pipefail
cd "$(dirname "$0")"

echo "=== Step 1: install circomlib + snarkjs ==="
npm install

echo ""
echo "=== Step 2: compile circuit ==="
circom kyc.circom --r1cs --wasm --sym --output . -l node_modules
echo "    → kyc.r1cs  kyc_js/kyc.wasm  kyc.sym"

echo ""
echo "=== Step 3: Powers of Tau ceremony (local, BN128, 2^15 constraints) ==="
# We generate a fresh ptau locally — no download required, suitable for dev/demo.
# For production you would use a public ceremony (e.g. Hermez or Semaphore ptau).
ENTROPY="zk-kyc-demo-$(date +%s)"
npx snarkjs powersoftau new bn128 15 pot15_0000.ptau -v
npx snarkjs powersoftau contribute pot15_0000.ptau pot15_0001.ptau \
    --name="zk-kyc demo contribution" -v -e="${ENTROPY}"
npx snarkjs powersoftau prepare phase2 pot15_0001.ptau pot15_final.ptau -v
echo "    → pot15_final.ptau"

echo ""
echo "=== Step 4: Groth16 Phase 2 setup ==="
npx snarkjs groth16 setup kyc.r1cs pot15_final.ptau kyc_0000.zkey
npx snarkjs zkey contribute kyc_0000.zkey kyc_final.zkey \
    --name="zk-kyc demo phase-2 contribution" -v -e="${ENTROPY}-phase2"
echo "    → kyc_final.zkey"

echo ""
echo "=== Step 5: export verification key ==="
npx snarkjs zkey export verificationkey kyc_final.zkey vk.json
echo "    → vk.json"

echo ""
echo "================================================"
echo "  Circuit setup complete!"
echo ""
echo "  Proving key : circuit/kyc_final.zkey"
echo "  Verif. key  : circuit/vk.json"
echo "================================================"
