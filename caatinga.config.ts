import { defineConfig } from "@caatinga/core";

// Deploy order (Caatinga resolves it from dependsOn):
//   circom-verifier, midnight-verifier  ->  compliance-gate  ->  compliance-escrow, compliance-dvp
// Contract IDs flow through ${contracts.<name>.contractId}; nothing is copied by hand.
const wasm = (name: string) => `./target/wasm32v1-none/release/${name}.wasm`;

export default defineConfig({
  project: "dpo2u-stellar-compliance-escrow",
  defaultNetwork: "testnet",
  buildRoot: ".",
  contracts: {
    circom_verifier: {
      path: "./contracts/circom-verifier",
      wasm: wasm("circom_verifier"),
      deployArgs: { admin: "${source.address}" },
    },
    midnight_verifier: {
      path: "./contracts/midnight-verifier",
      wasm: wasm("midnight_verifier"),
      deployArgs: { admin: "${source.address}" },
    },
    compliance_gate: {
      path: "./contracts/compliance-gate",
      wasm: wasm("compliance_gate"),
      dependsOn: ["circom_verifier", "midnight_verifier"],
      deployArgs: {
        admin: "${source.address}",
        circom_verifier: "${contracts.circom_verifier.contractId}",
        midnight_verifier: "${contracts.midnight_verifier.contractId}",
      },
    },
    compliance_escrow: {
      path: "./contracts/compliance-escrow",
      wasm: wasm("compliance_escrow"),
      dependsOn: ["compliance_gate"],
      deployArgs: {
        admin: "${source.address}",
        gate: "${contracts.compliance_gate.contractId}",
      },
    },
    compliance_dvp: {
      path: "./contracts/compliance-dvp",
      wasm: wasm("compliance_dvp"),
      dependsOn: ["compliance_gate"],
      deployArgs: {
        gate: "${contracts.compliance_gate.contractId}",
      },
    },
  },
  networks: {
    testnet: {
      rpcUrl: "https://soroban-testnet.stellar.org",
      networkPassphrase: "Test SDF Network ; September 2015",
    },
  },
  zk: {
    circuits: {
      sanctions: {
        path: "./circuits/sanctions",
        protocol: "groth16",
        curve: "bls12381",
        verifierContract: "circom_verifier",
      },
    },
  },
  // Read-only checks run by `ctg wire` / `ctg smoke` after a full deploy:
  // each contract must point at the address Caatinga deployed for its dependency.
  postDeployRead: [
    {
      contract: "compliance_gate",
      method: "circom_verifier",
      kind: "read",
      expect: { matcher: "contains", value: "${contracts.circom_verifier.contractId}" },
    },
    {
      contract: "compliance_escrow",
      method: "gate",
      kind: "read",
      expect: { matcher: "contains", value: "${contracts.compliance_gate.contractId}" },
    },
    {
      contract: "compliance_dvp",
      method: "gate",
      kind: "read",
      expect: { matcher: "contains", value: "${contracts.compliance_gate.contractId}" },
    },
  ],
  smoke: {
    reads: [
      { contract: "compliance_gate", method: "admin", expect: { matcher: "reachable" } },
      { contract: "compliance_escrow", method: "gate", expect: { matcher: "reachable" } },
      { contract: "midnight_verifier", method: "admin", expect: { matcher: "reachable" } },
    ],
  },
});
