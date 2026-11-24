#!/usr/bin/env node
// DPO2U — builds a FICTITIOUS sanctions snapshot (indexed Merkle tree) and the
// circuit input for one beneficiary. Testnet/demo only: no real identities.
//
//   node tools/sanctions-tree/build.mjs [--id <beneficiary-id>] [--issued-at <unix>]
//
// Writes:
//   fixtures/snapshot.json             public part: sanctions_root, pepper_commit, issued_at, size
//   circuits/sanctions/input.json      private + public inputs for `ctg zk prove sanctions`
// The pepper stays in fixtures/snapshot.secret.json (gitignored), as it would
// stay with the list provider in production.
import { createHash, randomBytes } from "node:crypto";
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "../..");
const DEPTH = 16;
const MAX = (1n << 248n) - 1n;

const args = Object.fromEntries(
  process.argv.slice(2).reduce((acc, a, i, all) => (a.startsWith("--") ? [...acc, [a.slice(2), all[i + 1]]] : acc), [])
);

// ---- exact circuit hashes via a compiled helper circuit -------------------
function circomBin() {
  if (process.env.CIRCOM) return process.env.CIRCOM;
  const p = path.join(os.homedir(), ".caatinga/zk-tools/circom/2.1.9/circom-linux-amd64");
  if (existsSync(p)) return p;
  throw new Error("circom not found: run `npx ctg zk build sanctions` once (installs it) or set CIRCOM");
}
const hdir = path.join(here, "hasher/build");
if (!existsSync(path.join(hdir, "main_js/main.wasm"))) {
  mkdirSync(hdir, { recursive: true });
  execFileSync(circomBin(), [path.join(here, "hasher/main.circom"), "--wasm", "-p", "bls12381", "-o", hdir], { stdio: "inherit" });
}
// circom emits CommonJS; this repo is ESM
writeFileSync(path.join(hdir, "main_js/package.json"), '{"type":"commonjs"}\n');
const require = createRequire(import.meta.url);
const wc = await require(path.join(hdir, "main_js/witness_calculator.js"))(readFileSync(path.join(hdir, "main_js/main.wasm")));
async function hashes(a, b = 0n, c = 0n) {
  const w = await wc.calculateWitness({ a, b, c }, true);
  return { h1: w[1], h2: w[2], h3: w[3] }; // outputs follow the constant-1 wire
}
const H1 = async (a) => (await hashes(a)).h1;
const H2 = async (a, b) => (await hashes(a, b)).h2;
const H3 = async (a, b, c) => (await hashes(a, b, c)).h3;

const trunc248 = (x) => x & MAX;
const sha248 = (s) => {
  const h = createHash("sha256").update(s, "utf8").digest();
  h[0] = 0;
  return BigInt("0x" + h.toString("hex"));
};
const R = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001n;

// ---- fictitious list -----------------------------------------------------
const listFile = path.join(root, "fixtures/sanctions-list.fictitious.json");
const list = JSON.parse(readFileSync(listFile, "utf8")).entries;
const secretFile = path.join(root, "fixtures/snapshot.secret.json");
const pepper = existsSync(secretFile)
  ? BigInt(JSON.parse(readFileSync(secretFile, "utf8")).pepper)
  : BigInt("0x" + randomBytes(31).toString("hex")) % R;
writeFileSync(secretFile, JSON.stringify({ pepper: pepper.toString() }, null, 2) + "\n");
const issuedAt = BigInt(args["issued-at"] ?? Math.floor(Date.now() / 1000));

const keyOf = async (id) => trunc248(await H2(pepper, sha248(id)));
const keys = [0n];
for (const id of list) keys.push(await keyOf(id));
keys.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
const leavesKV = keys.map((v, i) => [v, i + 1 < keys.length ? keys[i + 1] : MAX]);
if (leavesKV.length > 2 ** DEPTH) throw new Error("list too large for depth");

// ---- Merkle tree (zero leaf = 0, zero subtrees precomputed) --------------
let level = [];
for (const [v, n] of leavesKV) level.push(await H2(v, n));
const zeros = [0n];
for (let i = 0; i < DEPTH; i++) zeros.push(await H2(zeros[i], zeros[i]));
const levels = [level];
for (let d = 0; d < DEPTH; d++) {
  const cur = levels[d];
  const next = [];
  for (let i = 0; i < Math.ceil(cur.length / 2); i++) {
    const l = cur[2 * i];
    const r = 2 * i + 1 < cur.length ? cur[2 * i + 1] : zeros[d];
    next.push(await H2(l, r));
  }
  levels.push(next.length ? next : [zeros[d + 1]]);
}
const treeRoot = levels[DEPTH][0];
const pepperCommit = await H1(pepper);
const sanctionsRoot = await H3(treeRoot, pepperCommit, issuedAt);

writeFileSync(
  path.join(root, "fixtures/snapshot.json"),
  JSON.stringify(
    {
      note: "FICTITIOUS sanctions snapshot for testnet demos. Entries = trunc248(Poseidon(pepper, trunc248(sha256(id)))).",
      size: list.length,
      depth: DEPTH,
      issued_at: issuedAt.toString(),
      pepper_commit: pepperCommit.toString(),
      sanctions_root: sanctionsRoot.toString(),
    },
    null,
    2
  ) + "\n"
);

// ---- circuit input for one beneficiary -----------------------------------
const id = args.id ?? "BR-DEMO-BENEFICIARY-0001";
const key = await keyOf(id);
const idx = leavesKV.findIndex(([v, n]) => v < key && key < n);
if (idx < 0) {
  console.error(`"${id}" IS on the fictitious list: no non-membership proof exists (expected for a listed party).`);
  process.exit(2);
}
const siblings = [];
const pathBits = [];
let pos = idx;
for (let d = 0; d < DEPTH; d++) {
  const cur = levels[d];
  const sib = pos ^ 1;
  siblings.push((sib < cur.length ? cur[sib] : zeros[d]).toString());
  pathBits.push(String(pos & 1));
  pos >>= 1;
}
const policyHash = BigInt(args["policy-hash"] ?? sha248("travel-rule-fatf@1.0.0+lgpd@1.0.0+cvm@1.0.0"));
const context = BigInt(args.context ?? 0);
const input = {
  sanctions_root: sanctionsRoot.toString(),
  pepper_commit: pepperCommit.toString(),
  policy_hash: policyHash.toString(),
  context: context.toString(),
  issued_at: issuedAt.toString(),
  id_hash: sha248(id).toString(),
  pepper: pepper.toString(),
  low_value: leavesKV[idx][0].toString(),
  low_next: leavesKV[idx][1].toString(),
  siblings,
  path_bits: pathBits,
};
writeFileSync(path.join(root, "circuits/sanctions/input.json"), JSON.stringify(input, null, 2) + "\n");
console.log(JSON.stringify({ sanctions_root: input.sanctions_root, pepper_commit: input.pepper_commit, policy_hash: input.policy_hash, issued_at: input.issued_at, leaf_index: idx }, null, 2));
