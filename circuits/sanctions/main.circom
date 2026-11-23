pragma circom 2.1.6;

// DPO2U — sanctions non-membership (Circom lane of compliance-gate).
//
// Proves: the beneficiary's identifier is NOT in the sanctions snapshot whose
// commitment `sanctions_root` is pinned on Stellar, without revealing it.
//
// Entry scheme (same as Midnight TravelRuleGate v12): entries are
//   key = trunc248( Poseidon(pepper, id_hash) ),  id_hash = trunc248(sha256(id))
// with a secret pepper per snapshot, so no brute-forceable identifier hash is
// ever public. The circuit checks Poseidon(pepper) == pepper_commit.
//
// Indexed Merkle tree (credit: ProofOrBluff / @realjohnny5i): leaves are
// (value, next) pairs of the sorted set; non-membership = a leaf with
// value < key < next under the tree root.
//
// sanctions_root = Poseidon(tree_root, pepper_commit, issued_at): issued_at is
// bound to the snapshot, so the prover cannot pick a fresher date.
//
// Public signals (order is the gate's contract, see docs/circuit.md):
//   [sanctions_root, pepper_commit, policy_hash, context, issued_at]
//
// Field: BLS12-381 scalar field (circom -p bls12381). Poseidon uses circomlib's
// constants evaluated in this field (see docs/threat-model.md, limitations).

include "../../node_modules/circomlib/circuits/poseidon.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";

// 1 iff the N-bit little-endian number `bits` is <= ct (ct a constant).
template LeConstant(N, ct) {
    signal input bits[N];
    signal output out;

    signal eq[N + 1];
    signal lt[N + 1];
    eq[N] <== 1;
    lt[N] <== 0;
    for (var i = N - 1; i >= 0; i--) {
        var cbit = (ct >> i) & 1;
        if (cbit == 1) {
            // bit 0 where ct has 1 while still equal => strictly less from here
            lt[i] <== lt[i + 1] + eq[i + 1] * (1 - bits[i]);
            eq[i] <== eq[i + 1] * bits[i];
        } else {
            lt[i] <== lt[i + 1];
            eq[i] <== eq[i + 1] * (1 - bits[i]);
        }
    }
    out <== lt[0] + eq[0];
}

// Canonical low 248 bits of a field element (rejects the 255-bit alias).
template Trunc248() {
    signal input in;
    signal output out;

    component n2b = Num2Bits(255);
    n2b.in <== in;
    // r - 1 for BLS12-381
    component canon = LeConstant(255, 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000);
    for (var i = 0; i < 255; i++) {
        canon.bits[i] <== n2b.out[i];
    }
    canon.out === 1;

    var acc = 0;
    var pow = 1;
    for (var i = 0; i < 248; i++) {
        acc += n2b.out[i] * pow;
        pow = pow * 2;
    }
    out <== acc;
}

template MerkleRoot(D) {
    signal input leaf;
    signal input siblings[D];
    signal input path_bits[D];
    signal output root;

    component h[D];
    signal cur[D + 1];
    signal d[D];
    cur[0] <== leaf;
    for (var i = 0; i < D; i++) {
        path_bits[i] * (path_bits[i] - 1) === 0;
        // path_bits[i] == 1 => current node is the right child
        d[i] <== path_bits[i] * (siblings[i] - cur[i]);
        h[i] = Poseidon(2);
        h[i].inputs[0] <== cur[i] + d[i];
        h[i].inputs[1] <== siblings[i] - d[i];
        cur[i + 1] <== h[i].out;
    }
    root <== cur[D];
}

template SanctionsNonMembership(D) {
    // public (declaration order = public signal order)
    signal input sanctions_root;
    signal input pepper_commit;
    signal input policy_hash;
    signal input context;
    signal input issued_at;

    // private
    signal input id_hash;
    signal input pepper;
    signal input low_value;
    signal input low_next;
    signal input siblings[D];
    signal input path_bits[D];

    // 1. the pepper is the one the provider committed to
    component pc = Poseidon(1);
    pc.inputs[0] <== pepper;
    pc.out === pepper_commit;

    // 2. derive the peppered key from the private identifier hash
    component kh = Poseidon(2);
    kh.inputs[0] <== pepper;
    kh.inputs[1] <== id_hash;
    component key = Trunc248();
    key.in <== kh.out;

    // 3. low_value < key < low_next (all < 2^248)
    component rv = Num2Bits(248);
    rv.in <== low_value;
    component rn = Num2Bits(248);
    rn.in <== low_next;
    component lt1 = LessThan(248);
    lt1.in[0] <== low_value;
    lt1.in[1] <== key.out;
    lt1.out === 1;
    component lt2 = LessThan(248);
    lt2.in[0] <== key.out;
    lt2.in[1] <== low_next;
    lt2.out === 1;

    // 4. the low leaf is in the tree
    component leaf = Poseidon(2);
    leaf.inputs[0] <== low_value;
    leaf.inputs[1] <== low_next;
    component mr = MerkleRoot(D);
    mr.leaf <== leaf.out;
    for (var i = 0; i < D; i++) {
        mr.siblings[i] <== siblings[i];
        mr.path_bits[i] <== path_bits[i];
    }

    // 5. snapshot commitment binds tree root, pepper and issue date
    component sr = Poseidon(3);
    sr.inputs[0] <== mr.root;
    sr.inputs[1] <== pepper_commit;
    sr.inputs[2] <== issued_at;
    sr.out === sanctions_root;

    // 6. bind the inputs that take part in no other constraint, so the proof
    //    is not malleable in them (policy and escrow context)
    signal policy_sq;
    policy_sq <== policy_hash * policy_hash;
    signal context_sq;
    context_sq <== context * context;
}

component main {public [sanctions_root, pepper_commit, policy_hash, context, issued_at]} = SanctionsNonMembership(16);
