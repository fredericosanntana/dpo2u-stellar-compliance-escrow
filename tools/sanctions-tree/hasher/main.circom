pragma circom 2.1.6;
// Off-chain helper: evaluates the exact Poseidon instances of the circuit
// (circomlib constants, BLS12-381 field) so the tree builder can never drift
// from the circuit.
include "../../../node_modules/circomlib/circuits/poseidon.circom";

template Hasher() {
    signal input a;
    signal input b;
    signal input c;
    signal output h1;
    signal output h2;
    signal output h3;
    component p1 = Poseidon(1);
    p1.inputs[0] <== a;
    h1 <== p1.out;
    component p2 = Poseidon(2);
    p2.inputs[0] <== a;
    p2.inputs[1] <== b;
    h2 <== p2.out;
    component p3 = Poseidon(3);
    p3.inputs[0] <== a;
    p3.inputs[1] <== b;
    p3.inputs[2] <== c;
    h3 <== p3.out;
}

component main = Hasher();
