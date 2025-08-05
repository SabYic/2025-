pragma circom 2.0.0;

include "./poseidon2_circuit/circomlib/circuits/poseidon.circom";  

template Poseidon2Hash3() {
    signal input in;      // 隐私输入（原象）
    signal output out;

    component poseidon = Poseidon(1);   

    poseidon.inputs[0] <== in;
    out <== poseidon.out;

   // expected === out;
}
component main = Poseidon2Hash3();
