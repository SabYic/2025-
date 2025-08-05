#!/bin/bash
snarkjs powersoftau new bn128 12 pot12_0000.ptau -v

snarkjs powersoftau contribute pot12_0000.ptau pot12_0001.ptau --name="First contribution" -v

snarkjs powersoftau prepare phase2 pot12_0001.ptau pot12_final.ptau -v

snarkjs groth16 setup myposeidon2.r1cs pot12_final.ptau myposeidon2_0000.zkey

snarkjs zkey contribute myposeidon2_0000.zkey myposeidon2_final.zkey --name="Key Contributor 1" -v

snarkjs zkey export verificationkey myposeidon2_final.zkey verification_key.json

snarkjs groth16 prove myposeidon2_final.zkey witness.wtns proof.json public.json

snarkjs groth16 verify verification_key.json public.json proof.json