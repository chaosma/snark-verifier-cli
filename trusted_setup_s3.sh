#!/bin/bash

for k in {5..25}
do
    wget "https://axiom-crypto.s3.amazonaws.com/challenge_0085/kzg_bn254_${k}.srs"
done

wget "https://storage.googleapis.com/modulus_srs/kzg_bn254_26.srs"

mv *.srs params/
