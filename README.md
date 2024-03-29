# Snark Verifier CLI

This is a command line tool for proof aggregation, it serves as a wrapper for [snark-verifier](https://github.com/axiom-crypto/snark-verifier) library. 

## Environment Setup

Make sure to choose the correct rustc version (see rust-toolchain). Download kzg trusted setup keys.

```bash
# download trusted setup keys for different sizes
# or modify this script to download specific size
./trusted_setup_s3.sh
```

## How to run it

The snark-verifier accepts a specific format. Let's denote it as ".snark" file. A snark file includes the proof of a plonkish circuit and protocol information used by proof aggregation.

`snark-verifier-cli` has $3$ commands. `read` command reads a snark file and print it out. `verify` command verifies a snark file. `aggregate` command aggregates multiple proofs inside a folder.

Here are some command examples:

```bash
# read a snark proof at location proofs/1.snark
cargo run -- read proofs/1.snark
# or
snark-verifier-cli read proofs/1.snark

# verify a snark proof at location data/agg_circuit.snark
snark-verify-cli verify data/agg_circuit.snark

# aggregate multiple proofs in folder proofs
cargo run -- aggregate proofs/
```

> The main branch of this tool is compatible with snark files generated by main branch of snark-verifier
>
> The `v0.1.1-ce` branch of this tool is compatible with snark files generated by `v0.1.1-ce` branch of snark-verifier.
