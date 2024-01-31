# Snark Verifier CLI

This is the command line tool for proof aggregation based on snark-verifier library. 

## Setup

```bash
# download trusted setup keys for different sizes
./trusted_setup_s3.sh
```


## Usage
```bash
# read|verify a snark proof 
cargo run -- [read|verify] /path/to/snark_file
# aggregate multiple proofs in a folder
cargo run -- aggregate /path/to/folder/
```
