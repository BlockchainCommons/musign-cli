## Abstract

This document describes how to build and run `musign`.
In addition, it shows how to run tests.

## Install Toolchain

First, make sure you have [Rust and Cargo](https://doc.rust-lang.org/cargo/getting-started/installation.html) installed.

## Build and Run

Building is easy. `cd` into `musign` directory and run 

```bash
$ cargo build
```

The executable is `target/debug/musign`. So `cd` into `target/debug/` and run 
```bash
$ musign -h


musign 
Generate secp256k1 keys, sign and verify messages with ECDSA and Schnorr

USAGE:
    musign <SUBCOMMAND>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

SUBCOMMANDS:
    generate    Generate a public key from a secret (private key/seed/secret key)
    help        Prints this message or the help of the given subcommand(s)
    sign        Sign a message. Signature is returned
    verify      Verify a signature for a given message. True is returned for a valid signature
                otherwise False
```

## Run Tests 

Tests can be run with

```bash
$ cargo test
```
