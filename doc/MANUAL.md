## Manual

This document shows how to use basic commands with `musig-cli`.

### Generate a public key

From a random 32 byte seed (private key) we can generate a public key for usage with `ECDSA`

```bash
$ musig-cli generate 7694c743a0159ebfb79a65aae8970fcc5be5e9db8efa1ebf70218ae00bb1f29b

"03dc5a4faf89ad7187933042bcc0fd028b3296f82e7a0f17eecceb4f787ae33f59"
```
or for usage with `Schnorr` signatures:

```bash
$ musig-cli generate -t schnorr 7694c743a0159ebfb79a65aae8970fcc5be5e9db8efa1ebf70218ae00bb1f29b

"dc5a4faf89ad7187933042bcc0fd028b3296f82e7a0f17eecceb4f787ae33f59"
```

### Sign a message

Signing a message which returns an `ECDSA` signature:

```bash
musig-cli sign "Hello world!" -s 7694c743a0159ebfb79a65aae8970fcc5be5e9db8efa1ebf70218ae00bb1f29b

"3044022012341336cb664828bcd15de1bcf13667ed995d100d1a1b3ece9c0c6691d8940702202cc227014626ea034d2371cdfa0e261f557d3f72d2cfcc2fe0756f5c5c71faba"
```

Signing a message with `Schnorr` returns a `Schnorr` signature:

```bash
$ musig-cli sign -t schnorr "Hello world!" -s 7694c743a0159ebfb79a65aae8970fcc5be5e9db8efa1ebf70218ae00bb1f29b

"22c2cfbaaee968a7afb6bfcd847b830e373ac066021d7286ade84ab5f64f8a4f7e0371c19f06e54f150dd4c98ebb631cb660389d8120e60f1dfa78a17aa3fc72"
```

### Verify a signature

Verifying an `ECDSA` signature:

```bash
$ musig-cli verify 3044022012341336cb664828bcd15de1bcf13667ed995d100d1a1b3ece9c0c6691d8940702202cc227014626ea034d2371cdfa0e261f557d3f72d2cfcc2fe0756f5c5c71faba "Hello world!" 03dc5a4faf89ad7187933042bcc0fd028b3296f82e7a0f17eecceb4f787ae33f59

True
```

Verifying a `Schnorr` signature:

```bash
$ musig-cli verify -t schnorr 22c2cfbaaee968a7afb6bfcd847b830e373ac066021d7286ade84ab5f64f8a4f7e0371c19f06e54f150dd4c98ebb631cb660389d8120e60f1dfa78a17aa3fc72  "Hello world!" dc5a4faf89ad7187933042bcc0fd028b3296f82e7a0f17eecceb4f787ae33f59

True
```

### Help

```bash
$ musig-cli -h
musig-cli 
Generate secp256k1 keys, sign and verify messages with ECDSA and Schnorr

USAGE:
    musig-cli <SUBCOMMAND>

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
