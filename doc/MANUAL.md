## Manual

This document shows how to use basic commands with `musign`.

### Generate a public key

```bash
musign-generate 
Generate a public key from a secret (private key/seed/secret key). In case of btc-legacy type p2pkh
address is generated

USAGE:
    musign generate [OPTIONS] <secret>

ARGS:
    <secret>    Secret (also known as seed, private key or secret key) in hex (64 chars)

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -t <sig-type>        Type of signature [default: ecdsa] [possible values: ecdsa, schnorr, btc-
                         legacy]
```

From a random 32 byte seed (private key) we can generate a public key for usage with `ECDSA`


```bash
$ musign generate 7694c743a0159ebfb79a65aae8970fcc5be5e9db8efa1ebf70218ae00bb1f29b

{"pubkey":"03dc5a4faf89ad7187933042bcc0fd028b3296f82e7a0f17eecceb4f787ae33f59"}
```
or for usage with `Schnorr` signatures:

```bash
$ musign generate -t schnorr 7694c743a0159ebfb79a65aae8970fcc5be5e9db8efa1ebf70218ae00bb1f29b

{"pubkey":"dc5a4faf89ad7187933042bcc0fd028b3296f82e7a0f17eecceb4f787ae33f59"}
```
For usage with `btc legacy` signatures a `p2pkh` address is returned:

```bash
$ musign generate -t btc-legacy 7694c743a0159ebfb79a65aae8970fcc5be5e9db8efa1ebf70218ae00bb1f29b

{"address":"12dR2srvCmffup7yBu5fdb3qkhFudTBnvZ"}
```
### Sign a message

```bash
musign-sign 
Sign a message. Signature is returned

USAGE:
    musign sign [OPTIONS] <msg> <-f <seckey-file>|-s <secret>>

ARGS:
    <msg>    Message to sign

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -r <format>             Output format [default: json] [possible values: json, cbor]
    -f <seckey-file>        Path to private key (Not implemented)
    -s <secret>             Secret in hex
    -t <sig-type>           Signature type [default: ecdsa] [possible values: ecdsa, schnorr, btc-
                            legacy]
```

Signing a message which returns an `ECDSA` signature in JSON format:

```bash
$ musign sign "Hello world!" -s 7694c743a0159ebfb79a65aae8970fcc5be5e9db8efa1ebf70218ae00bb1f29b

{"sig_type":"ECDSA","signature":"3044022012341336cb664828bcd15de1bcf13667ed995d100d1a1b3ece9c0c6691d8940702202cc227014626ea034d2371cdfa0e261f557d3f72d2cfcc2fe0756f5c5c71faba","message":"Hello world!","pubkey":"03dc5a4faf89ad7187933042bcc0fd028b3296f82e7a0f17eecceb4f787ae33f59"}
```

If we choose `CBOR` format:

```bash
$ musign sign "Hello world!" -s 7694c743a0159ebfb79a65aae8970fcc5be5e9db8efa1ebf70218ae00bb1f29b -r cbor

a4687369675f7479706565454344534163736967984012183413183618cb18661848182818bc18d1185d18e118bc18f11836186718ed1899185d100d181a181b183e18ce189c0c1866189118d8189407182c18c21827011846182618ea03184d1823187118cd18fa0e1826181f1855187d183f187218d218cf18cc182f18e01875186f185c185c187118fa18ba676d6573736167656c48656c6c6f20776f726c6421667075626b65797842303364633561346661663839616437313837393333303432626363306664303238623332393666383265376130663137656563636562346637383761653333663539
```
This translates to `CBOR` diagnostic notation as:

```bash
{"sig_type": "ECDSA", "sig": [18, 52, 19, 54, 203, 102, 72, 40, 188, 209, 93, 225, 188, 241, 54, 103, 237, 153, 93, 16, 13, 26, 27, 62, 206, 156, 12, 102, 145, 216, 148, 7, 44, 194, 39, 1, 70, 38, 234, 3, 77, 35, 113, 205, 250, 14, 38, 31, 85, 125, 63, 114, 210, 207, 204, 47, 224, 117, 111, 92, 92, 113, 250, 186], "message": "Hello world!", "pubkey": "03dc5a4faf89ad7187933042bcc0fd028b3296f82e7a0f17eecceb4f787ae33f59"}
```

Signing a message with `Schnorr` returns a `Schnorr` signature in JSON:

```bash
$ musign sign -t schnorr "Hello world!" -s 7694c743a0159ebfb79a65aae8970fcc5be5e9db8efa1ebf70218ae00bb1f29b

{"sig_type":"Schnorr","signature":"22c2cfbaaee968a7afb6bfcd847b830e373ac066021d7286ade84ab5f64f8a4f7e0371c19f06e54f150dd4c98ebb631cb660389d8120e60f1dfa78a17aa3fc72","message":"Hello world!","pubkey":"dc5a4faf89ad7187933042bcc0fd028b3296f82e7a0f17eecceb4f787ae33f59"}
```

Signing a message with `Legacy BTC` method:

```bash
$ musign sign -t btc-legacy -s 7694c743a0159ebfb79a65aae8970fcc5be5e9db8efa1ebf70218ae00bb1f29b "Hello world!"

{"sig_type":"BtcLegacy","signature":"IJIhzsY2hAFo613hTg9Gz4qc3ffWKVz3A+Wux8lwYSj5Vm1Mxqn5i7VTdhSuysrNAexNcSMBlkHyqOym77IiC/0=","message":"Hello world!","address":"12dR2srvCmffup7yBu5fdb3qkhFudTBnvZ"}
```


### Verify a signature

```bash
musign-verify 
Verify a signature for a given message. True is returned for a valid signature otherwise False

USAGE:
    musign verify [OPTIONS] <signature> <message> <-p <pubkey>|-a <address>>

ARGS:
    <signature>    Signature in hex
    <message>      Message string

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -a <address>         BTC p2pkh address
    -p <pubkey>          Public key in hex
    -t <sig-type>        [default: ecdsa] [possible values: ecdsa, schnorr, btc-legacy]
```

Verifying an `ECDSA` signature:

```bash
$ musign verify 3044022012341336cb664828bcd15de1bcf13667ed995d100d1a1b3ece9c0c6691d8940702202cc227014626ea034d2371cdfa0e261f557d3f72d2cfcc2fe0756f5c5c71faba "Hello world!" -p 03dc5a4faf89ad7187933042bcc0fd028b3296f82e7a0f17eecceb4f787ae33f59

true
```

Verifying a `Schnorr` signature:

```bash
$ musign verify -t schnorr 22c2cfbaaee968a7afb6bfcd847b830e373ac066021d7286ade84ab5f64f8a4f7e0371c19f06e54f150dd4c98ebb631cb660389d8120e60f1dfa78a17aa3fc72  "Hello world!" -p dc5a4faf89ad7187933042bcc0fd028b3296f82e7a0f17eecceb4f787ae33f59

true
```

Verifying a `BTC legacy` signature with and address `12dR2srvCmffup7yBu5fdb3qkhFudTBnvZ`

```bash
musign verify -t btc-legacy IJIhzsY2hAFo613hTg9Gz4qc3ffWKVz3A+Wux8lwYSj5Vm1Mxqn5i7VTdhSuysrNAexNcSMBlkHyqOym77IiC/0= "Hello world!" -a 12dR2srvCmffup7yBu5fdb3qkhFudTBnvZ

true
```

### Help

```bash
$ musign -h
musign-cli 
Generate secp256k1 keys, sign and verify messages with ECDSA and Schnorr

USAGE:
    musign <SUBCOMMAND>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

SUBCOMMANDS:
    generate    Generate a public key from a secret (private key/seed/secret key). In case of
                btc-legacy type p2pkh address is generated
    help        Prints this message or the help of the given subcommand(s)
    sign        Sign a message. Signature is returned
    verify      Verify a signature for a given message. True is returned for a valid signature
                otherwise false

```
