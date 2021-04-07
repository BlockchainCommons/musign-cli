## Manual

This document shows how to use basic commands with `musign`.

### Generate a public key

```bash
$ musign-generate 
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
$ musign verify -t btc-legacy IJIhzsY2hAFo613hTg9Gz4qc3ffWKVz3A+Wux8lwYSj5Vm1Mxqn5i7VTdhSuysrNAexNcSMBlkHyqOym77IiC/0= "Hello world!" -a 12dR2srvCmffup7yBu5fdb3qkhFudTBnvZ

true
```

### Multisignatures

#### Multisig-setup

```
musign-multisig-setup 
Set up a multisig: quorum and all the participants (pubkeys)

USAGE:
    musign multisig-setup [OPTIONS] <threshold> -p <pubkeys>...

ARGS:
    <threshold>    Threshold

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -p <pubkeys>...        List of public keys to participate in a multisig
    -t <sig-type>          Signature type. Currently only ecdsa implemented [default: ecdsa]
                           [possible values: ecdsa, schnorr, btc-legacy]

```

Let's create a multisignature setup 2 of 3:


```bash
$ musign multisig-setup 2 -p 03c2805489921b22854b1381e32a1d7c4452a4fd12f6c3f13cab9dc899216a6bd1 026586cae2ee70f6f046f63ce2e7e3b479099c61753cf7d913f2eab2e78df5a435 0350f1f0017a468c993b046442438e5340b6675376663b7f653fd03f667488c60d > m_setup.json
```

```bash
echo $(<m_setup.json)
{"sig_type":"ECDSA","threshold":2,"pubkeys":["03c2805489921b22854b1381e32a1d7c4452a4fd12f6c3f13cab9dc899216a6bd1","026586cae2ee70f6f046f63ce2e7e3b479099c61753cf7d913f2eab2e78df5a435","0350f1f0017a468c993b046442438e5340b6675376663b7f653fd03f667488c60d"]}
```

#### multisig-construct-msg

```bash
musign-multisig-construct-msg 
Add message to a multisig setup. Returns an unsigned multisignature object

USAGE:
    musign multisig-construct-msg <msg> <setup>

ARGS:
    <msg>      Message to sign
    <setup>    Multisignature setup (JSON)

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information
```

Now, we can create a multisignature object with a message to be signed with the participants of the multisignature setup:

```bash
$ musign  multisig-construct-msg "Hello world!" "$(<m_setup.json)" > m_obj.json
```

```bash
echo $(<m_obj.json)
{"msg":"Hello world!","setup":{"sig_type":"ECDSA","threshold":2,"pubkeys":["03c2805489921b22854b1381e32a1d7c4452a4fd12f6c3f13cab9dc899216a6bd1","026586cae2ee70f6f046f63ce2e7e3b479099c61753cf7d913f2eab2e78df5a435","0350f1f0017a468c993b046442438e5340b6675376663b7f653fd03f667488c60d"]}}
```

#### multisig-sign

```bash
$ musign-multisig-sign 
Sign a multisignature object passed over via stdin

USAGE:
    musign multisig-sign -s <secret>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -s <secret>

```
We can now start signing our multisig object:

```bash
$ musign multisig-sign -s e6dd32f8761625f105c39a39f19370b3521d845a12456d60ce44debd0a362641 < m_obj.json > m_obj_signed1.json
```

```bash
$ musign multisig-sign -s aadd32f8761625f105c39a39f19370b3521d845a12456d60ce44debd0a362641 < m_obj.json > m_obj_signed2.json
```

```bash
echo $(<m_obj_signed1.json)
{"msg":"Hello world!","setup":{"sig_type":"ECDSA","threshold":2,"pubkeys":["03c2805489921b22854b1381e32a1d7c4452a4fd12f6c3f13cab9dc899216a6bd1","026586cae2ee70f6f046f63ce2e7e3b479099c61753cf7d913f2eab2e78df5a435","0350f1f0017a468c993b046442438e5340b6675376663b7f653fd03f667488c60d"]},"signatures":["3045022100b762298fe57c79493630077f05b708b9e57498b0f6ffb950770a96144fe36f29022055579bf40db6c32355aaf4eedd16713f3fe4d232714397b2fcc0d67953037969"]}
```

The JSON object is signed by first removing all the whitespaces. The order of JSON properties is preserved.

If we are passing in the object that already contains some signatures, the signatures are also removed before signing.

#### multisig-combine

```bash
$ musign-multisig-combine 
Combine signatures of individually signed multisignature objects. Pass them over stdin

USAGE:
    musign multisig-combine

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information
```

Let's combine the signatures:

```bash
$ cat m_obj_signed1.json m_obj_signed2.json | musign multisig-combine > m_obj_signed_combined.json
```

*Note:* Combining signatures is not necessary if we had signed m_obj_signed1.json with the second private key.

#### multisig-verify

```bash
musign-multisig-verify 
Verify a multisignature object passed over by stdin

USAGE:
    musign multisig-verify

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information
```

Finally, we can verify our combined multisignature object:

```bash
$ musign multisig-verify < m_obj_signed_combined.json

true
```

This is our final object:

```bash
echo $(<m_obj_signed_combined.json)
{"msg":"Hello world!","setup":{"sig_type":"ECDSA","threshold":2,"pubkeys":["03c2805489921b22854b1381e32a1d7c4452a4fd12f6c3f13cab9dc899216a6bd1","026586cae2ee70f6f046f63ce2e7e3b479099c61753cf7d913f2eab2e78df5a435","0350f1f0017a468c993b046442438e5340b6675376663b7f653fd03f667488c60d"]},"signatures":["3045022100c71a9ae764c5f457c7d9ff0e7e11004e3c328492ab7894972f9e14403386b1320220267bb019a8d86a92f4dfefce26a3001d8c1995a284e0bb664573b9e3ada7b36c","3045022100b762298fe57c79493630077f05b708b9e57498b0f6ffb950770a96144fe36f29022055579bf40db6c32355aaf4eedd16713f3fe4d232714397b2fcc0d67953037969"]}
```

### Using musign with keytool

We can pipe a hex private or a public key generated with [keytool](https://github.com/BlockchainCommons/bc-keytool-cli) into musign. Let's sign a simple message with a private key derived from a `HD key` with a derivation path of `m/99h/1h/2h/2/0`

```bash
$ keytool --seed 581fbdbf6b3eeababae7e7b51e3aabea address-ec-key --full-address-derivation-path m/99h/1h/2h/2/0 | musign sign "Hello world!"

{"sig_type":"ECDSA","signature":"3045022100a2aaa2d2d0b9a4cafa2af352c1344a762d795a8c3eddd201f5ade6c0a907e1150220418220301b1e8f37b88e8f5d8e19399c8e05ac14e2ef0c2915cc5d537de040c3","message":"Hello world!","pubkey":"038e4c0a6e918071b1e1b344ca1a2d72e2ba6147af70a222461e34b5c080e7a726"}
```

Let's verify the signature with the public key derived form the `HD key` in `keytool`:

```bash
keytool --seed 581fbdbf6b3eeababae7e7b51e3aabea address-pub-ec-key --full-address-derivation-path m/99h/1h/2h/2/0 | musign verify "$(cat object.json | jq -r '.signature')" "$(cat object.json | jq -r '.message')"

true
```

#### Multisignatures

Similarily, we can pipe `keytool` keys in hex into musign subcommands associated with multisignatures.

```bash
$ { keytool --seed 581fbdbf6b3eeababae7e7b51e3aabea address-ec-key --full-address-derivation-path m/99h/1h/2h/0 && keytool --seed 581fbdbf6b3eeababae7e7b51e3aabea address-ec-key --full-address-derivation-path m/99h/1h/2h/1; } | musign multisig-setup 2

{"sig_type":"ECDSA","threshold":2,"pubkeys":["0fb01cbd70be8fcfaf11e64681d99a5d8490b8672ae587861709b21c5b6f9113","db20fa1bd20a2310d09f16e279743a2edf400ee9804cd62b86fde571a31fffe0"]}
```

When signing a multisig object we have to pipe the object itself and the private key:

```bash
$ { cat tmp.json && keytool --seed 581fbdbf6b3eeababae7e7b51e3aabea address-ec-key --full-address-derivation-path m/99h/1h/2h/2/0;} | musign multisig-sign

{"msg":"Hello world!","setup":{"sig_type":"ECDSA","threshold":2,"pubkeys":["03c2805489921b22854b1381e32a1d7c4452a4fd12f6c3f13cab9dc899216a6bd1","026586cae2ee70f6f046f63ce2e7e3b479099c61753cf7d913f2eab2e78df5a435","0350f1f0017a468c993b046442438e5340b6675376663b7f653fd03f667488c60d"]},"signatures":["304402205f18db844afe9ca5f61b4da47a422d1d34c2d0bbb590d413757646a1f32ac10d0220706134b6f8f33b0ebdafc5afdd3ddecc45103cab9554735f121cfe582df1b788"]}
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
    generate                  Generate a public key from a secret (private key/seed/secret key).
                              In case of btc-legacy type p2pkh address is generated
    help                      Prints this message or the help of the given subcommand(s)
    sign                      Sign a message. Signature is returned
    verify                    Verify a signature for a given message. True is returned for a
                              valid signature otherwise False
    multisig-setup            Set up a multisig: quorum and all the participants (pubkeys)
    multisig-construct-msg    Add message to a multisig setup. Returns an unsigned
                              multisignature object
    multisig-sign             Sign a multisignature object passed over via stdin
    multisig-combine          Combine signatures of individually signed multisignature objects.
                              Pass them over stdin
    multisig-verify           Verify a multisignature object passed over by stdin

```
