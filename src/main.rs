use clap::{ArgGroup, Clap, ValueHint};
use std::collections::HashSet;
use std::path::PathBuf;
use std::str::FromStr;
extern crate hex;
extern crate secp256k1;
use secp256k1::bitcoin_hashes::sha256;
use serde::{Deserialize, Serialize};
use serde_json::json;

//use secp256k1::rand::rngs::OsRng;
use secp256k1::{schnorrsig, Message, PublicKey, Secp256k1, SecretKey, Signature};
extern crate bitcoin;
use bitcoin::util::address::Address;
use bitcoin::util::key::PublicKey as Public_key;
use bitcoin::util::misc::{signed_msg_hash, MessageSignature};

use std::io::{stdin, BufReader, Read};

#[derive(Serialize, Deserialize, Debug, PartialEq)]
enum OneOrMany<T> {
    One(T),
    Many(Vec<T>),
}

#[derive(Serialize, Deserialize, Debug, Clap, PartialEq, Clone, Eq, Hash)]
enum SigType {
    ECDSA,
    Schnorr,
    /// mainnet
    BtcLegacy,
}

#[derive(Serialize, Deserialize, Debug)]
struct Sig {
    sig_type: SigType,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sig: Option<Vec<u8>>, // TODO
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pubkey: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    quorum: Option<[u16; 2]>, // [2,3] -> 2 out of 3
}

fn signmessage(seckey: SecretKey, message: String) -> (String, String) {
    let secp = secp256k1::Secp256k1::new();
    let msg_hash = signed_msg_hash(&message);
    let msg = secp256k1::Message::from_slice(&msg_hash).unwrap();
    let secp_sig = secp.sign_recoverable(&msg, &seckey);
    let signature = MessageSignature {
        signature: secp_sig,
        compressed: true,
    };

    let pubkey = signature.recover_pubkey(&secp, msg_hash).unwrap();
    let p2pkh = Address::p2pkh(&pubkey, bitcoin::Network::Bitcoin);

    (signature.to_base64(), p2pkh.to_string())
}

fn verifymessage(signature: String, p2pkh_address: String, message: String) -> bool {
    let secp = secp256k1::Secp256k1::new();
    let signature = MessageSignature::from_str(&signature).unwrap();
    let msg_hash = signed_msg_hash(&message);

    let addr = Address::from_str(&p2pkh_address).unwrap();

    signature
        .is_signed_by_address(&secp, &addr, msg_hash)
        .unwrap()
}

fn generate_schnorr_keypair(seed: String) -> (schnorrsig::KeyPair, schnorrsig::PublicKey) {
    let s = Secp256k1::new();

    let keypair = schnorrsig::KeyPair::from_seckey_str(&s, &seed).unwrap();

    let pubkey = schnorrsig::PublicKey::from_keypair(&s, &keypair);
    (keypair, pubkey)
}

fn sign_schnorr(seckey: String, msg: String) -> schnorrsig::Signature {
    let s = Secp256k1::new();
    let keypair = schnorrsig::KeyPair::from_seckey_str(&s, &seckey).unwrap();
    let pubkey = schnorrsig::PublicKey::from_keypair(&s, &keypair);

    let message = Message::from_hashed_data::<sha256::Hash>(msg.as_bytes());
    let sig = s.schnorrsig_sign_no_aux_rand(&message, &keypair);
    assert!(s.schnorrsig_verify(&sig, &message, &pubkey).is_ok());
    sig
}

fn verify_schnorr(signature: String, msg: String, pubkey: String) -> bool {
    let s = Secp256k1::new();
    let pubkey = schnorrsig::PublicKey::from_str(&pubkey).unwrap();
    let sig = schnorrsig::Signature::from_str(&signature).expect("Signature format incorrect");
    let message = Message::from_hashed_data::<sha256::Hash>(msg.as_bytes());
    if s.schnorrsig_verify(&sig, &message, &pubkey).is_ok() {
        true
    } else {
        false
    }
}

fn generate_keypair(seed: Vec<u8>) -> (SecretKey, PublicKey) {
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&seed).expect("seed error");
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    (secret_key, public_key)
}

fn sign(seckey: String, msg: String) -> Signature {
    let seckey = SecretKey::from_str(&seckey).expect("Private key error");

    let message = Message::from_hashed_data::<sha256::Hash>(msg.as_bytes());
    let secp = Secp256k1::new();
    let sig = secp.sign(&message, &seckey);
    let public_key = PublicKey::from_secret_key(&secp, &seckey);
    assert!(secp.verify(&message, &sig, &public_key).is_ok());

    sig
}

fn verify(signature: String, msg: String, pubkey: String) -> bool {
    let pubkey = PublicKey::from_str(&pubkey).unwrap();
    let sig = Signature::from_str(&signature).expect("Signature format incorrect");

    let message = Message::from_hashed_data::<sha256::Hash>(msg.as_bytes());
    let secp = Secp256k1::new();

    if secp.verify(&message, &sig, &pubkey).is_ok() {
        true
    } else {
        false
    }
}

// ecdsa multisig
fn multisig_verify(obj: CmdMultisigConstruct) -> bool {
    let mut msg = obj.clone();
    msg.signatures = None;
    // remove signatures and whitespaces!
    let mut msg = serde_json::to_string(&msg).unwrap();
    msg.retain(|c| !c.is_whitespace());

    let pubkeys = obj.setup.pubkeys;
    let sigs = obj.signatures.unwrap();
    let pubkeys: HashSet<String> = pubkeys.into_iter().collect();
    let sigs: HashSet<String> = sigs.into_iter().collect();

    if sigs.len() < obj.setup.threshold.into() || pubkeys.len() < obj.setup.threshold.into() {
        return false;
    }

    let mut cnt = 0;
    for sig in sigs.iter() {
        for pubkey in &pubkeys {
            if verify(sig.to_string(), msg.clone(), pubkey.to_string()) == true {
                cnt = cnt + 1;
            }
        }
    }

    if cnt >= obj.setup.threshold.into() {
        return true;
    }
    false
}

// ecdsa multisig
fn multisig_combine<'a>(obj: &'a mut Vec<CmdMultisigConstruct>) -> &'a CmdMultisigConstruct {
    // Convert vector to hashset and remove signatures
    let objs: HashSet<CmdMultisigConstruct> = obj
        .clone()
        .into_iter()
        .map(|mut s: CmdMultisigConstruct| {
            s.signatures = None;
            s
        })
        .collect();

    // All the object without signatures must be the same. Therefore only one element in hashset
    assert!(objs.len() == 1); // TODO error handling

    // collect all the signatures
    let mut v: HashSet<String> = HashSet::new();
    for o in obj.clone() {
        if o.signatures.is_some() {
            let p = o.signatures.unwrap();
            v.extend(p.into_iter().clone())
        }
    }

    let mut out = &mut obj[0];

    let v_unique: Vec<String> = v.into_iter().collect();
    out.signatures = Some(v_unique);
    out
}

#[derive(Debug, Clap, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
#[clap()]
pub struct CmdMultisigSetup {
    /// Signature type
    #[clap(arg_enum, default_value = "ecdsa", short = 't')]
    sig_type: SigType,
    /// Threshold
    #[clap(required = true)]
    threshold: u8,
    /// List of public keys to participate in a multisig
    #[clap(short, required = true)]
    pubkeys: Vec<String>,
}

#[derive(Debug, Clap, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
#[clap()]
pub struct CmdMultisigConstruct {
    /// Message to sign.
    #[clap(required = true)]
    msg: String,
    /// Multisignature setup (JSON)
    #[clap(required = true, parse(try_from_str = serde_json::from_str))]
    setup: CmdMultisigSetup,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[clap(skip)]
    signatures: Option<Vec<String>>,
}

#[derive(Debug, Clap, Serialize, Deserialize, Clone)]
#[clap()]
pub struct CmdMultisigSign {
    /// Multisig object
    #[clap(required = true, parse(try_from_str = serde_json::from_str))]
    obj: CmdMultisigConstruct,
    #[clap(short)]
    secret: String,
}

#[derive(Debug, Clap, Serialize, Deserialize, Clone)]
#[clap()]
pub struct CmdMultisigCombine {
    /// Multisig object
    #[clap(required = true, parse(try_from_str = serde_json::from_str))]
    obj: Vec<CmdMultisigConstruct>,
}

#[derive(Debug, Clap, Serialize, Deserialize, Clone)]
#[clap()]
pub struct CmdMultisigVerify {
    /// Multisig object
    #[clap(required = true, parse(try_from_str = serde_json::from_str))]
    obj: CmdMultisigConstruct,
}

#[derive(Debug, Clap)]
#[clap()]
pub struct CmdSign {
    /// Path to private key (Not implemented)
    #[clap(parse(from_os_str), value_hint = ValueHint::AnyPath, short = 'f')]
    seckey_file: Option<PathBuf>,
    /// Secret in hex
    #[clap(short)]
    secret: Option<String>,
    /// Message to sign.
    #[clap(required = true)]
    msg: String,
    /// Signature type
    #[clap(arg_enum, default_value = "ecdsa", short = 't')]
    sig_type: SigType,
    /// Output format
    #[clap(short='r', default_value = "json", possible_values=&["json", "cbor"])]
    format: String,
}

// musign verify -h is correct while musign help verify is not
#[derive(Debug, Clap)]
#[clap(group = ArgGroup::new("verify").required(true) )]
pub struct CmdVerify {
    /// Signature in hex
    #[clap(required = true)]
    signature: String,
    /// Message string
    #[clap(required = true)]
    message: String,
    /// Public key in hex
    #[clap(group = "verify", short = 'p')]
    pubkey: Option<String>,
    #[clap(arg_enum, default_value = "ecdsa", short = 't')]
    sig_type: SigType,
    /// BTC p2pkh address
    #[clap(group = "verify", short = 'a')]
    address: Option<String>,
}

#[derive(Clap, Debug)]
#[clap(name = "musign-cli")]
/// Generate secp256k1 keys, sign and verify messages with ECDSA and Schnorr
enum Opt {
    /// Generate a public key from a secret (private key/seed/secret key). In case of btc-legacy type
    /// p2pkh address is generated
    Generate {
        /// Secret (also known as seed, private key or secret key) in hex (64 chars).
        secret: String,
        /// Type of signature.
        #[clap(arg_enum, default_value = "ecdsa", short = 't')]
        sig_type: SigType,
    },

    /// Sign a message. Signature is returned.
    Sign(CmdSign),

    /// Verify a signature for a given message. True is returned for a valid signature otherwise False.
    Verify(CmdVerify),

    /// Set up a multisig
    #[clap(display_order = 2000)]
    MultisigSetup(CmdMultisigSetup),

    #[clap(display_order = 2001)]
    MultisigConstruct(CmdMultisigConstruct),

    #[clap(display_order = 2002)]
    MultisigSign(CmdMultisigSign),

    #[clap(display_order = 2003)]
    MultisigCombine(CmdMultisigCombine),

    #[clap(display_order = 2004)]
    MultisigVerify(CmdMultisigVerify),
}

fn main() {
    let matches = Opt::parse();

    //println!("DEBUG: {:?}\n", matches); // TODO: enclose under --verbose

    match matches {
        Opt::Generate { secret, sig_type } => {
            let seed_bytes = hex::decode(secret.clone()).expect("Decoding seed failed");

            match sig_type {
                SigType::ECDSA => {
                    let (_, pubkey) = generate_keypair(seed_bytes);
                    let ret = json!({
                        "pubkey": pubkey.to_string(),
                    });
                    println!("{}", ret.to_string());
                }
                SigType::Schnorr => {
                    let (_, pubkey) = generate_schnorr_keypair(secret);
                    let ret = json!({
                        "pubkey": pubkey.to_string(),
                    });
                    println!("{}", ret.to_string());
                }
                SigType::BtcLegacy => {
                    let (_, pubkey) = generate_keypair(seed_bytes);
                    let pubkey = Public_key {
                        compressed: true,
                        key: pubkey,
                    };
                    let p2pkh = Address::p2pkh(&pubkey, bitcoin::Network::Bitcoin);
                    let ret = json!({
                        "address": p2pkh.to_string(),
                    });
                    println!("{}", ret.to_string());
                }
            };
        }
        Opt::Sign(cmd) => {
            let mut privkey = String::new();
            let ret = stdin().read_to_string(&mut privkey);
            let sec = if ret.is_ok() {
                privkey.retain(|c| !c.is_whitespace());
                privkey
            } else {
                cmd.secret.clone().expect("error private key string")
            };

            let out = match cmd.sig_type {
                SigType::ECDSA => {
                    let sig = sign(sec.clone(), cmd.msg.clone());

                    // TODO: make a method inside a struct
                    let seed_bytes = hex::decode(sec).expect("Decoding seed failed");
                    let (_, pubkey) = generate_keypair(seed_bytes);

                    let mut sig = Sig {
                        sig_type: cmd.sig_type,
                        signature: Some(sig.to_string()),
                        sig: Some(sig.serialize_compact().to_vec()),
                        message: cmd.msg,
                        pubkey: Some(pubkey.to_string()),
                        address: None,
                        quorum: None,
                    };

                    if cmd.format == "cbor" {
                        sig.signature = None;
                    } else {
                        sig.sig = None;
                    }

                    sig
                }
                SigType::Schnorr => {
                    let sig = sign_schnorr(sec.clone(), cmd.msg.clone());
                    // TODO: make a method inside a struct
                    let (_, pubkey) = generate_schnorr_keypair(sec);

                    let mut sig = Sig {
                        sig_type: cmd.sig_type,
                        signature: Some(sig.to_string()),
                        sig: Some(hex::decode(sig.to_string()).unwrap()), // TODO
                        message: cmd.msg,
                        pubkey: Some(pubkey.to_string()),
                        address: None,
                        quorum: None,
                    };

                    if cmd.format == "cbor" {
                        sig.signature = None;
                    } else {
                        sig.sig = None;
                    }

                    sig
                }

                SigType::BtcLegacy => {
                    let seckey = SecretKey::from_str(&sec).expect("Private key error");
                    let (sig, addr) = signmessage(seckey, cmd.msg.clone());
                    Sig {
                        sig_type: cmd.sig_type,
                        signature: Some(sig),
                        sig: None,
                        message: cmd.msg,
                        pubkey: None,
                        address: Some(addr),
                        quorum: None,
                    }
                }
            };

            if cmd.format == "json" {
                println!("{}", serde_json::to_string(&out).unwrap());
            } else {
                let cbor = serde_cbor::to_vec(&out);
                let cbor = hex::encode(cbor.unwrap());
                println!("{}", cbor);
            }
        }

        Opt::Verify(cmd) => {
            match cmd.sig_type {
                SigType::ECDSA => {
                    let res = verify(cmd.signature, cmd.message, cmd.pubkey.unwrap());
                    println!("{}", res);
                }
                SigType::Schnorr => {
                    let res = verify_schnorr(cmd.signature, cmd.message, cmd.pubkey.unwrap());
                    println!("{}", res);
                }
                SigType::BtcLegacy => {
                    let ret = verifymessage(cmd.signature, cmd.address.unwrap(), cmd.message);
                    println!("{}", ret);
                }
            };
        }

        Opt::MultisigSetup(cmd) => {
            match cmd.sig_type {
                SigType::ECDSA => {
                    println!("{}", serde_json::to_string(&cmd).unwrap());
                }
                SigType::Schnorr => {}
                SigType::BtcLegacy => {}
            };
        }

        Opt::MultisigConstruct(cmd) => {
            println!("{}", serde_json::to_string(&cmd).unwrap());
        }
        // cargo run -- multisig-sign "$(< multisig_object.json)"  -s dd
        Opt::MultisigSign(cmd) => {
            let mut js: CmdMultisigConstruct = cmd.obj.clone();
            // remove signatures before signing
            let mut sigs = js.signatures;
            js.signatures = None;

            // remove whitespaces
            let mut j = serde_json::to_string(&js).unwrap();
            j.retain(|c| !c.is_whitespace());

            let sig = sign(cmd.secret.clone(), j.clone());

            match sigs {
                Some(ref mut v) => v.push(sig.to_string()),
                None => {
                    sigs = Some(vec![sig.to_string()]);
                }
            };

            js.signatures = sigs;

            println!("{}", serde_json::to_string(&js).unwrap());
        }

        Opt::MultisigVerify(cmd) => {
            let ret = multisig_verify(cmd.obj);
            println!("{}", ret);
        }

        Opt::MultisigCombine(cmd) => {
            let mut c = cmd.obj.clone();
            let ret = multisig_combine(&mut c);
            println!("{}", serde_json::to_string(&ret).unwrap());
        }
    };
}
