use clap::{ArgGroup, Clap, ValueHint};
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

#[derive(Serialize, Deserialize, Debug, PartialEq)]
enum OneOrMany<T> {
    One(T),
    Many(Vec<T>),
}

#[derive(Serialize, Deserialize, Debug, Clap, PartialEq)]
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
    signature: Option<OneOrMany<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sig: Option<Vec<u8>>, // TODO
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pubkey: Option<OneOrMany<String>>,
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

#[derive(Debug, Clap, Serialize, Deserialize)]
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

#[derive(Debug, Clap)]
#[clap(group = ArgGroup::new("seck").required(true))]
pub struct CmdMultisigConstruct {
    /// Threshold
    #[clap(required = true)]
    threshold: u8,
    /// List of public keys to participate in a multisig
    #[clap(required = true)]
    pubkeys: Vec<String>,
    /// Signature type
    #[clap(arg_enum, default_value = "ecdsa", short = 't')]
    sig_type: SigType,
}

#[derive(Debug, Clap)]
#[clap(group = ArgGroup::new("seck").required(true))]
pub struct CmdSign {
    /// Path to private key (Not implemented)
    #[clap(parse(from_os_str), value_hint = ValueHint::AnyPath, short = 'f', group="seck")]
    seckey_file: Option<PathBuf>,
    /// Secret in hex
    #[clap(group = "seck", short)]
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
    MultisigSetup(CmdMultisigSetup),
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
            let out = match cmd.sig_type {
                SigType::ECDSA => {
                    let sig = sign(
                        cmd.secret.clone().expect("error private key string"),
                        cmd.msg.clone(),
                    );
                    // TODO: make a method inside a struct
                    let seed_bytes =
                        hex::decode(cmd.secret.unwrap()).expect("Decoding seed failed");
                    let (_, pubkey) = generate_keypair(seed_bytes);

                    let mut sig = Sig {
                        sig_type: cmd.sig_type,
                        signature: Some(OneOrMany::One(sig.to_string())),
                        sig: Some(sig.serialize_compact().to_vec()),
                        message: cmd.msg,
                        pubkey: Some(OneOrMany::One(pubkey.to_string())),
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
                    let sig = sign_schnorr(
                        cmd.secret.clone().expect("error private key string"),
                        cmd.msg.clone(),
                    );
                    // TODO: make a method inside a struct
                    let (_, pubkey) = generate_schnorr_keypair(cmd.secret.clone().unwrap());

                    let mut sig = Sig {
                        sig_type: cmd.sig_type,
                        signature: Some(OneOrMany::One(sig.to_string())),
                        sig: Some(hex::decode(sig.to_string()).unwrap()), // TODO
                        message: cmd.msg,
                        pubkey: Some(OneOrMany::One(pubkey.to_string())),
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
                    let seckey =
                        SecretKey::from_str(&cmd.secret.unwrap()).expect("Private key error");
                    let (sig, addr) = signmessage(seckey, cmd.msg.clone());
                    Sig {
                        sig_type: cmd.sig_type,
                        signature: Some(OneOrMany::One(sig)),
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
    };
}
