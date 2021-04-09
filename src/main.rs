use clap::{Clap, ValueHint};
use std::collections::HashSet;
use std::io::BufRead;
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

mod errors;
use errors::MusignError;
use std::io::{stdin, BufReader, Read};

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
}

fn signmessage(seckey: SecretKey, message: String) -> Result<(String, String), MusignError> {
    let secp = secp256k1::Secp256k1::new();
    let msg_hash = signed_msg_hash(&message);
    let msg = secp256k1::Message::from_slice(&msg_hash)?;
    let secp_sig = secp.sign_recoverable(&msg, &seckey);
    let signature = MessageSignature {
        signature: secp_sig,
        compressed: true,
    };

    let pubkey = signature.recover_pubkey(&secp, msg_hash)?;
    let p2pkh = Address::p2pkh(&pubkey, bitcoin::Network::Bitcoin);

    Ok((signature.to_base64(), p2pkh.to_string()))
}

fn verifymessage(
    signature: String,
    p2pkh_address: String,
    message: String,
) -> Result<bool, MusignError> {
    let secp = secp256k1::Secp256k1::new();
    let signature = MessageSignature::from_str(&signature)?;
    let msg_hash = signed_msg_hash(&message);

    let addr = Address::from_str(&p2pkh_address)?;

    Ok(signature.is_signed_by_address(&secp, &addr, msg_hash)?)
}

fn generate_schnorr_keypair(
    seed: String,
) -> Result<(schnorrsig::KeyPair, schnorrsig::PublicKey), MusignError> {
    let s = Secp256k1::new();

    let keypair = schnorrsig::KeyPair::from_seckey_str(&s, &seed)?;

    let pubkey = schnorrsig::PublicKey::from_keypair(&s, &keypair);
    Ok((keypair, pubkey))
}

fn sign_schnorr(seckey: String, msg: String) -> Result<schnorrsig::Signature, MusignError> {
    let s = Secp256k1::new();
    let keypair = schnorrsig::KeyPair::from_seckey_str(&s, &seckey)?;
    let pubkey = schnorrsig::PublicKey::from_keypair(&s, &keypair);

    let message = Message::from_hashed_data::<sha256::Hash>(msg.as_bytes());
    let sig = s.schnorrsig_sign_no_aux_rand(&message, &keypair);
    assert!(s.schnorrsig_verify(&sig, &message, &pubkey).is_ok());
    Ok(sig)
}

fn verify_schnorr(signature: String, msg: String, pubkey: String) -> Result<bool, MusignError> {
    let s = Secp256k1::new();
    let pubkey = schnorrsig::PublicKey::from_str(&pubkey)?;
    let sig = schnorrsig::Signature::from_str(&signature).expect("Signature format incorrect");
    let message = Message::from_hashed_data::<sha256::Hash>(msg.as_bytes());
    Ok(s.schnorrsig_verify(&sig, &message, &pubkey).is_ok())
}

fn generate_keypair(seed: Vec<u8>) -> Result<(SecretKey, PublicKey), MusignError> {
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&seed)?;
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    Ok((secret_key, public_key))
}

fn sign(seckey: String, msg: String) -> Result<Signature, MusignError> {
    let seckey = SecretKey::from_str(&seckey)?;

    let message = Message::from_hashed_data::<sha256::Hash>(msg.as_bytes());
    let secp = Secp256k1::new();
    let sig = secp.sign(&message, &seckey);
    let public_key = PublicKey::from_secret_key(&secp, &seckey);
    assert!(secp.verify(&message, &sig, &public_key).is_ok());

    Ok(sig)
}

fn verify(signature: String, msg: String, pubkey: String) -> Result<bool, MusignError> {
    let pubkey = PublicKey::from_str(&pubkey)?;
    let sig = Signature::from_str(&signature).expect("Signature format incorrect");

    let message = Message::from_hashed_data::<sha256::Hash>(msg.as_bytes());
    let secp = Secp256k1::new();

    Ok(secp.verify(&message, &sig, &pubkey).is_ok())
}

// ecdsa multisig
fn multisig_verify(obj: CmdMultisigConstruct) -> Result<bool, MusignError> {
    let mut msg = obj.clone();
    msg.signatures = None;
    // remove signatures and whitespaces!
    let mut msg = serde_json::to_string(&msg)?;
    msg.retain(|c| !c.is_whitespace());

    let pubkeys = obj.setup.pubkeys.unwrap(); // safe
    let sigs = obj.signatures.unwrap(); // safe
    let pubkeys: HashSet<String> = pubkeys.into_iter().collect();
    let sigs: HashSet<String> = sigs.into_iter().collect();

    if sigs.len() < obj.setup.threshold.into() || pubkeys.len() < obj.setup.threshold.into() {
        return Ok(false);
    }

    let mut cnt = 0;
    for sig in sigs.iter() {
        for pubkey in &pubkeys {
            if verify(sig.to_string(), msg.clone(), pubkey.to_string())? {
                cnt += 1;
            }
        }
    }

    if cnt >= obj.setup.threshold.into() {
        return Ok(true);
    }
    Ok(false)
}

// ecdsa multisig
fn multisig_combine(
    obj: &mut Vec<CmdMultisigConstruct>,
) -> Result<&CmdMultisigConstruct, MusignError> {
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
    assert!(objs.len() == 1);

    // collect all the signatures
    let mut v: HashSet<String> = HashSet::new();
    for o in obj.clone() {
        if o.signatures.is_some() {
            let p = o.signatures.ok_or_else(|| {
                MusignError::new(
                    "conversion".to_string(),
                    "collecting sigantures".to_string(),
                )
            })?;
            v.extend(p.into_iter().clone())
        }
    }

    let mut out = &mut obj[0];

    let v_unique: Vec<String> = v.into_iter().collect();
    out.signatures = Some(v_unique);
    Ok(out)
}

#[derive(Debug, Clap, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
#[clap()]
pub struct CmdMultisigSetup {
    /// Signature type. Currently only ecdsa implemented.
    #[clap(arg_enum, default_value = "ecdsa", short = 't')]
    sig_type: SigType,
    /// Threshold
    #[clap(required = true)]
    threshold: u8,
    /// List of public keys to participate in a multisig in hex format.
    /// Alternatively, the keys can be piped via STDIN
    #[clap(short)]
    pubkeys: Option<Vec<String>>,
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
    /// Private key in hex to sign the multisig object.
    /// Alternatively, the key can be provided via STDIN
    #[clap(short)]
    secret: Option<String>,
}

#[derive(Debug, Clap)]
#[clap()]
pub struct CmdSign {
    /// Path to private key (Not implemented)
    #[clap(parse(from_os_str), value_hint = ValueHint::AnyPath, short = 'f')]
    seckey_file: Option<PathBuf>,
    /// Private key in hex.
    /// Alternatively, the key can be piped via STDIN
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
#[clap()]
pub struct CmdVerify {
    /// Signature in hex
    #[clap(required = true)]
    signature: String,
    /// Message string
    #[clap(required = true)]
    message: String,
    /// Public key in hex.
    /// Alternatively, the key can be provided via STDIN
    #[clap(short = 'p')]
    pubkey: Option<String>,
    #[clap(arg_enum, default_value = "ecdsa", short = 't')]
    sig_type: SigType,
    /// BTC p2pkh address
    #[clap(short = 'a')]
    address: Option<String>,
}

#[derive(Clap, Debug)]
#[clap(name = "musign-cli")]
/// Generate secp256k1 keys, sign and verify messages with ECDSA and Schnorr in a single- or multisignature setup.
enum Opt {
    /// Generate a public key from a secret (private key/seed/secret key). In case of btc-legacy type
    /// p2pkh address is generated.
    Generate {
        /// Secret (also known as seed, private key or secret key) in hex.
        /// Alternatively, the key can be provided via STDIN
        secret: Option<String>,
        /// Type of signature.
        #[clap(arg_enum, default_value = "ecdsa", short = 't')]
        sig_type: SigType,
    },

    /// Sign a message. Signature is returned.
    Sign(CmdSign),

    /// Verify a signature for a given message. True is returned for a valid signature otherwise false.
    Verify(CmdVerify),

    /// Set up a multisig: quorum and all the participants (pubkeys in hex).
    #[clap(display_order = 2000)]
    MultisigSetup(CmdMultisigSetup),

    /// Add message to a multisig setup. Returns an unsigned multisignature object.
    #[clap(display_order = 2001, name = "multisig-construct-msg")]
    MultisigConstruct(CmdMultisigConstruct),

    /// Sign a multisignature object passed via STDIN.
    #[clap(display_order = 2002)]
    MultisigSign(CmdMultisigSign),

    /// Combine signatures of individually signed multisignature objects. Pass them via STDIN.
    #[clap(display_order = 2003)]
    MultisigCombine,

    /// Verify a multisignature object passed via STDIN. Returns true or false.
    #[clap(display_order = 2004)]
    MultisigVerify,
}

fn main() -> Result<(), MusignError> {
    let matches = Opt::parse();

    //println!("DEBUG: {:?}\n", matches); // TODO: enclose under --verbose

    match matches {
        Opt::Generate { secret, sig_type } => {
            let secret = if secret != None {
                secret.unwrap() // safe
            } else {
                let mut privkey = String::new();
                let ret = stdin().read_to_string(&mut privkey);
                assert!(ret.is_ok());
                privkey.retain(|c| !c.is_whitespace());
                privkey
            };

            let seed_bytes = hex::decode(secret.clone()).map_err(|_| {
                MusignError::new("conversion".to_string(), "cannot decode secret".to_string())
            })?;

            match sig_type {
                SigType::ECDSA => {
                    let (_, pubkey) = generate_keypair(seed_bytes)?;
                    let ret = json!({
                        "pubkey": pubkey.to_string(),
                    });
                    println!("{}", ret.to_string());
                }
                SigType::Schnorr => {
                    let (_, pubkey) = generate_schnorr_keypair(secret)?;
                    let ret = json!({
                        "pubkey": pubkey.to_string(),
                    });
                    println!("{}", ret.to_string());
                }
                SigType::BtcLegacy => {
                    let (_, pubkey) = generate_keypair(seed_bytes)?;
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
            let sec = if cmd.secret != None {
                cmd.secret.clone().expect("error private key string") // safe
            } else {
                let mut privkey = String::new();
                let ret = stdin().read_to_string(&mut privkey);
                assert!(ret.is_ok());
                privkey.retain(|c| !c.is_whitespace());
                privkey
            };

            let out = match cmd.sig_type {
                SigType::ECDSA => {
                    let sig = sign(sec.clone(), cmd.msg.clone())?;

                    // TODO: make a method inside a struct
                    let seed_bytes = hex::decode(sec).expect("Decoding seed failed");
                    let (_, pubkey) = generate_keypair(seed_bytes)?;

                    let mut sig = Sig {
                        sig_type: cmd.sig_type,
                        signature: Some(sig.to_string()),
                        sig: Some(sig.serialize_compact().to_vec()),
                        message: cmd.msg,
                        pubkey: Some(pubkey.to_string()),
                        address: None,
                    };

                    if cmd.format == "cbor" {
                        sig.signature = None;
                    } else {
                        sig.sig = None;
                    }

                    sig
                }
                SigType::Schnorr => {
                    let sig = sign_schnorr(sec.clone(), cmd.msg.clone())?;
                    // TODO: make a method inside a struct
                    let (_, pubkey) = generate_schnorr_keypair(sec)?;

                    let mut sig = Sig {
                        sig_type: cmd.sig_type,
                        signature: Some(sig.to_string()),
                        sig: Some(hex::decode(sig.to_string()).map_err(|_| {
                            MusignError::new(
                                "conversion".to_string(),
                                "cannot decode signature into hex".to_string(),
                            )
                        })?),
                        message: cmd.msg,
                        pubkey: Some(pubkey.to_string()),
                        address: None,
                    };

                    if cmd.format == "cbor" {
                        sig.signature = None;
                    } else {
                        sig.sig = None;
                    }

                    sig
                }

                SigType::BtcLegacy => {
                    let seckey = SecretKey::from_str(&sec)?;
                    let (sig, addr) = signmessage(seckey, cmd.msg.clone())?;
                    Sig {
                        sig_type: cmd.sig_type,
                        signature: Some(sig),
                        sig: None,
                        message: cmd.msg,
                        pubkey: None,
                        address: Some(addr),
                    }
                }
            };

            if cmd.format == "json" {
                println!("{}", serde_json::to_string(&out)?);
            } else {
                let cbor = serde_cbor::to_vec(&out)?;
                let cbor = hex::encode(cbor);
                println!("{}", cbor);
            }
        }

        Opt::Verify(cmd) => {
            let pubkey = if cmd.pubkey != None {
                cmd.pubkey.clone().expect("error private key string") // safe
            } else if cmd.address != None {
                cmd.address.unwrap() // safe
            } else {
                let mut pubkey = String::new();
                let ret = stdin().read_to_string(&mut pubkey);
                assert!(ret.is_ok());
                pubkey.retain(|c| !c.is_whitespace());
                pubkey
            };

            match cmd.sig_type {
                SigType::ECDSA => {
                    let res = verify(cmd.signature, cmd.message, pubkey)?;
                    println!("{}", res);
                }
                SigType::Schnorr => {
                    let res = verify_schnorr(cmd.signature, cmd.message, pubkey)?;
                    println!("{}", res);
                }
                SigType::BtcLegacy => {
                    let ret = verifymessage(cmd.signature, pubkey, cmd.message)?;
                    println!("{}", ret);
                }
            };
        }

        Opt::MultisigSetup(mut cmd) => {
            if cmd.pubkeys == None {
                let mut v: Vec<String> = Vec::new();
                let stdin = stdin();
                for line in stdin.lock().lines() {
                    let s = line?;
                    v.push(s);
                }
                cmd.pubkeys = Some(v);
            };

            match cmd.sig_type {
                SigType::ECDSA => {
                    println!("{}", serde_json::to_string(&cmd)?);
                }
                SigType::Schnorr => {}
                SigType::BtcLegacy => {}
            };
        }

        Opt::MultisigConstruct(cmd) => {
            println!("{}", serde_json::to_string(&cmd)?);
        }

        Opt::MultisigSign(mut cmd) => {
            let mut v: Vec<String> = Vec::new();
            let stdin = stdin();
            for line in stdin.lock().lines() {
                let s = line?;
                v.push(s);
            }

            if v.len() == 2 {
                // The second stdin arg must be private key, Otherwise
                // it must be provided as cli arg -s
                cmd.secret = Some(v[1].clone());
            }

            let mut js: CmdMultisigConstruct = serde_json::from_str(&v[0])?;
            // remove signatures before signing
            let mut sigs = js.signatures;
            js.signatures = None;

            // remove whitespaces
            let mut j = serde_json::to_string(&js)?;
            j.retain(|c| !c.is_whitespace());

            let sig = sign(cmd.secret.unwrap(), j)?; // safe

            match sigs {
                Some(ref mut v) => v.push(sig.to_string()),
                None => {
                    sigs = Some(vec![sig.to_string()]);
                }
            };

            js.signatures = sigs;

            println!("{}", serde_json::to_string(&js)?);
        }

        Opt::MultisigVerify => {
            let multisig_reader = BufReader::new(stdin());
            let obj: CmdMultisigConstruct = serde_json::from_reader(multisig_reader)?;
            let ret = multisig_verify(obj)?;
            println!("{}", ret);
        }

        Opt::MultisigCombine => {
            let mut v: Vec<CmdMultisigConstruct> = Vec::new();
            let stdin = stdin();
            for line in stdin.lock().lines() {
                let s = line?;
                let p: CmdMultisigConstruct = serde_json::from_str(&s)?;
                v.push(p);
            }
            let ret = multisig_combine(&mut v)?;
            println!("{}", serde_json::to_string(&ret)?);
        }
    };
    Ok(())
}
