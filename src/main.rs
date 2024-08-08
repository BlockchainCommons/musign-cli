use clap::{Clap, ValueHint};
use rand::Rng;
use secp256k1::bitcoin_hashes::sha256;
use secp256k1::{schnorrsig, Message, PublicKey, Secp256k1, SecretKey, Signature};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashSet;
use std::io::{self, BufRead, BufReader, Read};
use std::path::PathBuf;
use std::str::FromStr;
use bitcoin::util::address::Address;
use bitcoin::util::key::PublicKey as BtcPublicKey;
use bitcoin::util::misc::{signed_msg_hash, MessageSignature};
use hex;
use errors::MusignError;

mod errors;

pub trait Compact {
    fn to_cmpact(&self) -> String;
    fn from_cmpact(sig: Vec<u8>) -> Signature;
}

impl Compact for Signature {
    fn to_cmpact(&self) -> String {
        let sig = self.serialize_compact().to_vec();
        hex::encode(sig)
    }

    fn from_cmpact(sig: Vec<u8>) -> Signature {
        Signature::from_compact(&sig).expect("Invalid compact signature")
    }
}

#[derive(Serialize, Deserialize, Debug, Clap, PartialEq, Clone, Eq, Hash)]
enum SigType {
    Ecdsa,
    Schnorr,
    BtcLegacy,
}

#[derive(Serialize, Deserialize, Debug)]
struct Sig {
    sig_type: SigType,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sig: Option<Vec<u8>>,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pubkey: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    address: Option<String>,
}

fn sign_message(seckey: SecretKey, message: String) -> Result<(String, String), MusignError> {
    let secp = Secp256k1::new();
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

fn verify_message(signature: String, p2pkh_address: String, message: String) -> Result<bool, MusignError> {
    let secp = Secp256k1::new();
    let signature = MessageSignature::from_str(&signature)?;
    let msg_hash = signed_msg_hash(&message);

    let addr = Address::from_str(&p2pkh_address)?;

    Ok(signature.is_signed_by_address(&secp, &addr, msg_hash)?)
}

fn generate_schnorr_keypair(seed: String) -> Result<(schnorrsig::KeyPair, schnorrsig::PublicKey), MusignError> {
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
    let sig = schnorrsig::Signature::from_str(&signature).expect("Invalid Schnorr signature format");
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
    let sig = hex::decode(signature)?;
    let sig = Signature::from_cmpact(sig);

    let message = Message::from_hashed_data::<sha256::Hash>(msg.as_bytes());
    let secp = Secp256k1::new();

    Ok(secp.verify(&message, &sig, &pubkey).is_ok())
}

fn multisig_verify(obj: CmdMultisigConstruct) -> Result<bool, MusignError> {
    let mut msg = obj.clone();
    msg.signatures = None;
    let mut msg = serde_json::to_string(&msg)?;
    msg.retain(|c| !c.is_whitespace());

    let pubkeys = obj.setup.pubkeys.unwrap();
    let sigs = obj.signatures.unwrap();
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

    Ok(cnt >= obj.setup.threshold.into())
}

fn multisig_combine(obj: &mut Vec<CmdMultisigConstruct>) -> Result<&CmdMultisigConstruct, MusignError> {
    let objs: HashSet<CmdMultisigConstruct> = obj.clone().into_iter().map(|mut s| {
        s.signatures = None;
        s
    }).collect();

    assert!(objs.len() == 1);

    let mut v: HashSet<String> = HashSet::new();
    for o in obj.clone() {
        if let Some(p) = o.signatures {
            v.extend(p.into_iter())
        }
    }

    let out = &mut obj[0];
    out.signatures = Some(v.into_iter().collect());
    Ok(out)
}

#[derive(Debug, Clap, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
#[clap()]
pub struct CmdMultisigSetup {
    #[clap(arg_enum, default_value = "ecdsa", short = 't')]
    sig_type: SigType,
    #[clap(required = true)]
    threshold: u8,
    #[clap(short)]
    pubkeys: Option<Vec<String>>,
}

#[derive(Debug, Clap, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
#[clap()]
pub struct CmdMultisigConstruct {
    #[clap(required = true)]
    msg: String,
    #[clap(required = true, parse(try_from_str = serde_json::from_str))]
    setup: CmdMultisigSetup,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[clap(skip)]
    signatures: Option<Vec<String>>,
}

#[derive(Debug, Clap, Serialize, Deserialize, Clone)]
#[clap()]
pub struct CmdMultisigSign {
    #[clap(short)]
    secret: Option<String>,
}

#[derive(Debug, Clap)]
#[clap()]
pub struct CmdSign {
    #[clap(parse(from_os_str), value_hint = ValueHint::AnyPath, short = 'f')]
    seckey_file: Option<PathBuf>,
    #[clap(short)]
    secret: Option<String>,
    #[clap(required = true)]
    msg: String,
    #[clap(arg_enum, default_value = "ecdsa", short = 't')]
    sig_type: SigType,
    #[clap(short='r', default_value = "json", possible_values=&["json", "cbor"])]
    format: String,
}

#[derive(Debug, Clap)]
#[clap()]
pub struct CmdVerify {
    #[clap(required = true)]
    signature: String,
    #[clap(required = true)]
    message: String,
    #[clap(short = 'p')]
    pubkey: Option<String>,
    #[clap(arg_enum, default_value = "ecdsa", short = 't')]
    sig_type: SigType,
    #[clap(short = 'a')]
    address: Option<String>,
}

#[derive(Clap, Debug)]
#[clap(name = "musign-cli")]
enum Opt {
    Generate {
        secret: Option<String>,
        #[clap(arg_enum, default_value = "ecdsa", short = 't')]
        sig_type: SigType,
    },
    Sign(CmdSign),
    Verify(CmdVerify),
    MultisigSetup(CmdMultisigSetup),
    MultisigConstruct(CmdMultisigConstruct),
    MultisigSign(CmdMultisigSign),
    MultisigCombine,
    MultisigVerify,
}

fn main() -> Result<(), MusignError> {
    let matches = Opt::parse();

    match matches {
        Opt::Generate { secret, sig_type } => {
            let secret = match secret {
                Some(s) => s,
                None => {
                    let mut rng = rand::thread_rng();
                    let mut key = [0u8; 32];
                    rng.fill(&mut key);
                    hex::encode(key)
                }
            };

            let seed_bytes = hex::decode(&secret).map_err(|_| {
                MusignError::new("conversion".to_string(), "cannot decode secret".to_string())
            })?;

            match sig_type {
                SigType::Ecdsa => {
                    let (secret_key, pubkey) = generate_keypair(seed_bytes)?;
                    println!("{}", json!({ "private_key": secret, "pubkey": pubkey.to_string() }).to_string());
                }
                SigType::Schnorr => {
                    let (_, pubkey) = generate_schnorr_keypair(secret)?;
                    println!("{}", json!({ "pubkey": pubkey.to_string() }).to_string());
                }
                SigType::BtcLegacy => {
                    let (secret_key, pubkey) = generate_keypair(seed_bytes)?;
                    let pubkey = BtcPublicKey { compressed: true, key: pubkey };
                    let p2pkh = Address::p2pkh(&pubkey, bitcoin::Network::Bitcoin);
                    println!("{}", json!({ "private_key": secret, "address": p2pkh.to_string() }).to_string());
                }
            }
        }
        Opt::Sign(cmd) => {
            let secret = cmd.secret.unwrap_or_else(|| {
                let mut privkey = String::new();
                io::stdin().read_to_string(&mut privkey).expect("Error reading from stdin");
                privkey.retain(|c| !c.is_whitespace());
                privkey
            });

            let out = match cmd.sig_type {
                SigType::Ecdsa => {
                    let sig = sign(secret.clone(), cmd.msg.clone())?;
                    let seed_bytes = hex::decode(&secret).expect("Decoding seed failed");
                    let (_, pubkey) = generate_keypair(seed_bytes)?;
                    let mut sig = Sig {
                        sig_type: cmd.sig_type,
                        signature: Some(sig.to_cmpact()),
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
                    let sig = sign_schnorr(secret.clone(), cmd.msg.clone())?;
                    let (_, pubkey) = generate_schnorr_keypair(secret)?;
                    let mut sig = Sig {
                        sig_type: cmd.sig_type,
                        signature: Some(sig.to_string()),
                        sig: Some(hex::decode(sig.to_string()).map_err(|_| {
                            MusignError::new("conversion".to_string(), "cannot decode signature into hex".to_string())
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
                    let seckey = SecretKey::from_str(&secret)?;
                    let (sig, addr) = sign_message(seckey, cmd.msg.clone())?;
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
                println!("{}", hex::encode(cbor));
            }
        }
        Opt::Verify(cmd) => {
            let pubkey = cmd.pubkey.clone().unwrap_or_else(|| {
                cmd.address.clone().unwrap_or_else(|| {
                    let mut pubkey = String::new();
                    io::stdin().read_to_string(&mut pubkey).expect("Error reading from stdin");
                    pubkey.retain(|c| !c.is_whitespace());
                    pubkey
                })
            });

            match cmd.sig_type {
                SigType::Ecdsa => {
                    let res = verify(cmd.signature, cmd.message, pubkey)?;
                    println!("{}", res);
                }
                SigType::Schnorr => {
                    let res = verify_schnorr(cmd.signature, cmd.message, pubkey)?;
                    println!("{}", res);
                }
                SigType::BtcLegacy => {
                    let ret = verify_message(cmd.signature, pubkey, cmd.message)?;
                    println!("{}", ret);
                }
            }
        }
        Opt::MultisigSetup(mut cmd) => {
            if cmd.pubkeys.is_none() {
                let stdin = io::stdin();
                let pubkeys: Vec<String> = stdin.lock().lines().collect::<Result<_, _>>()?;
                cmd.pubkeys = Some(pubkeys);
            }

            println!("{}", serde_json::to_string(&cmd)?);
        }
        Opt::MultisigConstruct(cmd) => {
            println!("{}", serde_json::to_string(&cmd)?);
        }
        Opt::MultisigSign(mut cmd) => {
            let stdin = io::stdin();
            let lines: Vec<String> = stdin.lock().lines().collect::<Result<_, _>>()?;
            if lines.len() == 2 {
                cmd.secret = Some(lines[1].clone());
            }

            let mut js: CmdMultisigConstruct = serde_json::from_str(&lines[0])?;
            js.signatures = None;
            let mut j = serde_json::to_string(&js)?;
            j.retain(|c| !c.is_whitespace());

            let sig = sign(cmd.secret.unwrap(), j)?;
            let mut sigs = js.signatures.unwrap_or_else(Vec::new);
            sigs.push(sig.to_cmpact());
            js.signatures = Some(sigs);

            println!("{}", serde_json::to_string(&js)?);
        }
        Opt::MultisigVerify => {
            let multisig_reader = BufReader::new(io::stdin());
            let obj: CmdMultisigConstruct = serde_json::from_reader(multisig_reader)?;
            let ret = multisig_verify(obj)?;
            println!("{}", ret);
        }
        Opt::MultisigCombine => {
            let stdin = io::stdin();
            let mut objects: Vec<CmdMultisigConstruct> = stdin.lock().lines()
                .map(|line| serde_json::from_str(&line.expect("Invalid input")).expect("Failed to parse JSON"))
                .collect();
            let ret = multisig_combine(&mut objects)?;
            println!("{}", serde_json::to_string(&ret)?);
        }
    }
    Ok(())
}
