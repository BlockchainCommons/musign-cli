extern crate bitcoin;
extern crate secp256k1;
extern crate serde_json;

#[derive(Debug)]
pub struct MusignError {
    kind: String,
    message: String,
}

impl From<secp256k1::Error> for MusignError {
    fn from(error: secp256k1::Error) -> Self {
        MusignError {
            kind: String::from("secp256k1"),
            message: error.to_string(),
        }
    }
}

impl From<serde_json::Error> for MusignError {
    fn from(error: serde_json::Error) -> Self {
        MusignError {
            kind: String::from("serde_json"),
            message: error.to_string(),
        }
    }
}

impl From<serde_cbor::Error> for MusignError {
    fn from(error: serde_cbor::Error) -> Self {
        MusignError {
            kind: String::from("serde_cbor"),
            message: error.to_string(),
        }
    }
}

impl From<std::io::Error> for MusignError {
    fn from(error: std::io::Error) -> Self {
        MusignError {
            kind: String::from("stdio"),
            message: error.to_string(),
        }
    }
}

impl From<bitcoin::Error> for MusignError {
    fn from(error: bitcoin::Error) -> Self {
        MusignError {
            kind: String::from("bitcoin"),
            message: error.to_string(),
        }
    }
}

impl From<bitcoin::util::misc::MessageSignatureError> for MusignError {
    fn from(error: bitcoin::util::misc::MessageSignatureError) -> Self {
        MusignError {
            kind: String::from("bitcoin"),
            message: error.to_string(),
        }
    }
}

impl From<bitcoin::util::address::Error> for MusignError {
    fn from(error: bitcoin::util::address::Error) -> Self {
        MusignError {
            kind: String::from("bitcoin"),
            message: error.to_string(),
        }
    }
}

impl MusignError {
    pub fn new(kind: String, message: String) -> Self {
        MusignError { kind, message }
    }
}
