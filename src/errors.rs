use std::fmt;

extern crate secp256k1;

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

impl fmt::Display for MusignError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.kind)
    }
}
