use std::convert::TryInto;

use ring::rand;
use ring::signature::{self, Ed25519KeyPair, KeyPair};

#[derive(PartialEq, Eq, Debug, Clone, Copy, Hash)]
pub struct PublicKey(pub [u8; 32]);

#[derive(PartialEq, Eq, Debug, Clone, Copy, Hash)]
pub struct Signature(pub [u8; 64]);

pub struct Keypair {
    kp: Ed25519KeyPair,
}

impl Keypair {
    pub fn generate() -> Self {
        let rng = rand::SystemRandom::new();
        let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        Self {
            kp: Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap(),
        }
    }

    pub fn public(&self) -> PublicKey {
        PublicKey(self.kp.public_key().as_ref().try_into().unwrap())
    }

    pub fn sign(&self, bs: &[u8]) -> Signature {
        Signature(self.kp.sign(bs).as_ref().try_into().unwrap())
    }
}

pub fn valid(public_key: PublicKey, message: &[u8], sig: Signature) -> bool {
    signature::UnparsedPublicKey::new(&signature::ED25519, public_key.0)
        .verify(message, &sig.0)
        .is_ok()
}

#[cfg(test)]
mod test {
    use crate::{signatures::valid, Keypair};

    #[test]
    fn sigs() {
        let payload = [1u8];
        let kp = Keypair::generate();
        let sig = kp.sign(&payload);

        assert!(valid(kp.public(), &payload, sig));
        assert!(!valid(kp.public(), &[], sig));
        assert!(!valid(Keypair::generate().public(), &[], sig));
    }
}
