use ring::signature;

#[derive(PartialEq, Eq, Debug)]
pub struct PublicKey(pub [u8; 32]);

#[derive(PartialEq, Eq, Debug)]
pub struct Signature(pub [u8; 64]);

pub fn valid(public_key: &PublicKey, message: &[u8], sig: &Signature) -> bool {
    signature::UnparsedPublicKey::new(&signature::ED25519, &public_key.0)
        .verify(message, &sig.0)
        .is_ok()
}

#[cfg(test)]
mod test {
    #[test]
    fn test() {
        // use ring::{
        //     rand,
        //     signature::{self, KeyPair},
        // };

        // // Generate a key pair in PKCS#8 (v2) format.
        // let rng = rand::SystemRandom::new();
        // let pkcs8_bytes = signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();

        // // Normally the application would store the PKCS#8 file persistently. Later
        // // it would read the PKCS#8 file from persistent storage to use it.

        // let key_pair = signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();

        // // Sign the message "hello, world".
        // const MESSAGE: &[u8] = b"hello, world";
        // let sig = key_pair.sign(MESSAGE);
        // dbg!(sig.as_ref().len());

        // // Normally an application would extract the bytes of the signature and
        // // send them in a protocol message to the peer(s). Here we just get the
        // // public key key directly from the key pair.
        // let peer_public_key_bytes = key_pair.public_key().as_ref();
        // dbg!(peer_public_key_bytes.len());

        // // Verify the signature of the message using the public key. Normally the
        // // verifier of the message would parse the inputs to this code out of the
        // // protocol message(s) sent by the signer.
        // let peer_public_key =
        //     signature::UnparsedPublicKey::new(&signature::ED25519, peer_public_key_bytes);
        // peer_public_key.verify(MESSAGE, sig.as_ref()).unwrap();
        // todo!()
    }
}
