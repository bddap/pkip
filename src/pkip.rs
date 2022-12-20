//! For most use-cases you can just use `pkip::send` and `pkip::recv`.
//! Those function use a default global `Pkip` object.
//! Use this struct directly if you need control over things like which
//! directory server to use.

use std::{collections::HashMap, io, net::SocketAddr, ops::Range, time::Instant};

use crate::{
    packet::{Register, REGISTER_SIZE},
    KeyPair, PublicKey,
};

pub struct Pkip {
    directory_servers: Vec<SocketAddr>,

    /// verifying a signature is expensive? We don't verify until necessary.
    pending_introductions: HashMap<PublicKey, Register<[u8; REGISTER_SIZE]>>,

    /// Introductions with valid signatures.
    verified_introductions: HashMap<PublicKey, Register<[u8; REGISTER_SIZE]>>,

    /// An introductory message has been sent. Waiting for response.
    /// The value of this map is "When did we send of the last request for introduction"
    awaiting_callback: HashMap<PublicKey, Instant>,
}

impl Pkip {
    pub fn new(directory_servers: Vec<SocketAddr>) -> Self {
        Pkip {
            directory_servers,
            pending_introductions: Default::default(),
            verified_introductions: Default::default(),
            awaiting_callback: Default::default(),
        }
    }
}

impl Pkip {
    /// Send an unsecured message to a remote server.
    pub async fn send_plaintext(dest: &PublicKey, message: &[u8]) -> io::Result<()> {
        todo!()
    }

    /// Recieve an unsecured message.
    pub fn recv_plaintext(dest: &KeyPair, buf: &mut [u8]) -> io::Result<Range<usize>> {
        todo!()
    }

    /// Send an authenticated and encrypted message to a remote server.
    pub fn send(src: &KeyPair, dest: &PublicKey, message: &[u8]) -> io::Result<()> {
        // since we know the public key of the "responder" we might be able to do a
        // "zero-RTT" noise protocol handshake
        // Handshake pattern here will be "XK" or "IK"
        // https://noiseprotocol.org/noise.html
        todo!()
    }

    /// Send an authenticated and encrypted message.
    pub fn recv(dest: &KeyPair, buf: &mut [u8]) -> io::Result<(Range<usize>, PublicKey)> {
        todo!()
    }
}
