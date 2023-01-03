//! For most use-cases you can just use `pkip::send` and `pkip::recv`.
//! Those function use a default global `Pkip` object.
//! Use this struct directly if you need control over things like which
//! directory server to use.

use std::{
    io,
    net::SocketAddr,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::net::UdpSocket;

use crate::{packet::PUBLIC_KEY_SIZE, KeyPair, PkipPacket, PublicKey};

pub async fn send_plaintext(
    sock: &UdpSocket,
    directory_server: SocketAddr,
    dest: PublicKey,
    message: &[u8],
) -> io::Result<()> {
    // This function allocates. Can we make a non-allocating version of this function
    // that is pleasant to use?
    // perhaps https://docs.rs/bytes/latest/bytes/struct.Bytes.html
    let payload = PkipPacket::send(dest, message);
    let sent = sock.send_to(&payload, directory_server).await?;
    if sent < payload.len() {
        return Err(not_fully_sent());
    }
    Ok(())
}

/// Receive an unsecured message.
///
/// Returns the destination key for the message as well as the length of the message.
///
/// If a message is too long to fit in the supplied buffer, excess bytes may be
/// discarded.
///
/// This function does not return any sort of address of the sender. That functionality
/// should be implemented at a higher layer.
pub async fn recv_plaintext(sock: &UdpSocket, buf: &mut [u8]) -> io::Result<(PublicKey, usize)> {
    // This function allocates. Can we make a non-allocating version of this function
    // that is pleasant to use?
    // perhaps https://docs.rs/bytes/latest/bytes/struct.Bytes.html
    let mut payload = vec![0u8; buf.len() + PUBLIC_KEY_SIZE];
    loop {
        let (len, _addr) = sock.recv_from(&mut payload).await?;
        if len < PUBLIC_KEY_SIZE {
            continue;
        }
        let pk = PublicKey((&payload[..PUBLIC_KEY_SIZE]).try_into().unwrap());
        let retlen = len - PUBLIC_KEY_SIZE;
        buf[..retlen].copy_from_slice(&payload[PUBLIC_KEY_SIZE..len]);
        return Ok((pk, retlen));
    }
}

/// Sign and send a Register packet to a directory server. Don't check to verify it worked.
pub async fn register_unreliable(
    sock: &UdpSocket,
    directory_server: SocketAddr,
    id: &KeyPair,
    my_addr: SocketAddr,
) -> io::Result<()> {
    let payload = PkipPacket::register(
        id,
        my_addr,
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    );
    let sent = sock.send_to(&payload, directory_server).await?;
    if sent < payload.len() {
        return Err(not_fully_sent());
    }
    Ok(())
}

// /// Send an authenticated and encrypted message to a remote server.
// pub fn send(src: &KeyPair, dest: &PublicKey, message: &[u8]) -> io::Result<()> {
//     // since we know the public key of the "responder" we might be able to do a
//     // "zero-RTT" noise protocol handshake
//     // Handshake pattern here will be "XK" or "IK"
//     // https://noiseprotocol.org/noise.html
//     todo!()
// }

// /// Receive an authenticated and encrypted message.
// pub fn recv(dest: &KeyPair, buf: &mut [u8]) -> io::Result<(usize, PublicKey)> {
//     todo!()
// }

fn not_fully_sent() -> io::Error {
    io::Error::new(io::ErrorKind::Other, "full packet was not written")
}
