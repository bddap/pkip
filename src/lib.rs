mod directory_server;
mod packet;
mod signatures;
mod util;

use std::{
    iter::once,
    net::SocketAddr,
    ops::Range,
    time::{SystemTime, UNIX_EPOCH},
};

use packet::{Register, PUBLIC_KEY_SIZE, REGISTER_SIZE};
use tokio::net::UdpSocket;
use util::take_array_ref;

pub use directory_server::directory_server;
pub use packet::{PkipPacket, TAG_REGISTER, TAG_SEND};
pub use signatures::{KeyPair, PublicKey, Signature};

pub struct PlaintextSocket {
    sock: tokio::net::UdpSocket,
    addr: PublicKey,
}

impl PlaintextSocket {
    /// Receives a single datagram message on the socket. On success, returns the range
    /// representing the payload.
    ///
    /// The returned range will have a maximum length of `buf.len() - [PUBLIC_KEY_SIZE]`.
    ///
    /// The function must be called with valid byte array buf of sufficient size to hold the
    /// message bytes. If a message is too long to fit in the supplied buffer, excess bytes may be
    /// discarded.
    ///
    /// # Panics
    ///
    /// Panics if buf is smaller than [PUBLIC_KEY_SIZE].
    pub async fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<Range<usize>> {
        assert!(buf.len() >= PUBLIC_KEY_SIZE);
        loop {
            let (len, _addr) = self.sock.recv_from(buf).await?;
            let payload = &buf[..len];
            let Some((pubkey, _payload)) = take_array_ref::<u8, PUBLIC_KEY_SIZE>(payload) else {
                // if packet is too small, keep waiting
                continue;
            };
            let pubkey = PublicKey(*pubkey);
            if self.addr != pubkey {
                // if packet is not addressed to me, keep waiting
                continue;
            }
            // return the payload only, no address
            return Ok(PUBLIC_KEY_SIZE..len);
        }
    }

    pub async fn register(
        directory_server: SocketAddr,
        sock: tokio::net::UdpSocket,
        kp: KeyPair,
        my_address: SocketAddr,
    ) -> std::io::Result<Self> {
        // how do we check whether registration was successful?
        // - Send a Forward packet to self with a random payload?
        // - Make a Lookup query?

        // for now we don't check

        let mut packet = [0u8; REGISTER_SIZE + 1];
        let backing: &mut [u8; REGISTER_SIZE] = (&mut packet[1..]).try_into().unwrap();
        let mut register = Register::parse(backing);
        register.set_address(kp.public());
        register.set_socket_address(my_address);
        register.set_timestamp_nanos(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        );
        let sig = kp.sign(register.signature_target());
        register.set_signature(sig);
        packet[0] = TAG_REGISTER;
        sock.send_to(&packet, directory_server).await?;
        Ok(PlaintextSocket {
            sock,
            addr: kp.public(),
        })
    }

    pub fn unregisted(sock: tokio::net::UdpSocket, addr: PublicKey) -> Self {
        PlaintextSocket { sock, addr }
    }

    pub async fn send(
        src_sock: &UdpSocket,
        directory_server: SocketAddr,
        dest: PublicKey,
        payload: &[u8],
    ) -> std::io::Result<()> {
        let pack: Vec<u8> = once(TAG_SEND)
            .chain(dest.0)
            .chain(payload.iter().copied())
            .collect();
        let sent = src_sock.send_to(&pack, directory_server).await?;
        if sent < payload.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "full packet was not written",
            ));
        }
        Ok(())
    }
}

// pub struct DirectoryClient {
//     // server: SocketAddr,
// }

// consider an "Introduce Us" packet sent from the application client to the directory server
//
// appclient                   directory server                      appserver
//    |      --introduce us-->       |                                   |
//    |                              |          --register client-->     |
//    |      <----------------------------------------------hello------  |
//
// Maybe this can be built atop on the "relay" functionality. Maybe the directory server doesn't
// need to know about "introductions".
