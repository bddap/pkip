//! Reference implementation of the pkip directory server using tokio
//! as an async runtime.

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv6Addr, SocketAddr},
};

use crate::{PkipPacket, PublicKey};

// be a pkip registry, listen for udp
//
// when a register packet is recieved, verify the signature
//   right now we verify that actual ip == specified ip
//   save in registry
//
// when a forward packet is recieved, forward it byte for byte to
// the socketaddr of the target. if you don't have the ip of the target stored
// drop the packet
pub async fn directory_server(sock: tokio::net::UdpSocket) -> std::io::Result<()> {
    let mut registry: HashMap<PublicKey, (u128, SocketAddr)> = HashMap::new();

    let mut buf = vec![0; u16::max_value() as usize];
    loop {
        let (amt, src) = sock.recv_from(&mut buf).await?;
        let filled = &buf[..amt];
        let Some(pack) = PkipPacket::parse(filled) else {
            continue;
        };
        match pack {
            PkipPacket::Register(r) => {
                let socket_address = canonical_socketaddr(r.socket_address());
                if socket_address != canonical_socketaddr(src) {
                    continue;
                }
                if !r.verify_signature() {
                    continue;
                }
                let timestamp = r.timestamp_nanos();
                let val = registry
                    .entry(r.signing_key())
                    .or_insert_with(|| (timestamp, socket_address));
                if val.0 < timestamp {
                    *val = (timestamp, socket_address);
                }
            }
            PkipPacket::Send(f) => {
                let Some((_, socket_address)) = registry.get(&f.destination_signing_key()) else {
                    continue;
                };

                // we include the address in the forwarded packet
                sock.send_to(f.backing(), socket_address).await?;
            }
        }
    }
}

fn canonical_socketaddr(mut sa: SocketAddr) -> SocketAddr {
    let ip = sa.ip();
    sa.set_ip(cononical_ip(ip));
    sa
}

fn cononical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        v4 @ IpAddr::V4(_) => v4,
        IpAddr::V6(v6) => canonical_ipv6(v6),
    }
}

fn canonical_ipv6(v6: Ipv6Addr) -> IpAddr {
    if let Some(mapped) = v6.to_ipv4_mapped() {
        IpAddr::V4(mapped)
    } else {
        // reset flowcontrol data
        let v6 = Ipv6Addr::from(v6.octets());
        IpAddr::V6(v6)
    }
}
