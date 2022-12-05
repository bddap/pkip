use std::{
    collections::HashMap,
    net::{IpAddr, Ipv6Addr, SocketAddr, UdpSocket},
};

use pkip::{PkipPacket, PublicKey};

// be a pkip registry, listen for udp
//
// when a register packet is recieved, verify the signature
//   right now we verify that actual ip == specified ip
//   save in registry
//
// when a forward packet is recieved, forward it byte for byte to
// the socketaddr of the target. if you don't have the ip of the target stored
// drop the packet
fn main() -> anyhow::Result<()> {
    let mut registry: HashMap<PublicKey, (u128, SocketAddr)> = HashMap::new();

    let socket = UdpSocket::bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 61982))?;

    let mut buf = vec![0; u16::max_value() as usize];
    loop {
        let (amt, src) = socket.recv_from(&mut buf)?;
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
                    .entry(r.address())
                    .or_insert_with(|| (timestamp, socket_address));
                if val.0 < timestamp {
                    *val = (timestamp, socket_address);
                }
            }
            PkipPacket::Forward(f) => {
                let Some((_, socket_address)) = registry.get(&f.address) else {
                    continue;
                };
                socket.send_to(f.payload, socket_address)?;
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
