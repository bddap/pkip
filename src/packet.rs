use std::{
    borrow::{Borrow, BorrowMut},
    convert::TryInto,
    iter::once,
    net::{IpAddr, Ipv6Addr, SocketAddr},
};

use crate::{
    signatures::{valid, PublicKey, Signature},
    KeyPair,
};

#[derive(PartialEq, Eq, Debug)]
pub enum PkipPacket<'a> {
    Register(Register<&'a [u8; REGISTER_SIZE]>),
    Send(Send<'a>),
}

pub const TAG_SEND: u8 = 0;
pub const TAG_REGISTER: u8 = 1;

impl<'a> PkipPacket<'a> {
    pub fn parse(payload: &'a [u8]) -> Option<Self> {
        let (first, rest) = payload.split_first()?;
        match *first {
            self::TAG_SEND => Some(Self::Send(Send::parse(rest)?)),
            self::TAG_REGISTER => Some(Self::Register(Register {
                bs: rest.try_into().ok()?,
            })),
            _ => None,
        }
    }

    /// Create and sign a registration packet.
    pub fn register(
        id: &KeyPair,
        my_addr: SocketAddr,
        timestamp_nanos: u128,
    ) -> [u8; REGISTER_SIZE + 1] {
        let mut ret = [0u8; REGISTER_SIZE + 1];
        ret[0] = TAG_REGISTER;
        let register_section: &mut [u8; REGISTER_SIZE] = (&mut ret[1..]).try_into().unwrap();
        let mut reg = Register {
            bs: register_section,
        };
        reg.set_address(id.public());
        reg.set_socket_address(my_addr);
        reg.set_timestamp_nanos(timestamp_nanos);
        let sig = id.sign(reg.signature_target());
        reg.set_signature(sig);
        ret
    }

    /// Create a forward packet. Does allocate.
    pub fn send(destination: PublicKey, payload: &[u8]) -> Vec<u8> {
        once(TAG_SEND)
            .chain(destination.0)
            .chain(payload.into_iter().copied())
            .collect()
    }
}

#[derive(PartialEq, Eq, Debug)]
pub struct Send<'a> {
    bs: &'a [u8],
}

impl<'a> Send<'a> {
    /// return the Forward type packet or None if the input
    /// is too short
    pub fn parse(bs: &'a [u8]) -> Option<Self> {
        if bs.len() < PUBLIC_KEY_SIZE {
            None
        } else {
            Some(Self { bs })
        }
    }

    /// return the singing key of the process to which this packet
    /// should be sent
    pub fn destination_signing_key(&self) -> PublicKey {
        PublicKey(self.bs[..PUBLIC_KEY_SIZE].try_into().unwrap())
    }

    pub fn payload(&self) -> &'a [u8] {
        &self.bs[PUBLIC_KEY_SIZE..]
    }

    pub fn backing(&self) -> &'a [u8] {
        &self.bs
    }
}

#[derive(PartialEq, Eq, Debug)]
pub struct Register<T> {
    bs: T,
}

const PUBLIC_KEY_START: usize = 0;
pub const PUBLIC_KEY_SIZE: usize = 32;
const SOCKET_ADDRESS_START: usize = PUBLIC_KEY_START + PUBLIC_KEY_SIZE;
const SOCKET_ADDRESS_SIZE: usize = 18;
const TIMESTAMP_START: usize = SOCKET_ADDRESS_START + SOCKET_ADDRESS_SIZE;
const TIMESTAMP_SIZE: usize = 16;
const SIGNATURE_START: usize = TIMESTAMP_START + TIMESTAMP_SIZE;
const SIGNATURE_SIZE: usize = 64;
pub const REGISTER_SIZE: usize = SIGNATURE_START + SIGNATURE_SIZE;

impl<T> Register<T> {
    /// parsing is free!
    pub fn parse(bs: T) -> Self {
        Register { bs }
    }
}

impl<T> Register<T>
where
    T: Borrow<[u8; REGISTER_SIZE]>,
{
    /// Check whether the signature is valid
    pub fn verify_signature(&self) -> bool {
        valid(
            self.signing_key(),
            self.signature_target(),
            self.signature(),
        )
    }

    pub fn signing_key(&self) -> PublicKey {
        PublicKey(*self.range::<PUBLIC_KEY_START, PUBLIC_KEY_SIZE>())
    }

    pub fn socket_address(&self) -> SocketAddr {
        parse_socketaddr(self.range::<SOCKET_ADDRESS_START, SOCKET_ADDRESS_SIZE>())
    }

    pub fn timestamp_nanos(&self) -> u128 {
        u128::from_be_bytes(*self.range::<TIMESTAMP_START, TIMESTAMP_SIZE>())
    }

    pub fn signature(&self) -> Signature {
        Signature(*self.range::<SIGNATURE_START, SIGNATURE_SIZE>())
    }

    pub fn signature_target(&self) -> &[u8; SIGNATURE_START - PUBLIC_KEY_START] {
        self.range::<PUBLIC_KEY_START, { SIGNATURE_START - PUBLIC_KEY_START }>()
    }

    fn range<const START: usize, const LEN: usize>(&self) -> &[u8; LEN] {
        range::<u8, START, LEN, REGISTER_SIZE>(self.bs.borrow())
    }
}

impl<T> Register<T>
where
    T: BorrowMut<[u8; REGISTER_SIZE]>,
{
    pub fn set_address(&mut self, address: PublicKey) {
        *self.range_mut::<PUBLIC_KEY_START, PUBLIC_KEY_SIZE>() = address.0;
    }

    pub fn set_socket_address(&mut self, socket_address: SocketAddr) {
        *self.range_mut::<SOCKET_ADDRESS_START, SOCKET_ADDRESS_SIZE>() =
            write_socketaddr(socket_address);
    }

    pub fn set_timestamp_nanos(&mut self, timestamp_nanos: u128) {
        *self.range_mut::<TIMESTAMP_START, TIMESTAMP_SIZE>() = timestamp_nanos.to_be_bytes();
    }

    pub fn set_signature(&mut self, signature: Signature) {
        *self.range_mut::<SIGNATURE_START, SIGNATURE_SIZE>() = signature.0;
    }

    fn range_mut<const START: usize, const LEN: usize>(&mut self) -> &mut [u8; LEN] {
        range_mut::<u8, START, LEN, REGISTER_SIZE>(self.bs.borrow_mut())
    }
}

fn range<T, const START: usize, const LEN: usize, const CONTAINER: usize>(
    bs: &[T; CONTAINER],
) -> &[T; LEN] {
    assert!(START + LEN <= CONTAINER);
    bs[START..(START + LEN)].try_into().unwrap()
}

fn range_mut<T, const START: usize, const LEN: usize, const CONTAINER: usize>(
    bs: &mut [T; CONTAINER],
) -> &mut [T; LEN] {
    assert!(START + LEN <= CONTAINER);
    bs.get_mut(START..(START + LEN))
        .unwrap()
        .try_into()
        .unwrap()
}

fn parse_socketaddr(dat: &[u8; 18]) -> SocketAddr {
    let (addr, port) = dat.split_at(16);

    // ipv4 addresses are supported via ipv4-mapped ipv6 addresses
    let addr: [u8; 16] = addr.try_into().unwrap();
    let addr = Ipv6Addr::from(addr);
    let addr = match addr.to_ipv4_mapped() {
        Some(ipv4) => IpAddr::V4(ipv4),
        None => IpAddr::V6(addr),
    };

    let port: [u8; 2] = port.try_into().unwrap();
    let port = u16::from_be_bytes(port);

    SocketAddr::new(addr, port)
}

fn canonical_ipv6(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, d] = v4.octets();
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, a, b, c, d]
        }
        IpAddr::V6(v6) => v6.octets(),
    }
}

fn write_socketaddr(sa: SocketAddr) -> [u8; 18] {
    let addr = canonical_ipv6(sa.ip());
    let [porta, portb] = sa.port().to_be_bytes();
    [
        addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7], addr[8], addr[9],
        addr[10], addr[11], addr[12], addr[13], addr[14], addr[15], porta, portb,
    ]
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddrV4, SocketAddrV6};

    use rand::{rngs::SmallRng, Rng, SeedableRng};

    use super::*;

    #[rustfmt::skip]
    const REGISTER_PACKET: [u8; REGISTER_SIZE + 1] = [
        0x01,                                           // ] tag == 0x01 identifies packet as register
                                                        //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ] public key
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ]
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ]
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // ]
                                                        //
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ] ipv6 addr ] socket addr ] signature target
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ]           ]             ]
                                                        //             ]             ]
        0x00, 0x03,                                     // ] port      ]             ]
                                                        //                           ]
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ] timestamp nanos         ]
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, // ]                         ]
                                                        //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ] signature
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ]
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ]
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // ]
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ]
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ]
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ]
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // ]
    ];

    #[rustfmt::skip]
    const FORWARD_PACKET: &[u8] = &[
        0x00,                                           // ] tag == 0x00 identifies packet as forward
                                                        //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ] public key
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ]
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ]
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // ]
                                                        //
        0x02,                                           // ] payload, has arbitrary length
    ];

    #[test]
    fn parse_forward() {
        let packet = PkipPacket::parse(FORWARD_PACKET).unwrap();
        let PkipPacket::Send(send) = packet else {
            panic!();
        };
        assert_eq!(
            send.destination_signing_key(),
            PublicKey([
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x01,
            ])
        );
        assert_eq!(send.payload(), &[0x02])
    }

    #[test]
    fn construct_register() {
        let kp = KeyPair::generate();
        let addr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 3, 0, 0));
        let timestamp_nanos = rand::random();
        let register = PkipPacket::register(&kp, addr, timestamp_nanos);
        let packet = PkipPacket::parse(&register).unwrap();
        let packet = match packet {
            PkipPacket::Register(r) => r,
            PkipPacket::Send(_) => panic!(),
        };
        assert_eq!(packet.signing_key(), kp.public());
        assert_eq!(packet.socket_address(), addr);
        assert_eq!(packet.timestamp_nanos(), timestamp_nanos);
        assert!(packet.verify_signature());
    }

    #[test]
    fn parse_register() {
        match PkipPacket::parse(&REGISTER_PACKET) {
            Some(PkipPacket::Register(_)) => {}
            _ => panic!(),
        }
    }

    #[test]
    fn parse_register_fields() {
        let r = Register::<&[u8; REGISTER_SIZE]> {
            bs: REGISTER_PACKET[1..].try_into().unwrap(),
        };
        assert_eq!(
            r.signing_key(),
            PublicKey([
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x01,
            ])
        );
        assert_eq!(
            r.socket_address(),
            SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from([
                    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00,
                ]),
                0x0003,
                0,
                0,
            ))
        );
        assert_eq!(r.timestamp_nanos(), 4);
        assert_eq!(
            r.signature(),
            Signature([
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
            ])
        );
    }

    #[test]
    fn socketaddr_parse() {
        assert_eq!(
            parse_socketaddr(&[
                0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x06,
            ]),
            SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from([
                    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00,
                ]),
                0x0006,
                0,
                0,
            )),
        );
        assert_eq!(
            parse_socketaddr(&[
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00,
                0x00, 0x07, 0x00, 0x06,
            ]),
            SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from([0x00, 0x00, 0x00, 0x07]),
                0x0006
            )),
        );
        assert_eq!(
            parse_socketaddr(&[
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ]),
            SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from([
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00,
                ]),
                0x0000,
                0,
                0,
            ))
        );
    }

    /// Check that a random signature does not verify.
    #[test]
    fn badsign_verify() {
        let mut rng = SmallRng::seed_from_u64(0);
        let backing = [(); REGISTER_SIZE].map(|()| rng.gen::<u8>());
        assert!(!Register { bs: backing }.verify_signature());
    }

    /// Check that properly signed  body does verify.
    #[test]
    fn sign_verify() {
        let mut rng = SmallRng::seed_from_u64(0);
        let mut backing = [(); REGISTER_SIZE].map(|()| rng.gen::<u8>());
        let mut r = Register { bs: &mut backing };
        let keypair = crate::KeyPair::generate();
        r.set_address(keypair.public());
        let sig = keypair.sign(r.signature_target());
        assert!(!r.verify_signature());
        r.set_signature(sig);
        assert!(r.verify_signature());

        // tamper
        r.set_timestamp_nanos(r.timestamp_nanos() + 1);
        assert!(!r.verify_signature());
    }
}
