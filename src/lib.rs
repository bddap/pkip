mod signatures;

use std::{
    borrow::{Borrow, BorrowMut},
    convert::TryInto,
    net::{IpAddr, Ipv6Addr, SocketAddr},
};

use signatures::{valid, PublicKey, Signature};

#[derive(PartialEq, Eq, Debug)]
pub struct Forward<'a> {
    pub address: PublicKey<'a>,
    pub payload: &'a [u8],
}

impl<'a> Forward<'a> {
    /// return the Forward type packet or None if the input
    /// is too short
    pub fn parse(bs: &'a [u8]) -> Option<Self> {
        let (public_key, payload) = take_array_ref(bs)?;
        Some(Self {
            address: PublicKey(public_key),
            payload,
        })
    }
}

#[derive(PartialEq, Eq, Debug)]
pub struct Register<T> {
    bs: T,
}

const PUBLIC_KEY_START: usize = 0;
const PUBLIC_KEY_SIZE: usize = 32;
const SOCKET_ADDRESS_START: usize = PUBLIC_KEY_START + PUBLIC_KEY_SIZE;
const SOCKET_ADDRESS_SIZE: usize = 18;
const TIMESTAMP_START: usize = SOCKET_ADDRESS_START + SOCKET_ADDRESS_SIZE;
const TIMESTAMP_SIZE: usize = 16;
const SIGNATURE_START: usize = TIMESTAMP_START + TIMESTAMP_SIZE;
const SIGNATURE_SIZE: usize = 64;
const REGISTER_SIZE: usize = SIGNATURE_START + SIGNATURE_SIZE;

impl<T> Register<T>
where
    T: Borrow<[u8; REGISTER_SIZE]>,
{
    /// Check whether the signature is valid
    pub fn verify_signature(&self) -> bool {
        // we should let register just be a reference to an array
        // then add getters for each field
        valid(self.address(), self.signed_message(), self.signature())
    }

    fn range<const START: usize, const LEN: usize>(&self) -> &[u8; LEN] {
        range::<u8, START, LEN, REGISTER_SIZE>(self.bs.borrow())
    }

    pub fn address(&self) -> PublicKey {
        PublicKey(self.range::<PUBLIC_KEY_START, PUBLIC_KEY_SIZE>())
    }

    pub fn socket_address(&self) -> SocketAddr {
        parse_socketaddr(self.range::<SOCKET_ADDRESS_START, SOCKET_ADDRESS_SIZE>())
    }

    pub fn timestamp_nanos(&self) -> u128 {
        u128::from_be_bytes(*self.range::<TIMESTAMP_START, TIMESTAMP_SIZE>())
    }

    pub fn signature(&self) -> Signature {
        Signature(self.range::<SIGNATURE_START, SIGNATURE_SIZE>())
    }

    pub fn signed_message(&self) -> &[u8; SIGNATURE_START - SOCKET_ADDRESS_START] {
        self.range::<SOCKET_ADDRESS_START, { SIGNATURE_START - SOCKET_ADDRESS_START }>()
    }
}

impl<T> Register<T>
where
    T: BorrowMut<[u8; REGISTER_SIZE]>,
{
    fn range_mut<const START: usize, const LEN: usize>(&mut self) -> &mut [u8; LEN] {
        range_mut::<u8, START, LEN, REGISTER_SIZE>(self.bs.borrow_mut())
    }

    pub fn set_address(&mut self, address: PublicKey) {
        *self.range_mut::<PUBLIC_KEY_START, PUBLIC_KEY_SIZE>() = *address.0;
    }

    pub fn set_socket_address(&self, socket_address: SocketAddr) {
        todo!()
    }

    pub fn set_timestamp_nanos(&self, timestamp_nanos: u128) {
        todo!()
    }

    pub fn set_signature(&self, signature: Signature) {
        todo!()
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

fn write_socketaddr(sa: SocketAddr) -> [u8; 18] {
    todo!()
}

fn take_array_ref<T, const N: usize>(slice: &[T]) -> Option<(&[T; N], &[T])> {
    if slice.len() < N {
        return None;
    }
    let (a, b) = slice.split_at(N);
    let a = a.try_into().unwrap();
    Some((a, b))
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddrV4, SocketAddrV6};

    use super::*;

    #[test]
    fn parse_forward() {
        #[rustfmt::skip]
        let packet = [
            // public key
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,

            // payload
            0x02,
        ];
        assert_eq!(
            Forward::parse(&packet).unwrap(),
            Forward {
                address: PublicKey(&[
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
                ]),
                payload: &[0x02]
            }
        )
    }

    #[test]
    fn parse_register() {
        #[rustfmt::skip]
        let packet: [u8; REGISTER_SIZE] = [
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
        let r = Register { bs: &packet };
        assert_eq!(
            r.address(),
            PublicKey(&[
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
            Signature(&[
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
        todo!()
    }

    /// Check that tampered body does not verify.
    #[test]
    fn tamper_verify() {
        todo!()
    }

    /// Check that properly signed  body does verify.
    #[test]
    fn sign_verify() {
        todo!()
    }
}
