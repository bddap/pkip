mod signatures;

use std::{
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
pub struct Register<'a> {
    bs: &'a [u8; Register::REGISTER_SIZE],
}

impl<'a> Register<'a> {
    const PUBLIC_KEY_START: usize = 0;
    const PUBLIC_KEY_END: usize = Self::PUBLIC_KEY_START + 32;
    const SOCKET_ADDRESS_START: usize = Self::PUBLIC_KEY_END;
    const SOCKET_ADDRESS_END: usize = Self::SOCKET_ADDRESS_START + 18;
    const TIMESTAMP_START: usize = Self::SOCKET_ADDRESS_END;
    const TIMESTAMP_END: usize = Self::TIMESTAMP_START + 16;
    const SIGNATURE_START: usize = Self::TIMESTAMP_END;
    const SIGNATURE_END: usize = Self::TIMESTAMP_END + 64;
    const REGISTER_SIZE: usize = Self::SIGNATURE_END;

    /// return the Forward type packet or None if the input
    /// is not the right size
    pub fn parse(bs: &'a [u8]) -> Option<Self> {
        Some(Self {
            bs: bs.try_into().ok()?,
        })
    }

    /// Check whether the signature is valid
    pub fn verify_signature(&self) -> bool {
        // we should let register just be a reference to an array
        // then add getters for each field
        valid(self.address(), self.signed_message(), self.signature())
    }

    pub fn address(&self) -> PublicKey<'a> {
        PublicKey(
            self.bs[Self::PUBLIC_KEY_START..Self::PUBLIC_KEY_END]
                .try_into()
                .unwrap(),
        )
    }

    pub fn socket_address(&self) -> SocketAddr {
        parse_socketaddr(
            self.bs[Self::SOCKET_ADDRESS_START..Self::SOCKET_ADDRESS_END]
                .try_into()
                .unwrap(),
        )
    }

    pub fn timestamp_nanos(&self) -> u128 {
        u128::from_be_bytes(
            self.bs[Self::TIMESTAMP_START..Self::TIMESTAMP_END]
                .try_into()
                .unwrap(),
        )
    }

    pub fn signature(&self) -> Signature<'a> {
        Signature(
            self.bs[Self::SIGNATURE_START..Self::SIGNATURE_END]
                .try_into()
                .unwrap(),
        )
    }

    pub fn signed_message(
        &self,
    ) -> &'a [u8; Register::TIMESTAMP_END - Register::SOCKET_ADDRESS_START] {
        self.bs[Self::SOCKET_ADDRESS_START..Self::TIMESTAMP_END]
            .try_into()
            .unwrap()
    }
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
        let packet = [
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
        let r = Register::parse(&packet).unwrap();
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
