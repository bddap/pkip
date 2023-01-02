use std::net::{IpAddr, Ipv6Addr, SocketAddr, UdpSocket};

use pkip::directory_server;

// TODO:
//   implement an example of a process listening on a public key
//   implement an example of a client sending messages to that process

// be a pkip registry over udp
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let socket = UdpSocket::bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 61982))?;
    directory_server(socket.try_into().unwrap()).await?;
    Ok(())
}
