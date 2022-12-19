use futures::future::select;
use std::{net::Ipv6Addr, time::Duration};
use tokio::net::UdpSocket;

use pkip::{directory_server, KeyPair, PlaintextSocket, PublicKey};

/// Test example does not encrypt or authenticate traffic. It's just testing routing.
#[tokio::test]
async fn foo() {
    let port_unspecified = 0;

    // start directory server
    let dir_sock = UdpSocket::bind((Ipv6Addr::LOCALHOST, port_unspecified))
        .await
        .unwrap();
    let dir_server_addr = dir_sock.local_addr().unwrap();
    let directory_server = async {
        directory_server(dir_sock).await.unwrap();
    };

    // Start application server, register with directory server. Be an echo server.
    let app_server_kp = KeyPair::generate();
    let app_server_pk = app_server_kp.public();
    let application_server = async {
        tokio::time::sleep(Duration::from_millis(10)).await;
        let sock = UdpSocket::bind((Ipv6Addr::LOCALHOST, port_unspecified))
            .await
            .unwrap();
        let my_addr = sock.local_addr().unwrap();
        let sock = PlaintextSocket::register(dir_server_addr, sock, app_server_kp, my_addr)
            .await
            .unwrap();
        let sending_sock = UdpSocket::bind((Ipv6Addr::LOCALHOST, port_unspecified))
            .await
            .unwrap();

        let mut buf = vec![0; u16::max_value() as usize];
        loop {
            let range = sock.recv_from(&mut buf).await.unwrap();
            let (return_addr, message) = buf[range].split_at(32);
            let return_addr: PublicKey = PublicKey(return_addr.try_into().unwrap());
            PlaintextSocket::send(&sending_sock, dir_server_addr, return_addr, message)
                .await
                .unwrap();
        }
    };

    // start client
    let application_client = async {
        tokio::time::sleep(Duration::from_millis(100)).await;

        let kp = KeyPair::generate();
        let my_pk = kp.public();
        let recv = UdpSocket::bind((Ipv6Addr::LOCALHOST, port_unspecified))
            .await
            .unwrap();
        let my_addr = recv.local_addr().unwrap();
        let recv = PlaintextSocket::register(dir_server_addr, recv, kp, my_addr)
            .await
            .unwrap();

        let send = UdpSocket::bind((Ipv6Addr::LOCALHOST, port_unspecified))
            .await
            .unwrap();

        let payload: Vec<u8> = my_pk.0.iter().chain(b"Hello Worl").copied().collect();

        PlaintextSocket::send(&send, dir_server_addr, app_server_pk, &payload)
            .await
            .unwrap();

        let mut buf = vec![0; u16::max_value() as usize];
        let range = recv.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[range], b"Hello Worl");
    };

    let allem = select(
        select(Box::pin(directory_server), Box::pin(application_server)),
        Box::pin(application_client),
    );
    tokio::time::timeout(Duration::from_millis(1000), allem)
        .await
        .unwrap();
}
