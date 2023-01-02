use futures::future::select;
use std::{net::Ipv6Addr, time::Duration};
use tokio::{net::UdpSocket, time::sleep};

use pkip::{
    directory_server, recv_plaintext, register_unreliable, send_plaintext, KeyPair, PublicKey,
    PUBLIC_KEY_SIZE,
};

/// Test example does not encrypt or authenticate traffic. It's just testing routing.
#[tokio::test]
async fn plaintext_end_to_end() {
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
        sleep(Duration::from_millis(1)).await;
        let sock = UdpSocket::bind((Ipv6Addr::LOCALHOST, port_unspecified))
            .await
            .unwrap();

        register_unreliable(
            &sock,
            dir_server_addr,
            &app_server_kp,
            sock.local_addr().unwrap(),
        )
        .await
        .unwrap();

        let mut buf = vec![0; u16::max_value() as usize];
        loop {
            let (dest_pk, len) = recv_plaintext(&sock, &mut buf).await.unwrap();
            assert_eq!(dest_pk, app_server_kp.public());
            let (return_addr, message) = buf[..len].split_at(PUBLIC_KEY_SIZE);
            let return_addr: PublicKey = PublicKey(return_addr.try_into().unwrap());
            send_plaintext(&sock, dir_server_addr, return_addr, message)
                .await
                .unwrap();
        }
    };

    // start client
    let application_client = async {
        sleep(Duration::from_millis(2)).await;

        let kp = KeyPair::generate();
        let sock = UdpSocket::bind((Ipv6Addr::LOCALHOST, port_unspecified))
            .await
            .unwrap();
        register_unreliable(&sock, dir_server_addr, &kp, sock.local_addr().unwrap())
            .await
            .unwrap();

        let greet = b"Hello Worl";

        let message: Vec<u8> = kp.public().0.iter().chain(greet).copied().collect();
        send_plaintext(&sock, dir_server_addr, app_server_pk, &message)
            .await
            .unwrap();

        let mut buf = vec![0; u16::max_value() as usize];
        let (dest, len) = recv_plaintext(&sock, &mut buf).await.unwrap();
        assert_eq!(dest, kp.public());
        assert_eq!(&buf[..len], greet);
    };

    let allem = select(
        select(Box::pin(directory_server), Box::pin(application_server)),
        Box::pin(application_client),
    );
    tokio::time::timeout(Duration::from_millis(10), allem)
        .await
        .unwrap();
}
