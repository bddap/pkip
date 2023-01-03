use std::{
    collections::HashSet,
    net::{Ipv6Addr, SocketAddr},
    path::PathBuf,
};

use futures::future::select;
use itertools::Itertools;
use pkip::{
    directory_server, recv_plaintext, register_unreliable, send_plaintext, KeyPair, PublicKey,
    PUBLIC_KEY_SIZE,
};
use tokio::{
    fs::{read, write},
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::UdpSocket,
};

#[derive(clap::Parser, Debug)]
enum Args {
    DirectoryServer {
        #[arg(short, long, default_value = "[::1]:24421")]
        listen_on: SocketAddr,
    },
    #[command(arg_required_else_help = true)]
    AppServer {
        #[arg(short, long, default_value = "[::1]:24421")]
        directory_server: SocketAddr,
        #[arg(short, long)]
        save_pubkey: PathBuf,
        /// If provided, register with directory server using this address.
        /// Otherwise use a local address.
        #[arg(short, long)]
        my_addr: Option<SocketAddr>,

        #[arg(short, long)]
        listen_on: Option<SocketAddr>,
    },
    #[command(arg_required_else_help = true)]
    AppClient {
        #[arg(short, long, default_value = "[::1]:24421")]
        directory_server: SocketAddr,
        #[arg(short, long)]
        load_pubkey: PathBuf,

        /// If provided, register with directory server using this address.
        /// Otherwise use a local address.
        #[arg(short, long)]
        my_addr: Option<SocketAddr>,

        #[arg(short, long)]
        listen_on: Option<SocketAddr>,
    },
}

#[tokio::main]
async fn main() {
    let args: Args = clap::Parser::parse();

    eprintln!("{:?}", args);

    match args {
        Args::DirectoryServer { listen_on } => {
            run_directory_server(listen_on).await;
        }
        Args::AppServer {
            directory_server,
            save_pubkey,
            my_addr,
            listen_on,
        } => {
            run_app_server(directory_server, save_pubkey, my_addr, listen_on).await;
        }
        Args::AppClient {
            directory_server,
            load_pubkey,
            my_addr,
            listen_on,
        } => {
            run_client(directory_server, load_pubkey, my_addr, listen_on).await;
        }
    }
}

async fn run_directory_server(listen_on: SocketAddr) {
    let sock = UdpSocket::bind(listen_on).await.unwrap();
    directory_server(sock).await.unwrap();
}

/// this server would be a good target for a udp amplification attack
async fn run_app_server(
    directory_server: SocketAddr,
    dump_pubkey: PathBuf,
    my_addr: Option<SocketAddr>,
    listen_on: Option<SocketAddr>,
) {
    let listen_on = listen_on.unwrap_or(SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 0));
    let sock = UdpSocket::bind(listen_on).await.unwrap();
    let my_addr = my_addr.unwrap_or_else(|| sock.local_addr().unwrap());

    let id = KeyPair::generate();

    let mut subscribed = HashSet::<PublicKey>::new();

    write(dump_pubkey, id.public().0).await.unwrap();

    register_unreliable(&sock, directory_server, &id, my_addr)
        .await
        .unwrap();

    let mut buf = vec![0u8; u16::max_value() as usize + 1];
    loop {
        let (pk, len) = recv_plaintext(&sock, &mut buf).await.unwrap();
        assert_eq!(pk, id.public());
        let message = &buf[..len];

        if message.len() < PUBLIC_KEY_SIZE {
            eprintln!("got message too small");
            continue;
        }
        let pk = PublicKey(message[..PUBLIC_KEY_SIZE].try_into().unwrap());

        subscribed.insert(pk);
        for pk in &subscribed {
            send_plaintext(&sock, directory_server, *pk, message)
                .await
                .unwrap();
        }
    }
}

async fn run_client(
    directory_server: SocketAddr,
    load_pubkey: PathBuf,
    my_addr: Option<SocketAddr>,
    listen_on: Option<SocketAddr>,
) {
    let listen_on = listen_on.unwrap_or(SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 0));
    let sock = UdpSocket::bind(listen_on).await.unwrap();
    let my_addr = my_addr.unwrap_or_else(|| sock.local_addr().unwrap());

    let app_server_pk = read(load_pubkey).await.unwrap();
    let app_server_pk = PublicKey(app_server_pk.try_into().unwrap());

    let kp = KeyPair::generate();

    register_unreliable(&sock, directory_server, &kp, my_addr)
        .await
        .unwrap();

    let read_from_stdin = async {
        let mut stdin = BufReader::new(tokio::io::stdin()).lines();
        let mut message = vec![0u8; 0];
        loop {
            let line = stdin.next_line().await.unwrap();
            let Some(line) = line else {
                break;
            };

            message.clear();
            message.extend(kp.public().0);
            message.extend(line.as_bytes());

            send_plaintext(&sock, directory_server, app_server_pk, &message)
                .await
                .unwrap();
        }
    };

    let write_to_stdout = async {
        let mut stdout = tokio::io::stdout();
        let mut buf = vec![0u8; u16::max_value() as usize + 1];
        loop {
            let (pk, len) = recv_plaintext(&sock, &mut buf).await.unwrap();
            if len < PUBLIC_KEY_SIZE {
                eprintln!("got message too small");
                continue;
            }
            if pk != kp.public() {
                eprintln!("got message for someone else");
                continue;
            }
            let sender = PublicKey(buf[..PUBLIC_KEY_SIZE].try_into().unwrap());
            if sender == kp.public() {
                // we send this
                continue;
            }
            let pk = hex(&sender.0);
            let message = &buf[PUBLIC_KEY_SIZE..len];
            stdout.write_all(pk.as_bytes()).await.unwrap();
            stdout.write_all(b":\n  ").await.unwrap();
            stdout.write_all(message).await.unwrap();
            stdout.write_all(b"\n").await.unwrap();
        }
    };

    select(Box::pin(read_from_stdin), Box::pin(write_to_stdout)).await;
}

fn hex(bs: &[u8]) -> String {
    bs.iter().map(|b| format!("{:02x}", b)).join("")
}
