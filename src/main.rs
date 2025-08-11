use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;

use core::genesis;
use core::proto;
use core::proto_enc;
use core::test_data::ping::PING;

use rs_plot::{serve, state::AppState};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    // Target UDP address of an Amadeus node.
    let addr: SocketAddr = std::env::var("UDP_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:36969".to_string())
        .parse()
        .expect("valid UDP_ADDR");

    // Bind a local UDP socket (Tokio).
    let socket = UdpSocket::bind("0.0.0.0:36969").await?;

    // Send a simple ping message to the node.
    socket.send_to(&PING, &addr).await?;
    println!("sent");

    let app_state = rs_plot::state::AppState::new();

    let s1 = app_state.clone();
    // --- spawn HTTP server ---
    let http = tokio::spawn(async move {
        if let Err(e) = serve("0.0.0.0:3000", &s1).await {
            eprintln!("server error: {e}");
        }
    });

    // --- run UDP recv loop concurrently ---
    let udp = tokio::spawn(async move {
        if let Err(e) = recv_loop(&socket, app_state).await {
            eprintln!("udp loop error: {e}");
        }
    });

    // Wait for either task to finish (or join both if you prefer)
    let _ = tokio::try_join!(http, udp);

    Ok(())
}

async fn recv_loop(socket: &UdpSocket, app_state: AppState) -> std::io::Result<()> {
    let mut buf = vec![0u8; 65_535];

    loop {
        // Apply a 5s timeout like your blocking read_timeout.
        match timeout(Duration::from_secs(5), socket.recv_from(&mut buf)).await {
            Err(_elapsed) => {
                // Timed out waiting—skip or add heartbeat/log if you want.
                continue;
            }
            Ok(Err(e)) => return Err(e),
            Ok(Ok((len, src))) => {
                let data = &buf[..len];

                // Unpack + parse like your sync code.
                if let Ok(m) = proto_enc::unpack_message_v2(data) {
                    match proto_enc::parse_nodeproto(&m.payload) {
                        Ok(proto::NodeProto::Ping(_)) => { /* ignore */ }
                        Ok(other) => {
                            println!("received {} bytes from {}", len, src);
                            println!("{:?}", other)
                        }
                        Err(_e) => { /* parse error; ignore or log */ }
                    }
                }
            }
        }
    }
}
