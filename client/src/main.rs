use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;

use core::node::ReedSolomonReassembler;
use core::node::etf_ser::Proto;
use core::node::handler::HandleResult;
use core::node::msg_v2::MessageV2;
use core::test_data::ping::PING;

use plot::{serve, state::AppState};

mod tracing;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    // Initialize tracing subscriber for logging.
    tracing::init_tracing();

    // Target UDP address of an Amadeus node.
    let addr: SocketAddr =
        std::env::var("UDP_ADDR").unwrap_or_else(|_| "127.0.0.1:36969".to_string()).parse().expect("valid UDP_ADDR");

    // Bind a local UDP socket (Tokio).
    let socket = UdpSocket::bind("0.0.0.0:36969").await?;

    // Send a simple ping message to the node.
    socket.send_to(&PING, &addr).await?;
    println!("sent");

    let app_state = plot::state::AppState::new();

    let s1 = app_state.clone();
    // --- spawn HTTP server ---
    let http = tokio::spawn(async move {
        if let Err(e) = serve("0.0.0.0:3000", &s1).await {
            eprintln!("server error: {e}");
        }
    });

    let rs_reassembler = ReedSolomonReassembler::new();
    rs_reassembler.start_periodic_cleanup();

    // --- run UDP recv loop concurrently ---
    let udp = tokio::spawn(async move {
        if let Err(e) = recv_loop(&socket, app_state, rs_reassembler).await {
            eprintln!("udp loop error: {e}");
        }
    });

    // Wait for either task to finish (or join both if you prefer)
    let _ = tokio::try_join!(http, udp);

    Ok(())
}

async fn recv_loop(
    socket: &UdpSocket,
    app_state: AppState,
    reassembler: ReedSolomonReassembler,
) -> std::io::Result<()> {
    let mut buf = vec![0u8; 65_535];

    loop {
        match timeout(Duration::from_secs(5), socket.recv_from(&mut buf)).await {
            Err(_) => continue,
            Ok(Err(e)) => return Err(e),
            Ok(Ok((len, src))) => {
                match handle(&reassembler, &app_state, src, &buf[..len]).await {
                    Some(HandleResult::Noop) => {}
                    Some(HandleResult::ReplyPong { .. }) => {
                        //println!("reply pong: {}", ts_m);
                    }
                    Some(HandleResult::ObservedPong { .. }) => {
                        //println!("observed pong: {} {}", ts_m, seen_time_ms);
                    }
                    Some(HandleResult::ReceivedEntry { entry }) => {
                        //println!("{:#?}", entry);
                    }
                    Some(HandleResult::Attestations { .. }) => {
                        //println!("received attestation bulk: {:?}", attestations);
                    }
                    Some(HandleResult::Error(e)) => {
                        println!("err: {}", e);
                    }
                    Some(hr) => {
                        //println!("handle result {:?}", hr);
                    }
                    _ => {}
                }
            }
        }
    }
}

async fn handle(
    reassembler: &ReedSolomonReassembler,
    app_state: &AppState,
    src: SocketAddr,
    bin: &[u8],
) -> Option<HandleResult> {
    if let Ok(msg) = MessageV2::try_from(bin) {
        match reassembler.add_shard(&msg).await {
            Ok(Some(proto)) => {
                // final shard received - reassembler assembled the message
                // record the peer as seen on ANY successfully parsed message
                let pk_str = bs58::encode(&msg.pk).into_string();
                app_state.seen_peer(src, Some(pk_str), Some(proto.get_name().into())).await;

                //println!("{:#?}", proto);

                return Some(HandleResult::from(proto));
            }
            Err(e) => println!("error adding shard: {}", e),
            _ => {}
        }
    }
    None
}
