use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;

use ama_core::node::ReedSolomonReassembler;
use ama_core::node::msg_v2::MessageV2;
use ama_core::node::proto::{Instruction, from_etf_bin};
use client::{PING, init_tracing};

use plot::{serve, state::AppState};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    // Initialize tracing subscriber for logging.
    init_tracing();
    ama_core::init(None).await.expect("core init");

    // Check for UDP_REPLAY environment variable for log file playback
    let socket: std::sync::Arc<dyn client::PacketReceiver> = if let Ok(log_path) = std::env::var("UDP_REPLAY") {
        // Create LogSocket for file replay
        let log_socket = client::LogSocket::new(&log_path).expect("Failed to open log file");
        std::sync::Arc::new(log_socket)
    } else {
        // Target UDP address of an Amadeus node.
        let addr: SocketAddr = std::env::var("UDP_ADDR")
            .unwrap_or_else(|_| "84.217.100.57:36969".to_string())
            .parse()
            .expect("valid UDP_ADDR");

        // Bind a local UDP socket (Tokio).
        let udp_socket = UdpSocket::bind("0.0.0.0:36969").await?;

        // Send a simple ping message to the node.
        udp_socket.send_to(&PING, &addr).await?;
        println!("sent");

        std::sync::Arc::new(udp_socket)
    };

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
        if let Err(e) = recv_loop(socket, app_state, rs_reassembler).await {
            eprintln!("udp loop error: {e}");
        }
    });

    // Wait for either task to finish (or join both if you prefer)
    let _ = tokio::try_join!(http, udp);

    Ok(())
}

async fn recv_loop(
    socket: std::sync::Arc<dyn client::PacketReceiver>,
    app_state: AppState,
    reassembler: ReedSolomonReassembler,
) -> std::io::Result<()> {
    let mut buf = vec![0u8; 65_535];

    loop {
        match timeout(Duration::from_secs(10), socket.recv_from(&mut buf)).await {
            Err(_) => {
                // If no packets for a while, print metrics
                println!("{}", ama_core::metrics::get_metrics());
                continue;
            }
            Ok(Err(e)) => return Err(e),
            Ok(Ok((len, src))) => {
                match handle(&reassembler, &app_state, src, &buf[..len]).await {
                    Some(Instruction::Noop) => {}
                    Some(Instruction::ReplyPong { .. }) => {
                        //println!("reply pong: {}", ts_m);
                    }
                    Some(Instruction::ObservedPong { .. }) => {
                        //println!("observed pong: {} {}", ts_m, seen_time_ms);
                    }
                    Some(Instruction::ReceivedEntry { .. }) => {
                        //println!("received entry");
                    }
                    Some(Instruction::AttestationBulk { .. }) => {
                        //println!("received attestation bulk");
                    }
                    Some(_) => {
                        //println!("handle result (ignored)");
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
) -> Option<Instruction> {
    match MessageV2::try_from(bin) {
        Ok(msg) => {
            // record the peer as seen on ANY successfully parsed message
            let pk_str = bs58::encode(&msg.pk).into_string();
            match reassembler.add_shard(&msg).await {
                Ok(Some(payload)) => {
                    // final shard received - reassembler assembled the message
                    match from_etf_bin(&payload) {
                        Ok(proto) => {
                            app_state.seen_peer(src, Some(pk_str), Some(proto.get_name().into())).await;
                            match proto.handle().await {
                                Ok(instruction) => return Some(instruction),
                                Err(e) => {
                                    println!("failed to handle proto: {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            println!("invalid proto: {}", e);
                        }
                    }
                }
                Ok(None) => {} // Still waiting for more shards, not an error
                Err(e) => {
                    println!("failed to reassemble: {}", e);
                }
            }
        }
        Err(e) => {
            println!("not a v2 packet: {}", e);
        }
    }
    None
}
