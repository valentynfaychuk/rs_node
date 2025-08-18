use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;

use core::proto;
use core::proto_enc;
use core::reed_solomon::ReedSolomonReassembler;
use core::test_data::ping::PING;

use plot::{serve, state::AppState};

#[tokio::main]
async fn main() -> std::io::Result<()> {
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
                let data = &buf[..len];

                if let Ok(m) = proto_enc::unpack_message_v2(data) {
                    match reassembler.add_shard(&m) {
                        Ok(Some(msg)) => {
                            // final shard received - reassembler assembled the message
                            // record the peer as seen on ANY successfully parsed message
                            let last_msg = variant_tag(&msg).to_string();
                            // kind is unknown here; pass None unless you can infer it
                            let pk_str = bs58::encode(&m.pk).into_string();
                            app_state.seen_peer(src, Some(pk_str), Some(last_msg)).await;

                            match msg.handle() {
                                proto::HandleResult::ReplyPong { ts_m } => {
                                    //println!("reply pong: {}", ts_m);
                                }
                                proto::HandleResult::ObservedPong { ts_m, seen_time_ms } => {
                                    //println!("observed pong: {} {}", ts_m, seen_time_ms);
                                }
                                proto::HandleResult::ReceivedEntry { entry } => {
                                    println!("{:#?}", entry);
                                }
                                proto::HandleResult::ReceivedSol { sol } => {
                                    println!("{:?}", sol);
                                }
                                proto::HandleResult::Attestations { .. } => {
                                    //println!("received attestation bulk: {:?}", attestations);
                                }
                                proto::HandleResult::Error(e) => {
                                    println!("err: {}", e);
                                }
                                proto::HandleResult::Noop => {
                                    // do nothing
                                }
                                hr => {
                                    println!("handle result {:?}", hr);
                                }
                            }
                        }
                        Ok(None) => {
                            // the are not enough shards to assemble the message yet
                            // do nothing
                        }
                        Err(e) => {
                            println!("err packet, shard: {} {}, {}", &m.shard_index, &m.shard_total, e);
                            // parse error; do nothing (only add peers when msg is OK)
                        }
                    }
                }
            }
        }
    }
}

/// Small helper: a stable human-readable tag for the enum variant.
fn variant_tag(m: &proto::NodeProto) -> &'static str {
    use proto::NodeProto::*;
    match m {
        Ping(_) => "Ping",
        Pong(_) => "Pong",
        WhoAreYou(_) => "WhoAreYou",
        TxPool(_) => "TxPool",
        Peers(_) => "Peers",
        Sol(_) => "Sol",
        Entry(_) => "Entry",
        AttestationBulk(_) => "AttestationBulk",
        ConsensusBulk(_) => "ConsensusBulk",
        CatchupEntry(_) => "CatchupEntry",
        CatchupTri(_) => "CatchupTri",
        CatchupBi(_) => "CatchupBi",
        CatchupAttestation(_) => "CatchupAttestation",
        SpecialBusiness(_) => "SpecialBusiness",
        SpecialBusinessReply(_) => "SpecialBusinessReply",
        SolicitEntry(_) => "SolicitEntry",
        SolicitEntry2(_) => "SolicitEntry2",
    }
}
