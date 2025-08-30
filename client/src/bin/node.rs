use client::{DumpReplaySocket, get_http_port, init_tracing};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, UdpSocket};
use tokio::spawn;
use tokio::time::timeout;

use ama_core::{Context, read_udp_packet};
use http::serve;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();
    let ctx = Arc::new(Context::new().await?);

    // HTTP dashboard server
    let ctx_http = ctx.clone();
    let http = spawn(async move {
        let port = get_http_port();
        let socket = TcpListener::bind(&format!("0.0.0.0:{port}")).await.expect("bind http");

        println!("http listening on {port}");
        if let Err(e) = serve(socket, ctx_http).await {
            eprintln!("http server error: {e}");
        }
    });

    // UDP amadeus node
    let ctx_udp = ctx.clone();
    let udp = spawn(async move {
        let socket = UdpSocket::bind("0.0.0.0:36969").await.expect("bind udp");

        println!("udp listening on 36969"); // port must always be 36969
        if let Err(e) = recv_loop(socket, ctx_udp).await {
            eprintln!("udp loop error: {e}");
        }
    });

    // Wait for either task to finish (or join both if you prefer)
    tokio::try_join!(http, udp)?;
    Ok(())
}

async fn recv_loop(socket: UdpSocket, ctx: Arc<Context>) -> anyhow::Result<()> {
    let mut buf = vec![0u8; 65_535];
    let timeout_secs = Duration::from_secs(10);

    loop {
        match timeout(timeout_secs, socket.dump_replay_recv_from(&mut buf)).await {
            Err(_) => {} // timeout
            Ok(Err(e)) => return Err(e.into()),
            Ok(Ok((len, src))) => match read_udp_packet(&ctx, src, &buf[..len]).await {
                Some(proto) => {
                    proto.handle(&ctx).await?;
                }
                None => {} // still waiting for more shards
            },
        }
    }
}
