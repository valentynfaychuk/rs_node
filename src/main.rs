use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;

mod genesis;
mod proto;
mod proto_enc;
mod test_data;
use test_data::ping::PING;

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

    // Run the async handler loop (Ctrl+C to quit).
    recv_loop(&socket).await
}

async fn recv_loop(socket: &UdpSocket) -> std::io::Result<()> {
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
                        },
                        Err(_e) => { /* parse error; ignore or log */ }
                    }
                }
            }
        }
    }
}
