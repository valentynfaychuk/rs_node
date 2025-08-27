use bincode::{config::standard, decode_from_slice, encode_to_vec};
use std::io::Result;
use std::net::SocketAddr;
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, OnceCell};
use tokio::time::{Duration, sleep};

#[async_trait::async_trait]
pub trait DumpReplaySocket: Send + Sync {
    async fn dump_replay_recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)>;
    async fn dump_replay_send_to(&self, buf: &[u8], target: SocketAddr) -> Result<usize>;
}

#[async_trait::async_trait]
impl DumpReplaySocket for UdpSocket {
    async fn dump_replay_recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        // use the replay file instead of the real socket if set
        // fallback to real UDP socket when no replay file
        let (len, src) = match udp_replay().await {
            Some(state) => state.lock().await.recv_from_replay(buf).await?,
            None => self.recv_from(buf).await?,
        };

        maybe_dump_datagram(src, &buf[..len]).await;

        Ok((len, src))
    }

    async fn dump_replay_send_to(&self, buf: &[u8], target: SocketAddr) -> Result<usize> {
        // dump outgoing packet with fixed source address
        let src_addr = "127.0.0.1:39696".parse().unwrap();
        maybe_dump_datagram(src_addr, buf).await;
        
        // send the packet normally
        self.send_to(buf, target).await
    }
}

const CHUNK_SIZE: usize = 10 * 1024 * 1024;

struct ReplayState {
    file: File,
    chunk: Vec<u8>,
    file_pos: usize,
    chunk_pos: usize,
}

impl ReplayState {
    async fn recv_from_replay(&mut self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        loop {
            let from_pos = self.chunk_pos;

            if let Ok((dgram, consumed)) = decode_from_slice::<DatagramDump, _>(&self.chunk[from_pos..], standard()) {
                self.chunk_pos += consumed;
                buf[..dgram.data.len()].copy_from_slice(&dgram.data);
                return Ok((dgram.data.len(), dgram.src));
            }

            // decode failed, try to load next chunk
            if self.read_next_chunk_with_remainder(from_pos).await? == 0 {
                // end of file reached, wait for more data (tail -f)
                sleep(Duration::from_secs(1)).await;
            }
        }
    }

    /// Read next chunk and preserve remaining bytes from current buffer
    async fn read_next_chunk_with_remainder(&mut self, from_pos: usize) -> Result<usize> {
        if from_pos < self.chunk.len() {
            let remainder = self.chunk[from_pos..].to_vec();

            self.chunk.clear();
            self.chunk.extend_from_slice(&remainder);
            self.chunk.resize(CHUNK_SIZE, 0);

            let bytes_read = self.file.read(&mut self.chunk[remainder.len()..]).await?;
            self.chunk.truncate(remainder.len() + bytes_read);
            self.file_pos += bytes_read;
            self.chunk_pos = 0;

            Ok(bytes_read)
        } else {
            // previous chunk was consumed fully

            self.chunk.clear();
            self.chunk.resize(CHUNK_SIZE, 0);

            let bytes_read = self.file.read(&mut self.chunk).await?;
            self.chunk.truncate(bytes_read);
            self.file_pos += bytes_read;
            self.chunk_pos = 0;

            Ok(bytes_read)
        }
    }
}

async fn udp_replay() -> Option<&'static Mutex<ReplayState>> {
    static UDP_REPLAY: OnceCell<Option<Mutex<ReplayState>>> = OnceCell::const_new();
    UDP_REPLAY
        .get_or_init(|| async {
            match std::env::var("UDP_REPLAY") {
                Ok(path) => match File::open(&path).await {
                    Ok(file) => {
                        let chunk = Vec::with_capacity(CHUNK_SIZE);
                        let mut state = ReplayState { file, chunk, file_pos: 0, chunk_pos: 0 };
                        let bytes = state
                            .read_next_chunk_with_remainder(0)
                            .await
                            .inspect_err(|e| eprintln!("failed to read from UDP_REPLAY file: {e}"))
                            .ok()?;

                        println!("replaying UDP packets from {path} (first chunk {bytes})");
                        Some(Mutex::new(state))
                    }
                    Err(e) => {
                        eprintln!("failed to open UDP_REPLAY file: {e}");
                        None
                    }
                },
                Err(_) => None,
            }
        })
        .await
        .as_ref()
}

async fn maybe_dump_datagram(src: SocketAddr, payload: &[u8]) {
    if let Some(file_mutex) = udp_dump().await {
        let mut f = file_mutex.lock().await;
        let dgram = DatagramDump { src, data: payload.to_vec() };
        if let Ok(bytes) = encode_to_vec(&dgram, standard()) {
            let _ = f.write_all(&bytes).await;
        }
    }
}

async fn udp_dump() -> Option<&'static Mutex<File>> {
    static UDP_DUMP: OnceCell<Option<Mutex<File>>> = OnceCell::const_new();
    UDP_DUMP
        .get_or_init(|| async {
            match std::env::var("UDP_DUMP") {
                Ok(path) => match OpenOptions::new().create(true).append(true).open(&path).await {
                    Ok(file) => {
                        println!("dumping UDP packets to {path}");
                        Some(Mutex::new(file))
                    }
                    Err(e) => {
                        eprintln!("failed to open UDP_DUMP file: {e}");
                        None
                    }
                },
                Err(_) => None,
            }
        })
        .await
        .as_ref()
}

#[derive(bincode::Encode, bincode::Decode)]
pub struct DatagramDump {
    src: SocketAddr,
    data: Vec<u8>,
}
