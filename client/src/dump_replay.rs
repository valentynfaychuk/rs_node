use bincode::error::{DecodeError, EncodeError};
use bincode::{config::standard, decode_from_slice, encode_to_vec};
use std::fs::{File, OpenOptions};
use std::io;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::sync::{Mutex, OnceLock};
use tokio::net::UdpSocket;
use tokio::time::{Duration, sleep};

#[async_trait::async_trait]
pub trait DumpReplaySocket: Send + Sync {
    async fn dump_replay_recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)>;
}

#[async_trait::async_trait]
impl DumpReplaySocket for UdpSocket {
    async fn dump_replay_recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        // use the replay file instead of the real socket if set
        // fallback to real UDP socket when no replay file
        let (len, src) = match udp_replay().as_ref() {
            Some(state_mutex) => recv_from_replay(state_mutex, buf).await?,
            None => self.recv_from(buf).await?,
        };

        // optionally dump the received datagram (disabled while replaying to avoid extra I/O)
        maybe_dump_datagram(src, &buf[..len]);

        Ok((len, src))
    }
}

struct ReplayState {
    data: Vec<u8>,
    position: usize,
}

fn udp_replay() -> &'static Option<Mutex<ReplayState>> {
    static UDP_REPLAY: OnceLock<Option<Mutex<ReplayState>>> = OnceLock::new();
    UDP_REPLAY.get_or_init(|| match std::env::var("UDP_REPLAY") {
        Ok(path) => match std::fs::read(&path) {
            Ok(data) => {
                println!("replaying UDP packets from {path} ({} bytes loaded)", data.len());
                Some(Mutex::new(ReplayState { data, position: 0 }))
            }
            Err(e) => {
                eprintln!("failed to read UDP_REPLAY file: {e}");
                None
            }
        },
        Err(_) => None,
    })
}

async fn recv_from_replay(state_mutex: &Mutex<ReplayState>, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
    loop {
        let result = {
            let mut state = state_mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner());

            // check if we've reached the end of the data
            if state.position >= state.data.len() {
                None
            } else {
                // try to decode a datagram from the current position
                let remaining = &state.data[state.position..];
                match decode_from_slice::<UdpLoggedDatagram, _>(remaining, standard()) {
                    Ok((dgram, consumed)) => {
                        state.position += consumed;
                        let payload = dgram.data();
                        let copy_len = std::cmp::min(payload.len(), buf.len());
                        buf[..copy_len].copy_from_slice(&payload[..copy_len]);
                        Some(Ok((copy_len, dgram.src())))
                    }
                    Err(_) => {
                        // if decode fails and we're at the end, we're done
                        if state.position >= state.data.len() {
                            None
                        } else {
                            // skip a byte and try again (corrupted data)
                            state.position += 1;
                            continue;
                        }
                    }
                }
            }
        };

        match result {
            Some(data) => return data,
            None => {
                sleep(Duration::from_secs(1)).await;
                continue;
            }
        }
    }
}

fn maybe_dump_datagram(src: SocketAddr, payload: &[u8]) {
    // Avoid re-dumping while replaying to prevent extra I/O and potential feedback loops
    // if udp_replay().as_ref().is_some() {
    //     return;
    // }
    if let Some(file_mutex) = udp_dump().as_ref() {
        if let Ok(mut f) = file_mutex.lock() {
            let dgram = UdpLoggedDatagram::new(src, payload.to_vec());
            if let Ok(bytes) = Vec::<u8>::try_from(dgram) {
                let _ = f.write_all(&bytes);
            }
        }
    }
}

fn udp_dump() -> &'static Option<Mutex<File>> {
    static UDP_DUMP: OnceLock<Option<Mutex<File>>> = OnceLock::new();
    UDP_DUMP.get_or_init(|| match std::env::var("UDP_DUMP") {
        Ok(path) => match OpenOptions::new().create(true).append(true).open(&path) {
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
    })
}

#[derive(Clone, bincode::Encode, bincode::Decode)]
pub struct UdpLoggedDatagram {
    src: SocketAddr,
    data: Vec<u8>,
}

impl UdpLoggedDatagram {
    pub fn new(src: SocketAddr, data: Vec<u8>) -> Self {
        Self { src, data }
    }

    pub fn src(&self) -> SocketAddr {
        self.src
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

impl TryFrom<UdpLoggedDatagram> for Vec<u8> {
    type Error = EncodeError;

    fn try_from(dgram: UdpLoggedDatagram) -> Result<Self, Self::Error> {
        encode_to_vec(&dgram, standard())
    }
}

impl TryFrom<&[u8]> for UdpLoggedDatagram {
    type Error = DecodeError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Ok(decode_from_slice(bytes, standard())?.0)
    }
}
