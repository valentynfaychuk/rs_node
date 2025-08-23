use client::UdpLoggedDatagram;
use std::env;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::net::UdpSocket;

fn usage_and_exit() -> ! {
    eprintln!(
        r#"
Usage: log <filename> <frames_count>

Binds UDP 0.0.0.0:36969 and appends every received datagram as raw bytes to <filename>.log
Stops after recording <frames_count> datagrams
Examples: cargo run -p client --bin log -- capture 100"#
    );
    std::process::exit(1);
}

fn parse_args() -> (String, usize) {
    let mut args = env::args().skip(1).collect::<Vec<_>>();
    if args.len() != 2 {
        usage_and_exit();
    }

    let base = args.remove(0);
    let count_str = args.remove(0);
    let frames: usize = match count_str.parse() {
        Ok(n) if n > 0 => n,
        _ => {
            eprintln!("frames_count must be a positive integer");
            usage_and_exit();
        }
    };

    (format!("{base}.log"), frames)
}

fn main() -> anyhow::Result<()> {
    let (log_path, frames_to_record) = parse_args();

    let mut file = OpenOptions::new().create(true).append(true).open(&log_path)?;

    let socket = UdpSocket::bind("0.0.0.0:36969")?;
    // Optional: increase recv buffer size if needed (best-effort)
    let _ = socket.set_nonblocking(false);

    eprintln!(
        "[log] Listening on UDP 0.0.0.0:36969, writing raw datagrams to {}, target frames: {}",
        log_path, frames_to_record
    );

    let mut buf = vec![0u8; 65_535];
    let mut recorded: usize = 0;

    while recorded < frames_to_record {
        let (len, src) = socket.recv_from(&mut buf)?;

        if len > 0 {
            let dgram: Vec<u8> = UdpLoggedDatagram::new(src, buf[..len].to_vec()).try_into()?;
            file.write_all(&dgram)?;
            file.flush()?; // disk persistence is OS-managed

            recorded += 1;
        }
    }

    // Best effort to sync file metadata and data
    if let Err(e) = file.sync_all() {
        eprintln!("[log] warning: sync_all failed: {}", e);
    }

    eprintln!("[log] Completed: recorded {} datagrams to {}", recorded, log_path);

    Ok(())
}
