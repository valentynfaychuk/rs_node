# Rust rewrite of the Amadeus Node

Folder structure:

- client: Light client
- core: Core library
- plot: Web dashboard
- pcaps: Testing PCAP files
- scripts: Self explanatory

## Prerequisites

You need to have rust environment and a running node somewhere to connect to.
It is best to run the offline node on the same machine (it requires a lot of storage).
To setup the machine, refer the Dockerfile from https://github.com/amadeus-robot/node.git

```bash
OFFLINE=1 iex -S mix
```

## Contributing

Before pushing changes, run `cargo fmt` to format the code.

## Running Light Client

```bash
# When running on the same machine as the running node, UDP_ADDR=127.0.0.1:36969 is added by default
UDP_ADDR=127.0.0.1:36969 cargo run --package client
```

## Running a PCAP simulation

### Step 1. Record traffic to a pcap on a real amadeus node (port 36969)

```bash
tcpdump -i any udp dst port 36969 -w pcaps/test.pcap -c 10000
```

### Step 2. Rewrite the pcap to match your LAN (as if packets came to your laptop)

```bash
./pcaps/rewrite-pcap.sh pcaps/test.pcap en0
# it must create pcaps/test.local.pcap
```

### Step 3. Replay the rewritten pcap on your laptop (needs sudo because working with kernel stack)

```bash
# The packets are often getting lost because they overflow the kernel buffers
# So it is suggested to increase the kernel buffers before replaying
sudo sysctl -w kern.ipc.maxsockbuf=8388608        # raises per-socket max
sudo sysctl -w net.inet.udp.recvspace=2097152     # default UDP recv buffer (per-socket)
sysctl kern.ipc.maxsockbuf net.inet.udp.recvspace # check the values

# Running the replay
sudo tcpdump -i en0 -n -vv udp dst port 36969     # to check if they are flowing
sudo tcpreplay -i en0 --pps 100 pcaps/test.local.pcap
```

### Expected output

Core library has a built-in metrics system (light client prints them after 10s of being idle)
Expected output of the metrics after replaying the `pcaps/test.local.pcap` file:

```bash
# HELP amadeus_protocol_messages_total Total number of protocol messages handled by type
# TYPE amadeus_protocol_messages_total counter
amadeus_protocol_messages_total{type="ping"} 8657
amadeus_protocol_messages_total{type="pong"} 0
amadeus_protocol_messages_total{type="who_are_you"} 0
amadeus_protocol_messages_total{type="txpool"} 0
amadeus_protocol_messages_total{type="peers"} 0
amadeus_protocol_messages_total{type="sol"} 0
amadeus_protocol_messages_total{type="entry"} 35
amadeus_protocol_messages_total{type="attestation_bulk"} 1165
amadeus_protocol_messages_total{type="consensus_bulk"} 0
amadeus_protocol_messages_total{type="catchup_entry"} 0
amadeus_protocol_messages_total{type="catchup_tri"} 0
amadeus_protocol_messages_total{type="catchup_bi"} 0
amadeus_protocol_messages_total{type="catchup_attestation"} 0
amadeus_protocol_messages_total{type="special_business"} 0
amadeus_protocol_messages_total{type="special_business_reply"} 0
amadeus_protocol_messages_total{type="solicit_entry"} 0
amadeus_protocol_messages_total{type="solicit_entry2"} 0

# HELP amadeus_packets_total Total number of UDP packets received
# TYPE amadeus_packets_total counter
amadeus_udp_packets_total 10001

# HELP amadeus_packet_errors_total Total number of packet processing errors by type
# TYPE amadeus_packet_errors_total counter
amadeus_packet_errors_total{type="v2_parsing"} 0
amadeus_packet_errors_total{type="reassembly"} 0
amadeus_packet_errors_total{type="etf_decode_and_validation"} 0
amadeus_packet_errors_total{type="handling"} 0
amadeus_packet_errors_total{type="unknown_proto"} 0
```

## Performance considerations

The handling of parsed and validated incoming messages are happening through the
`HandleExt` trait, which is `#[async_trait]`, which is very flexible and allow
for having trait objects. Further performance improvements could include making
it more explicit, for example by using:

```rust
pub trait HandleExt {
    type Fut<'a>: Future<Output=Result<..>> + 'a
    where
        Self: 'a;
    fn handle<'a>(&'a self) -> Self::Fut<'a>;
}
```

Another direction of improvement is to avoid using synchronisation, like mutexes,
and instead to use channels for communication between the threads.

## Adding core library to other project

```bash
cargo add ama_core --git https://github.com/amadeus-robot/rs_node --package core --branch main
# Or add following to Cargo.toml
# [dependencies]
# ama_core = { package = "core", git = "https://github.com/amadeus-robot/rs_node", branch = "main" }
```