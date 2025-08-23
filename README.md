# Rust rewrite of the Amadeus Node

Folder structure:

- client: Light client
- core: Core library
- plot: Web dashboard
- pcaps: Testing PCAP files
- scripts: Self explanatory

## Prerequisites

### Amadeus Elixir Node (Optional)

You need to have rust environment and a running node somewhere to connect to.
It is best to run the offline node on the same machine (it requires a lot of storage).
To setup the machine, refer the Dockerfile from https://github.com/amadeus-robot/node.git

```bash
OFFLINE=1 iex -S mix
```

### RocksDB toolbox (Optional)

To install rocksdb tools follow:

```bash
git clone https://github.com/facebook/rocksdb.git && cd rocksdb && make ldb && make sst_dump
brew install rocksdb # or on MacOS (this will install `rocksdb_ldb` and `rocksdb_sst_dump`)
```

## Running Light Client

The light client offers three binaries:

- node
- cli
- log

```bash
# Node is an Amadeus node that receives and handles messages
# UDP_ADDR is the address of target Amadeus node, default it 127.0.0.1:36969
UDP_ADDR=127.0.0.1:36969 cargo run --package client --bin node

# CLI is a client that can deploy a contract or send transactions
cargo run --package client --bin cli -- gensk trainer-sk
cargo run --package client --bin cli -- getpk trainer-sk

# Log is a utility that captures raw UDP diagrams for further replay
cargo run --package client --bin log
```

## Running a PCAP simulation

Step 1. Record traffic to a pcap on a real amadeus node (port 36969).
This command is transparent to the node but could impact the performance,
so feel free to run it alongside the node, but without abusing.

```bash
tcpdump -i any udp dst port 36969 -w pcaps/test.pcap -c 10000
```

Step 2. Rewrite the PCAP to match your LAN. This is needed to make sure
that the packets are addressed to the light client and will arrive.

```bash
./pcaps/rewrite-pcap.sh pcaps/test.pcap en0
# it must create pcaps/test.pcap.local
```

Step 3. Replay the rewritten PCAP locally. To run the replay, you need sudo
because the replay command works with the kernel stack.

```bash
sudo tcpreplay -i en0 --pps 1000 pcaps/test.pcap.local
# if you want to watch the replay in real-time, you can use:
sudo tcpdump -i en0 -n -vv udp dst port 36969
```

### Expected output after `pcaps/test.pcap.local`

Core library has a built-in metrics system (light client prints them after
10s of being idle) Expected output of the metrics after replaying the
`pcaps/test.pcap.local` file, total number of packets in the pcap is 10000
but the light client processes 10001 because it also receives its own ping:

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

### Troubleshooting PCAP replay

If you see that not all packets from the PACP reach the light client, it
could be because the kernel buffers are too small to handle the replay at
a given rate, you need to increase the kernel buffers for UDP traffic or
decrease the `--pps` value.

```bash
# The packets are often getting lost because they overflow the kernel buffers
# So it is suggested to increase the kernel buffers before replaying
sudo sysctl -w kern.ipc.maxsockbuf=8388608        # raises per-socket max
sudo sysctl -w net.inet.udp.recvspace=2097152     # default UDP recv buffer (per-socket)
sysctl kern.ipc.maxsockbuf net.inet.udp.recvspace # check the values
```

If you see that no packets are reaching the light client, the reason could
be that your IP address changed (e.g. after the restart), simply recreate
the `.pcap.local` file to insert the current IP address.

```bash
rm pcaps/test.pcap.local && ./pcaps/rewrite-pcap.sh pcaps/test.pcap en0
```

## Debugging the RocksDB

If installed on MacOS using brew, the command is `rocksdb_ldb` and `rocksdb_sst_dump`,
if manually - then the commands are `ldb` and `sst_dump` respectively.

```bash
rocksdb_ldb --db=run.local/fabric/db list_column_families
rocksdb_ldb --db=run.local/fabric/db --column_family=sysconf scan
rocksdb_ldb --db=run.local/fabric/db --column_family=entry_by_height scan
rocksdb_ldb --db=run.local/fabric/db --column_family=sysconf get rooted_tip
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

## Contributing

Before pushing changes, run `cargo fmt` and `cargo clippy` to maintain the quality.

## TODO

- [ ] Parsing into MessageV2
- [ ] Refactoring the RocksDB and Fabric
- [ ] For error metrics, add the error argument