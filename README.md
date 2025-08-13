# Rust rewrite of the Amadeus Node

## Prerequisites

You need to have rust environment and a running node somewhere to connect to.
It is best to run the offline node on the same machine (it requires a lot of storage).
To setup the machine, refer the Dockerfile from https://github.com/amadeus-robot/node.git

```bash
OFFLINE=1 iex -S mix
```

## Running

```bash
# When running on the same machine as the running node, UDP_ADDR=127.0.0.1:36969 is added by default
UDP_ADDR=127.0.0.1:36969 cargo run --bin rs
```

## Simulating network traffic

### PCAP path

Step 1. Record traffic to a pcap on a real amadeus node (port 36969)

```bash
tcpdump -i any udp dst port 36969 -w pcaps/test.pcap -c 10000
```

Step 2. Rewrite the pcap to match your LAN (as if packets came to your laptop)

```bash
./pcaps/rewrite-pcap.sh pcaps/test.pcap en0
# it must create pcaps/test.local.pcap
```

Step 3. Replay the rewritten pcap on your laptop (needs sudo because working with kernel stack)

```bash
sudo tcpdump -i en0 -n -vv udp dst port 36969
sudo tcpreplay -i en0 --pps 100 pcaps/test.local.pcap
```
