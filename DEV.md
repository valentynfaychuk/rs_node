# Cheat Sheet for Developers

```bash
leaks -nocontext $(pgrep -f "target/debug/node")
sudo tcpdump -i any -nnvv -e 'udp and port 36969'
```

```bash
[Interface]
PrivateKey = ...
Address = 10.0.0.1/24
ListenPort = 51820

# NAT for egress + allow WG forwarding
PostUp = iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT
PostUp = iptables -A FORWARD -o wg0 -m state --state RELATED,ESTABLISHED -j ACCEPT

# DNAT public:36969/udp -> 10.0.0.2:36969 and permit it
PostUp = iptables -t nat -A PREROUTING -i eth0 -p udp --dport 36969 -j DNAT --to-destination 10.0.0.2:36969
PostUp = iptables -A FORWARD -p udp -d 10.0.0.2 --dport 36969 -j ACCEPT

PostDown = iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT
PostDown = iptables -D FORWARD -o wg0 -m state --state RELATED,ESTABLISHED -j ACCEPT
PostDown = iptables -t nat -D PREROUTING -i eth0 -p udp --dport 36969 -j DNAT --to-destination 10.0.0.2:36969
PostDown = iptables -D FORWARD -p udp -d 10.0.0.2 --dport 36969 -j ACCEPT

[Peer]
PublicKey = ...
AllowedIPs = 10.0.0.2/32
```

```bash
[Interface]
PrivateKey = ...
Address = 10.0.0.2/24
DNS = 1.1.1.1

[Peer]
PublicKey = ...
AllowedIPs = 0.0.0.0/0
Endpoint = faychuk.com:51820
PersistentKeepalive = 25
```