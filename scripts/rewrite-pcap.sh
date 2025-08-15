#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<EOF

  $0 <name.pcap> <if>

Rewrites the provided packet capture to replay on the given interface.
The rewritten file is saved alongside the original as <name.pcap>.local
EOF
}

if [[ $# -lt 2 ]]; then
  usage
  exit 1
fi

# Execute rewrite
if ! command -v tcprewrite >/dev/null 2>&1; then
  echo "Error: 'tcprewrite' not found" >&2
  exit 1
fi

in_pcap="$1"
iface="$2"

if [[ ! -f "$in_pcap" ]]; then
  echo "Error: can't read $in_pcap" >&2
  exit 1
fi

# Determine output path: sibling with .pcap.local suffix
in_dir=$(dirname "$in_pcap")
in_base=$(basename "$in_pcap")
if [[ "$in_base" == *.pcap ]]; then
  out_base="${in_base%.pcap}.pcap.local"
else
  out_base="${in_base}.pcap.local"
fi
out_pcap="$in_dir/$out_base"

# Detect interface IP and MAC (macOS first, Linux fallback)
get_iface_ip() {
  local ifc="$1"
  if command -v ipconfig >/dev/null 2>&1; then
    ipconfig getifaddr "$ifc" 2>/dev/null || true
  elif command -v ip >/dev/null 2>&1; then
    ip -4 addr show "$ifc" 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1 || true
  fi
}

get_iface_mac() {
  local ifc="$1"
  if command -v ifconfig >/dev/null 2>&1; then
    ifconfig "$ifc" 2>/dev/null | awk '/ether/{print $2; exit}' || true
  elif command -v ip >/dev/null 2>&1; then
    ip link show "$ifc" 2>/dev/null | awk '/link\//{print $2; exit}' || true
  fi
}

MYIP=$(get_iface_ip "$iface")
MYMAC=$(get_iface_mac "$iface")

if [[ -z "${MYIP:-}" || -z "${MYMAC:-}" ]]; then
  echo "Error: can't detect ip/mac for $iface, make sure it is up" >&2
  exit 1
fi

# Build tcprewrite arguments (single pass, no intermediates)
args=(--fixcsum --infile "$in_pcap" --outfile "$out_pcap" \
      --enet-dmac "$MYMAC" --enet-smac "$MYMAC" \
      --dstipmap "0.0.0.0/0:${MYIP}/32")

# Normalize DLT to Ethernet when not sending on loopback
if [[ "$iface" != "lo" ]]; then
  args=(--dlt enet "${args[@]}")
fi

tcprewrite "${args[@]}"

echo "Created $out_pcap"
echo
echo "sudo tcpdump -i $iface -n -vv -e udp dst port 36969"
echo "sudo tcpreplay -i $iface --pps 100 $out_pcap"