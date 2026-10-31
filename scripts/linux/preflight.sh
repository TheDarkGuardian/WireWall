#!/usr/bin/env bash
set -euo pipefail
interface=${1:-}
[[ -n "$interface" ]] || { echo "Usage: $0 INTERFACE" >&2; exit 1; }
[[ "$interface" =~ ^[a-zA-Z0-9_.:-]{1,15}$ ]] || { echo "Invalid interface name" >&2; exit 1; }
for dependency in ip nft; do command -v "$dependency" >/dev/null || { echo "Missing: $dependency" >&2; exit 1; }; done
printf 'Kernel: '; uname -r
printf 'Architecture: '; uname -m
printf 'Virtualization: '; if command -v systemd-detect-virt >/dev/null; then systemd-detect-virt || true; else echo unknown; fi
printf 'BTF: '; if [[ -r /sys/kernel/btf/vmlinux ]]; then echo available; else echo unavailable; fi
echo "Interface and existing XDP information:"
ip -j link show dev "$interface"
echo "Existing nftables table names:"
nft list tables
echo "Conntrack limits:"
for key in nf_conntrack_count nf_conntrack_max nf_conntrack_tcp_loose; do
  file="/proc/sys/net/netfilter/$key"
  [[ ! -r "$file" ]] || { printf '%s=' "$key"; cat "$file"; }
done
if command -v bpftool >/dev/null; then
  echo "Kernel BPF feature probe:"
  bpftool feature probe kernel
fi
echo "Read-only preflight completed. This does not establish native-XDP support; an explicit test attach is still required."
