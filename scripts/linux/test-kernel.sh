#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.."
[[ $EUID -eq 0 ]] || { echo "Run as root in an Ubuntu test VM." >&2; exit 1; }
[[ -f bpf/wirewall_bpfel.o ]] || { echo "Run scripts/linux/build.sh first." >&2; exit 1; }
export WIREWALL_KERNEL_TEST=1
export WIREWALL_BPF_OBJECT="$PWD/bpf/wirewall_bpfel.o"
go test -count=1 -v ./internal/dataplane -run '^TestKernel'
echo "BPF_PROG_TEST_RUN finished; no network interface was attached."
