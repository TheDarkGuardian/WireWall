#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.."

for dependency in clang gcc go; do
  command -v "$dependency" >/dev/null || { echo "Missing build dependency: $dependency" >&2; exit 1; }
done
[[ -f /usr/include/bpf/bpf_helpers.h ]] || { echo "Install libbpf-dev before building." >&2; exit 1; }
case "$(uname -m)" in
  x86_64) target_arch=x86 ;;
  aarch64) target_arch=arm64 ;;
  *) echo "This release supports Ubuntu amd64 and arm64." >&2; exit 1 ;;
esac

clang -target bpfel -D"__TARGET_ARCH_${target_arch}" -O2 -g -Wall -Werror \
  -I"/usr/include/$(gcc -dumpmachine)" -Ibpf \
  -c bpf/wirewall.c -o bpf/wirewall_bpfel.o
mkdir -p bin
go build -trimpath -o bin/wirewall ./cmd/wirewall
echo "Built bin/wirewall and bpf/wirewall_bpfel.o. No interface was changed."
