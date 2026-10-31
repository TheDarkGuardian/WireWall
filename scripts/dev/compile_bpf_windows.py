"""Compile the real BPF C source on Windows without WSL, a VM, or installation.

Only a SHA256-pinned official Zig archive and pinned official libbpf headers are
downloaded into .tools/. Zig supplies the Linux UAPI headers. This produces and
inspects an ELF/BTF object; it does NOT run the Linux verifier or attach XDP.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import platform
import struct
import subprocess
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[2]
ZIG_VERSION = "0.17.0"
ZIG_DIRECTORY = f"zig-x86_64-windows-{ZIG_VERSION}"
ZIG_ARCHIVE = ZIG_DIRECTORY + ".zip"
ZIG_URL = f"https://ziglang.org/download/{ZIG_VERSION}/{ZIG_ARCHIVE}"
ZIG_SHA256 = "b5663f69581dcf391293fbf16c06cb80d81d806545ce618b4d0bab7f0eb8c428"
LIBBPF_COMMIT = "20ea95b4505c477af3b6ff6ce9d19cee868ddc5d"  # official v1.4.0
LIBBPF_HEADERS = {
    "bpf_helpers.h": "b2c9bca883f03e7de2535bf0faa894cc52ab99719bcaa42c0d707c63b492e7c1",
    "bpf_helper_defs.h": "713f32128360bebe69a23202649984a66cbcb73f0e0ebae7dc7c8469e48798cd",
    "bpf_endian.h": "64b77c97b089ca06203d0451407844fe93933b4e36e7315a294745fa29d058fb",
}
MAX_DOWNLOAD = 150 * 1024 * 1024


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def fetch_verified(url: str, path: Path, expected: str, offline: bool) -> None:
    if not path.exists():
        if offline:
            raise SystemExit(f"Offline input missing: {path}")
        temporary = path.with_suffix(path.suffix + ".download")
        path.parent.mkdir(parents=True, exist_ok=True)
        size = 0
        try:
            with urllib.request.urlopen(url, timeout=60) as source, temporary.open("wb") as target:
                while chunk := source.read(1 << 20):
                    size += len(chunk)
                    if size > MAX_DOWNLOAD:
                        raise SystemExit("Download exceeds the 150 MiB tool limit")
                    target.write(chunk)
            if digest(temporary) != expected:
                raise SystemExit(f"SHA256 mismatch: {path.name}")
            temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)
    if digest(path) != expected:
        raise SystemExit(f"SHA256 mismatch: {path.name}; refusing to execute/use it")


def inspect_bpf(path: Path) -> dict:
    raw = path.read_bytes()
    if len(raw) < 64 or raw[:6] != b"\x7fELF\x02\x01":
        raise SystemExit("Compiler output is not ELF64 little-endian")
    header = struct.unpack_from("<16sHHIQQQIHHHHHH", raw)
    if header[1] != 1 or header[2] != 247:
        raise SystemExit("Compiler output is not an EM_BPF relocatable object")
    offset, entry_size, count, names_index = header[6], header[11], header[12], header[13]
    if entry_size != 64 or names_index >= count or offset + entry_size * count > len(raw):
        raise SystemExit("Invalid ELF section table")
    sections = [struct.unpack_from("<IIQQQQIIQQ", raw, offset + i * entry_size) for i in range(count)]
    strings = sections[names_index]
    names = raw[strings[4]:strings[4] + strings[5]]
    inventory = {}
    for section in sections:
        if section[0] >= len(names):
            raise SystemExit("Invalid ELF section name offset")
        name = names[section[0]:].split(b"\0", 1)[0].decode("utf-8")
        if section[1] != 8 and section[4] + section[5] > len(raw):
            raise SystemExit("Invalid ELF section bounds")
        inventory[name] = section[5]
    for required in ("xdp", ".maps", "license", ".BTF", ".BTF.ext"):
        if not inventory.get(required):
            raise SystemExit(f"Compiler output lacks required {required} section")
    if inventory["xdp"] % 8:
        raise SystemExit("BPF instruction section has an invalid byte count")
    return {"machine": "EM_BPF", "bytes": len(raw), "instructionSlots": inventory["xdp"] // 8,
            "sections": inventory, "kernelVerified": False}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arch", choices=("amd64", "arm64"), default="amd64")
    parser.add_argument("--offline", action="store_true", help="Use only previously downloaded verified inputs")
    parser.add_argument("--output", default="bpf/wirewall_bpfel.o", help="Object path inside the workspace")
    args = parser.parse_args()
    if platform.system() != "Windows" or platform.machine().lower() not in ("amd64", "x86_64"):
        raise SystemExit("This helper runs on Windows x64; Ubuntu uses scripts/linux/build.sh")
    tools = (ROOT / ".tools").resolve()
    output = (ROOT / args.output).resolve()
    if not tools.is_relative_to(ROOT) or not output.is_relative_to(ROOT) or output.suffix != ".o":
        raise SystemExit("Tool and object paths must remain inside this workspace")
    tools.mkdir(exist_ok=True)
    archive = tools / ZIG_ARCHIVE
    fetch_verified(ZIG_URL, archive, ZIG_SHA256, args.offline)
    zig_root = tools / ZIG_DIRECTORY
    executable = zig_root / "zig.exe"
    if not executable.exists():
        with zipfile.ZipFile(archive) as package:
            for member in package.infolist():
                if not (tools / member.filename).resolve().is_relative_to(tools):
                    raise SystemExit("Unsafe compiler archive entry")
            package.extractall(tools)
    # Verify the executable against the pinned archive before running it, even
    # on later offline builds that reuse the extracted directory.
    with zipfile.ZipFile(archive) as package:
        expected_executable = hashlib.sha256(package.read(f"{ZIG_DIRECTORY}/zig.exe")).hexdigest()
    if digest(executable) != expected_executable:
        raise SystemExit("Extracted Zig executable differs from the verified archive")
    include = tools / "bpf-sdk" / "include"
    for name, expected in LIBBPF_HEADERS.items():
        fetch_verified(f"https://raw.githubusercontent.com/libbpf/libbpf/{LIBBPF_COMMIT}/src/{name}",
                       include / "bpf" / name, expected, args.offline)
    target_arch, header_arch = ("x86", "x86") if args.arch == "amd64" else ("arm64", "aarch64")
    linux_headers = zig_root / "lib" / "libc" / "include"
    output.parent.mkdir(parents=True, exist_ok=True)
    command = [str(executable), "cc", "-target", "bpfel-freestanding", f"-D__TARGET_ARCH_{target_arch}",
               "-O2", "-g", "-Wall", "-Werror", "-fno-asynchronous-unwind-tables", "-fno-unwind-tables",
               "-I" + str(include), "-I" + str(linux_headers / f"{header_arch}-linux-any"),
               "-I" + str(linux_headers / "any-linux-any"), "-I" + str(ROOT / "bpf"),
               "-c", str(ROOT / "bpf" / "wirewall.c"), "-o", str(output)]
    subprocess.run(command, cwd=ROOT, check=True)
    result = inspect_bpf(output)
    result.update({"zigVersion": ZIG_VERSION, "zigArchiveSHA256": ZIG_SHA256,
                   "libbpfCommit": LIBBPF_COMMIT, "target": args.arch,
                   "sourceSHA256": digest(ROOT / "bpf" / "wirewall.c"),
                   "headerSHA256": digest(ROOT / "bpf" / "wirewall.h"),
                   "objectSHA256": digest(output), "output": str(output)})
    (tools / "bpf-build-manifest.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"Compiled EM_BPF + BTF: {output} ({result['instructionSlots']} instruction slots)")
    print("Linux verifier, XDP attachment and network behavior remain unverified.")


if __name__ == "__main__":
    main()
