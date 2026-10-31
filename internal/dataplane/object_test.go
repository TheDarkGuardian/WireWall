package dataplane

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
)

// This parses the compiled ELF and BTF only. It never creates a map, loads a
// kernel program, opens a link, or claims that Linux's verifier accepted it.
func TestCompiledObjectABI(t *testing.T) {
	path := os.Getenv("WIREWALL_BPF_OBJECT")
	explicit := path != ""
	if !explicit {
		path = filepath.Join("..", "..", "bpf", "wirewall_bpfel.o")
	}
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) && !explicit {
		t.Skip("compile the BPF object first to check the actual ELF/BTF ABI")
	} else if err != nil {
		t.Fatal(err)
	}
	spec, err := ebpf.LoadCollectionSpec(path)
	if err != nil {
		t.Fatalf("parse BPF ELF/BTF: %v", err)
	}
	if spec.ByteOrder != binary.LittleEndian {
		t.Fatal("the loader marshals the shared ABI as little-endian")
	}
	program := spec.Programs["wirewall_xdp"]
	if program == nil || program.Type != ebpf.XDP || len(program.Instructions) == 0 {
		t.Fatal("compiled object does not contain the expected XDP program")
	}
	outer := spec.Maps["policies"]
	if outer == nil || outer.Type != ebpf.ArrayOfMaps || outer.MaxEntries != 1 || outer.KeySize != 4 {
		t.Fatal("compiled policy publication map ABI changed")
	}
	inner := outer.InnerMap
	if inner == nil || inner.Type != ebpf.Array || inner.KeySize != 4 || inner.MaxEntries != 1 || inner.ValueSize != uint32(binary.Size(kernelPolicy{})) {
		t.Fatalf("compiled inner policy map ABI changed: %+v", inner)
	}
	for _, expected := range []struct {
		name       string
		kind       ebpf.MapType
		key, value uint32
		entries    uint32
	}{
		{"policy_template", ebpf.Array, 4, uint32(binary.Size(kernelPolicy{})), 1},
		{"service_buckets", ebpf.Hash, 16, 32, 1024},
		{"source_buckets", ebpf.Hash, 32, 32, 8192},
		{"bans", ebpf.Hash, 32, 8, 8192},
		{"counters", ebpf.PerCPUArray, 4, 16, uint32(len(reasonNames))},
		{"protocol_counts", ebpf.PerCPUArray, 4, 16, 8},
		{"service_counts", ebpf.PerCPUHash, 4, 16, 1024},
		{"readers", ebpf.PerCPUArray, 4, 8, 1},
		{"events", ebpf.RingBuf, 0, 0, 1 << 20},
	} {
		mapping := spec.Maps[expected.name]
		if mapping == nil || mapping.Type != expected.kind || mapping.KeySize != expected.key || mapping.ValueSize != expected.value || mapping.MaxEntries != expected.entries {
			t.Fatalf("compiled %s map ABI changed: %+v", expected.name, mapping)
		}
	}
	for _, expected := range []struct {
		name string
		size uint32
	}{
		{"ww_policy", uint32(binary.Size(kernelPolicy{}))},
		{"ww_rule", uint32(binary.Size(kernelRule{}))},
		{"ww_bucket", 32},
		{"ww_source_key", 32},
		{"ww_bucket_key", 16},
		{"ww_ban_key", 32},
	} {
		var structure *btf.Struct
		if err := spec.Types.TypeByName(expected.name, &structure); err != nil {
			t.Fatalf("compiled BTF type %s: %v", expected.name, err)
		}
		if structure.Size != expected.size {
			t.Fatalf("compiled BTF %s size=%d want=%d", expected.name, structure.Size, expected.size)
		}
	}
	// Size equality alone would miss fields accidentally reordered between C
	// and binary.Write. Check offsets at the packet/byte and publication ABI.
	for name, offsets := range map[string]map[string]uint32{
		"ww_bucket": {"lock": 0, "updated_ns": 8, "credits": 16, "byte_credits": 24},
		"ww_rule":   {"pps": 72, "burst": 80, "source_pps": 88, "source_burst": 96, "bps": 104, "byte_burst": 112, "source_bps": 120, "source_byte_burst": 128},
		"ww_policy": {"version": 0, "enforce": 8, "rule_count": 12, "management_port": 16, "management_count": 20, "management": 24, "rules": 344, "reserved": 9048},
	} {
		var structure *btf.Struct
		if err := spec.Types.TypeByName(name, &structure); err != nil {
			t.Fatal(err)
		}
		found := make(map[string]uint32, len(structure.Members))
		for _, member := range structure.Members {
			found[member.Name] = uint32(member.Offset)
		}
		for field, bytes := range offsets {
			bits, exists := found[field]
			if !exists || bits != bytes*8 {
				t.Fatalf("compiled BTF %s.%s offset=%d bits exists=%v want=%d", name, field, bits, exists, bytes*8)
			}
		}
	}
}
