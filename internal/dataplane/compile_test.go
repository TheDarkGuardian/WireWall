package dataplane

import (
	"encoding/binary"
	"testing"

	"github.com/TheDarkGuardian/WireWall/internal/model"
	"github.com/TheDarkGuardian/WireWall/internal/policy"
)

func TestKernelPolicyLayoutAndOrdering(t *testing.T) {
	p := policy.Default()
	p.Version = 42
	p.Rules = []model.Rule{
		{ID: "second", Name: "second", Enabled: true, Priority: 20, Action: "drop", Protocol: "tcp", Source: "192.0.2.99/24", Destination: "any", SourcePort: "any", DestinationPort: "8000-8080"},
		{ID: "first", Name: "first", Enabled: true, Priority: 10, Action: "pass", Protocol: "udp", Source: "any", Destination: "any", SourcePort: "any", DestinationPort: "53"},
	}
	compiled, err := compilePolicy(p)
	if err != nil {
		t.Fatal(err)
	}
	data, err := compiled.value.marshal()
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 9064 || binary.LittleEndian.Uint64(data[:8]) != 42 {
		t.Fatal("kernel ABI changed")
	}
	if compiled.rules[0].ID != "first" || compiled.value.Rules[1].DestinationHi != 8080 {
		t.Fatal("rule ordering/range compilation is wrong")
	}
	prefix := compiled.value.Rules[1].Source
	if prefix.Family != 4 || prefix.Bits != 24 || prefix.Address[3] != 0 {
		t.Fatal("prefix must be masked and IPv4 bytes start at offset zero")
	}
}

func TestCompileRejectsInvalidAndOversizedPolicies(t *testing.T) {
	p := policy.Default()
	p.ManagementCIDRs = make([]string, 17)
	for i := range p.ManagementCIDRs {
		p.ManagementCIDRs[i] = "192.0.2.0/24"
	}
	if _, err := compilePolicy(p); err == nil {
		t.Fatal("oversized management list accepted")
	}
	p = policy.Default()
	p.Version = 0
	if _, err := compilePolicy(p); err == nil {
		t.Fatal("version zero must not be published")
	}
}

func TestPrefixAndPortABI(t *testing.T) {
	ipv6, err := compilePrefix("2001:db8:abcd::9/48")
	if err != nil {
		t.Fatal(err)
	}
	if ipv6.Family != 6 || ipv6.Bits != 48 || ipv6.Address[15] != 0 {
		t.Fatal("bad IPv6 prefix")
	}
	for _, invalid := range []string{"80-79", "65536", "1-2-3", "bad"} {
		if _, _, err := compilePorts(invalid); err == nil {
			t.Fatalf("accepted %q", invalid)
		}
	}
	lo, hi, err := compilePorts("any")
	if err != nil || lo != 0 || hi != 65535 {
		t.Fatal("wildcard must include ICMP zero ports")
	}
}

func TestByteBudgetABIAndBackwardCompatibility(t *testing.T) {
	p := policy.Default()
	p.Mode = "enforce"
	p.Rules = []model.Rule{{ID: "bytes", Name: "byte budget", Enabled: true, Priority: 1, Action: "limit", Protocol: "tcp", Source: "any", Destination: "any", SourcePort: "any", DestinationPort: "443", PPS: 100, Burst: 50, BPS: 12000, ByteBurst: 6000, SourceBPS: 1200, SourceByteBurst: 600}}
	compiled, err := compilePolicy(p)
	if err != nil {
		t.Fatal(err)
	}
	data, err := compiled.value.marshal()
	if err != nil {
		t.Fatal(err)
	}
	firstRule := 24 + maxManagement*20
	for _, field := range []struct {
		offset int
		want   uint64
	}{{104, 12000}, {112, 6000}, {120, 1200}, {128, 600}} {
		if got := binary.LittleEndian.Uint64(data[firstRule+field.offset : firstRule+field.offset+8]); got != field.want {
			t.Fatalf("byte ABI at offset %d = %d, want %d", field.offset, got, field.want)
		}
	}
	p.Rules[0].BPS = 0
	p.Rules[0].ByteBurst = 0
	p.Rules[0].SourceBPS = 0
	p.Rules[0].SourceByteBurst = 0
	legacy, err := compilePolicy(p)
	if err != nil {
		t.Fatalf("packet-only policy stopped compiling: %v", err)
	}
	if legacy.value.Rules[0].BPS != 0 || legacy.value.Rules[0].SourceBPS != 0 {
		t.Fatal("legacy policy unexpectedly enabled byte budgets")
	}
}
