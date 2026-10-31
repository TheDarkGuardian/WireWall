//go:build linux

package dataplane

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/TheDarkGuardian/WireWall/internal/model"
	"github.com/TheDarkGuardian/WireWall/internal/policy"
)

// These tests execute the compiled C program in the real kernel without
// attaching it to a network interface. They are intentionally opt-in.
func kernelFixture(t *testing.T, p model.Policy, banList []model.Ban) (*ebpf.Program, *linuxBackend) {
	t.Helper()
	if os.Getenv("WIREWALL_KERNEL_TEST") != "1" {
		t.Skip("requires Ubuntu/root/BPF object; set WIREWALL_KERNEL_TEST=1 explicitly")
	}
	if os.Geteuid() != 0 {
		t.Fatal("kernel tests require root")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	object := os.Getenv("WIREWALL_BPF_OBJECT")
	if object == "" {
		object = filepath.Join("..", "..", "bpf", "wirewall_bpfel.o")
	}
	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		t.Fatal(err)
	}
	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		var verifier *ebpf.VerifierError
		if errors.As(err, &verifier) {
			t.Fatalf("kernel verifier rejected the program: %v\n%+v", err, verifier)
		}
		t.Fatalf("kernel verifier rejected the program: %v", err)
	}
	t.Cleanup(collection.Close)
	backend := &linuxBackend{collection: collection, policySpec: spec.Maps["policies"].InnerMap.Copy(), ruleIDs: make(map[uint64][]string)}
	if err := backend.applyLocked(p, banList, false); err != nil {
		t.Fatal(err)
	}
	return collection.Programs["wirewall_xdp"], backend
}

func TestKernelUnsampledTrafficClassification(t *testing.T) {
	p := policy.Default()
	program, backend := kernelFixture(t, p, nil)
	packet := tcpFrame("192.0.2.10", "192.0.2.1", 40000, 443, 2)
	for i := 0; i < 7; i++ {
		if _, _, err := program.Test(packet); err != nil {
			t.Fatal(err)
		}
	}
	var values []Counter
	if err := backend.collection.Maps["protocol_counts"].Lookup(uint32(1), &values); err != nil {
		t.Fatal(err)
	}
	var count uint64
	for _, v := range values {
		count += v.Packets
	}
	if count != 7 {
		t.Fatalf("TCP unsampled count=%d", count)
	}
	if err := backend.collection.Maps["service_counts"].Lookup(uint32(6<<16|443), &values); err != nil {
		t.Fatal(err)
	}
	count = 0
	for _, v := range values {
		count += v.Packets
	}
	if count != 7 {
		t.Fatalf("service unsampled count=%d", count)
	}
	// Fill beyond bounded cardinality: classifications remain complete while
	// lost service classifications are explicitly counted, never affect verdict.
	for i := 0; i < 1030; i++ {
		frame := udpFrame("192.0.2.10", "192.0.2.1", 40000, uint16(10000+i))
		if _, _, err := program.Test(frame); err != nil {
			t.Fatal(err)
		}
	}
	if err := backend.collection.Maps["counters"].Lookup(uint32(14), &values); err != nil {
		t.Fatal(err)
	}
	count = 0
	for _, v := range values {
		count += v.Packets
	}
	if count != 7 {
		t.Fatalf("overflow=%d want7", count)
	}
}

func TestKernelRetiredGenerationReclamation(t *testing.T) {
	p := policy.Default()
	p.Mode = "enforce"
	ban := model.Ban{Address: "192.0.2.10", ExpiresAt: time.Now().Add(time.Minute)}
	_, backend := kernelFixture(t, p, []model.Ban{ban})
	var active []uint64
	if err := backend.collection.Maps["readers"].Lookup(uint32(0), &active); err != nil {
		t.Fatal(err)
	}
	if len(active) == 0 {
		t.Fatal("kernel exposed no possible CPUs")
	}
	active[0] = 1 // Model an invocation retaining the previous map reference.
	if err := backend.collection.Maps["readers"].Put(uint32(0), active); err != nil {
		t.Fatal(err)
	}
	var address [16]byte
	copy(address[:4], []byte{192, 0, 2, 10})
	oldKey := banKey{Version: p.Version, Family: 4, Address: address}
	for i := 0; i < maxRetiredGenerations; i++ {
		p.Version++
		if err := backend.applyLocked(p, []model.Ban{ban}, false); err != nil {
			t.Fatalf("stage generation %d: %v", p.Version, err)
		}
	}
	var expiry uint64
	if err := backend.collection.Maps["bans"].Lookup(oldKey, &expiry); err != nil {
		t.Fatalf("retired reader lost its ban state: %v", err)
	}
	if len(backend.retired) != maxRetiredGenerations {
		t.Fatalf("retired generations=%d", len(backend.retired))
	}
	last := backend.policy.Version
	p.Version++
	if err := backend.applyLocked(p, []model.Ban{ban}, false); err == nil {
		t.Fatal("activation should defer at the bounded retired-generation limit")
	}
	if backend.policy.Version != last {
		t.Fatal("failed staging changed the published policy")
	}
	active[0] = 0
	if err := backend.collection.Maps["readers"].Put(uint32(0), active); err != nil {
		t.Fatal(err)
	}
	if err := backend.applyLocked(p, []model.Ban{ban}, false); err != nil {
		t.Fatal(err)
	}
	if err := backend.collection.Maps["bans"].Lookup(oldKey, &expiry); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("quiescent retired state was not reclaimed: %v", err)
	}
	if len(backend.retired) != 0 {
		t.Fatalf("retired generations remain after quiescence: %d", len(backend.retired))
	}
}

func TestKernelMissingPolicyFailsClosedWithoutReaderLeak(t *testing.T) {
	p := policy.Default()
	p.Mode = "enforce"
	program, backend := kernelFixture(t, p, nil)
	if err := backend.collection.Maps["policies"].Delete(uint32(0)); err != nil {
		t.Fatal(err)
	}
	frame := tcpFrame("192.0.2.10", "198.51.100.10", 42000, 443, 0x02)
	action, _, err := program.Test(frame)
	if err != nil || action != 0 {
		t.Fatalf("missing policy action=%d want XDP_ABORTED (0), error=%v", action, err)
	}
	assertNoKernelReaders(t, backend)
}

func TestKernelIPv6PolicyAndManagementExemption(t *testing.T) {
	p := policy.Default()
	p.Mode = "enforce"
	p.ManagementCIDRs = []string{"2001:db8::10/128"}
	rule := dropRule()
	rule.Protocol = "tcp"
	rule.Source = "2001:db8::/32"
	rule.Destination = "any"
	rule.DestinationPort = "any"
	p.Rules = []model.Rule{rule}
	payload := tcpFrame("192.0.2.10", "198.51.100.10", 42000, p.ManagementPort, 0x02)[34:]
	program, backend := kernelFixture(t, p, nil)
	for _, test := range []struct {
		name, source string
		port         uint16
		want         uint32
	}{
		{"management tuple", "2001:db8::10", p.ManagementPort, 2},
		{"management source other service", "2001:db8::10", 443, 1},
		{"non-management source SSH", "2001:db8::11", p.ManagementPort, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			tcp := append([]byte(nil), payload...)
			binary.BigEndian.PutUint16(tcp[2:4], test.port)
			frame := ipv6Frame(test.source, "2001:db8:1::1", 6, tcp)
			got, _, err := program.Test(frame)
			if err != nil || got != test.want {
				t.Fatalf("action=%d want=%d error=%v", got, test.want, err)
			}
			assertNoKernelReaders(t, backend)
		})
	}
}

func TestKernelByteBudgets(t *testing.T) {
	frame := tcpFrame("192.0.2.10", "198.51.100.10", 42000, 8080, 0x02)
	rateRule := func() model.Rule { r := dropRule(); r.Action = "limit"; r.PPS = 1000; r.Burst = 1000; return r }
	t.Run("aggregate counts IP bytes not Ethernet bytes", func(t *testing.T) {
		p := policy.Default()
		p.Mode = "enforce"
		r := rateRule()
		r.BPS = 1
		r.ByteBurst = 80
		p.Rules = []model.Rule{r}
		program, backend := kernelFixture(t, p, nil)
		now, err := monotonicNS()
		if err != nil {
			t.Fatal(err)
		}
		if err := backend.collection.Maps["service_buckets"].Put(bucketKey{Version: p.Version, Slot: 0}, bucketValue{UpdatedNS: now + uint64(time.Hour), Credits: 1000 * 1_000_000_000, ByteCredits: 80 * 1_000_000_000}); err != nil {
			t.Fatal(err)
		}
		for i, want := range []uint32{2, 2, 1} {
			candidate := append([]byte(nil), frame...)
			candidate[29] = byte(10 + i)
			got, _, err := program.Test(candidate)
			if err != nil || got != want {
				t.Fatalf("packet %d action=%d want=%d error=%v", i, got, want, err)
			}
		}
		var reasons []Counter
		if err := backend.collection.Maps["counters"].Lookup(uint32(12), &reasons); err != nil {
			t.Fatal(err)
		}
		var total uint64
		for _, c := range reasons {
			total += c.Packets
		}
		if total != 1 {
			t.Fatalf("byte_limit counter=%d", total)
		}
		assertNoKernelReaders(t, backend)
	})
	t.Run("byte rejection preserves packet token", func(t *testing.T) {
		p := policy.Default()
		p.Mode = "enforce"
		r := rateRule()
		r.PPS = 1
		r.Burst = 1
		r.BPS = 1
		r.ByteBurst = 40
		p.Rules = []model.Rule{r}
		program, backend := kernelFixture(t, p, nil)
		now, err := monotonicNS()
		if err != nil {
			t.Fatal(err)
		}
		if err := backend.collection.Maps["service_buckets"].Put(bucketKey{Version: p.Version, Slot: 0}, bucketValue{UpdatedNS: now + uint64(time.Hour), Credits: 1_000_000_000, ByteCredits: 40 * 1_000_000_000}); err != nil {
			t.Fatal(err)
		}
		large := append(append([]byte(nil), frame...), make([]byte, 20)...)
		binary.BigEndian.PutUint16(large[16:18], 60)
		first, _, err := program.Test(large)
		if err != nil || first != 1 {
			t.Fatalf("oversize byte burst action=%d error=%v", first, err)
		}
		second, _, err := program.Test(frame)
		if err != nil || second != 2 {
			t.Fatalf("byte rejection charged packet credit, next action=%d error=%v", second, err)
		}
		assertNoKernelReaders(t, backend)
	})
	t.Run("source byte budget independent of source packets", func(t *testing.T) {
		p := policy.Default()
		p.Mode = "enforce"
		r := rateRule()
		r.SourceBPS = 1
		r.SourceByteBurst = 40
		p.Rules = []model.Rule{r}
		program, backend := kernelFixture(t, p, nil)
		now, err := monotonicNS()
		if err != nil {
			t.Fatal(err)
		}
		var address [16]byte
		copy(address[:4], []byte{192, 0, 2, 10})
		if err := backend.collection.Maps["source_buckets"].Put(sourceKey{Version: p.Version, Slot: 0, Family: 4, Address: address}, bucketValue{UpdatedNS: now + uint64(time.Hour), ByteCredits: 40 * 1_000_000_000}); err != nil {
			t.Fatal(err)
		}
		for i, want := range []uint32{2, 1, 2} {
			candidate := append([]byte(nil), frame...)
			if i == 2 {
				candidate[29] = 11
			}
			got, _, err := program.Test(candidate)
			if err != nil || got != want {
				t.Fatalf("source byte packet %d action=%d want=%d error=%v", i, got, want, err)
			}
		}
		assertNoKernelReaders(t, backend)
	})
	t.Run("source byte rejection preserves source packet token", func(t *testing.T) {
		p := policy.Default()
		p.Mode = "enforce"
		r := rateRule()
		r.SourcePPS, r.SourceBurst = 1, 1
		r.SourceBPS, r.SourceByteBurst = 1, 40
		p.Rules = []model.Rule{r}
		program, backend := kernelFixture(t, p, nil)
		now, err := monotonicNS()
		if err != nil {
			t.Fatal(err)
		}
		var address [16]byte
		copy(address[:4], []byte{192, 0, 2, 10})
		key := sourceKey{Version: p.Version, Slot: 0, Family: 4, Address: address}
		if err := backend.collection.Maps["source_buckets"].Put(key, bucketValue{UpdatedNS: now + uint64(time.Hour), Credits: 1_000_000_000, ByteCredits: 40 * 1_000_000_000}); err != nil {
			t.Fatal(err)
		}
		large := append(append([]byte(nil), frame...), make([]byte, 20)...)
		binary.BigEndian.PutUint16(large[16:18], 60)
		for i, test := range []struct {
			frame []byte
			want  uint32
		}{{large, 1}, {frame, 2}, {frame, 1}} {
			got, _, err := program.Test(test.frame)
			if err != nil || got != test.want {
				t.Fatalf("source dual-budget packet %d action=%d want=%d error=%v", i, got, test.want, err)
			}
			assertNoKernelReaders(t, backend)
		}
	})
}

func tcpFrame(source, destination string, sourcePort, destinationPort uint16, flags byte) []byte {
	packet := make([]byte, 54)
	copy(packet[:12], []byte{2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2})
	binary.BigEndian.PutUint16(packet[12:14], 0x0800)
	ip := packet[14:34]
	ip[0], ip[8], ip[9] = 0x45, 64, 6
	binary.BigEndian.PutUint16(ip[2:4], 40)
	src := netip.MustParseAddr(source).As4()
	dst := netip.MustParseAddr(destination).As4()
	copy(ip[12:16], src[:])
	copy(ip[16:20], dst[:])
	tcp := packet[34:]
	binary.BigEndian.PutUint16(tcp[:2], sourcePort)
	binary.BigEndian.PutUint16(tcp[2:4], destinationPort)
	tcp[12], tcp[13] = 0x50, flags
	return packet
}

func udpFrame(source, destination string, sourcePort, destinationPort uint16) []byte {
	packet := tcpFrame(source, destination, sourcePort, destinationPort, 0)
	packet = packet[:42]
	packet[23] = 17
	binary.BigEndian.PutUint16(packet[16:18], 28)
	binary.BigEndian.PutUint16(packet[38:40], 8)
	return packet
}

func ipv6Frame(source, destination string, next byte, payload []byte) []byte {
	packet := make([]byte, 14+40+len(payload))
	binary.BigEndian.PutUint16(packet[12:14], 0x86dd)
	packet[14], packet[20], packet[21] = 0x60, next, 64
	binary.BigEndian.PutUint16(packet[18:20], uint16(len(payload)))
	src, dst := netip.MustParseAddr(source).As16(), netip.MustParseAddr(destination).As16()
	copy(packet[22:38], src[:])
	copy(packet[38:54], dst[:])
	copy(packet[54:], payload)
	return packet
}

func assertNoKernelReaders(t *testing.T, backend *linuxBackend) {
	t.Helper()
	var active []uint64
	if err := backend.collection.Maps["readers"].Lookup(uint32(0), &active); err != nil {
		t.Fatal(err)
	}
	if !readersQuiescent(active) {
		t.Fatalf("XDP exit leaked a reader: %v", active)
	}
}

func dropRule() model.Rule {
	return model.Rule{ID: "blocked", Name: "block test service", Enabled: true, Priority: 10, Action: "drop", Protocol: "tcp", Source: "192.0.2.0/24", Destination: "198.51.100.0/24", SourcePort: "any", DestinationPort: "8080"}
}

func TestKernelPacketCorpus(t *testing.T) {
	base := policy.Default()
	base.Mode = "enforce"
	base.Rules = []model.Rule{dropRule()}
	matching := tcpFrame("192.0.2.10", "198.51.100.10", 42000, 8080, 0x02)
	wrongPort := tcpFrame("192.0.2.10", "198.51.100.10", 42000, 8081, 0x02)
	truncated := append([]byte(nil), matching[:20]...)
	badOffset := append([]byte(nil), matching...)
	badOffset[46] = 0x40
	badIHL := append([]byte(nil), matching...)
	badIHL[14] = 0x44
	shortIP := append([]byte(nil), matching...)
	binary.BigEndian.PutUint16(shortIP[16:18], 19)
	longIP := append([]byte(nil), matching...)
	binary.BigEndian.PutUint16(longIP[16:18], 1000)
	reservedFragment := append([]byte(nil), matching...)
	binary.BigEndian.PutUint16(reservedFragment[20:22], 0x8000)
	nonFirstFragment := append([]byte(nil), matching...)
	binary.BigEndian.PutUint16(nonFirstFragment[20:22], 1)
	options := make([]byte, len(wrongPort)+4)
	copy(options, wrongPort[:34])
	copy(options[38:], wrongPort[34:])
	options[14] = 0x46
	binary.BigEndian.PutUint16(options[16:18], 44)
	validUDP := udpFrame("192.0.2.10", "198.51.100.10", 42000, 53)
	shortUDP := append([]byte(nil), validUDP...)
	binary.BigEndian.PutUint16(shortUDP[38:40], 7)
	longUDP := append([]byte(nil), validUDP...)
	binary.BigEndian.PutUint16(longUDP[38:40], 9)
	tcpPayload := append([]byte(nil), wrongPort[34:]...)
	validIPv6 := ipv6Frame("2001:db8::1", "2001:db8::2", 6, tcpPayload)
	truncatedIPv6 := validIPv6[:40]
	longIPv6 := append([]byte(nil), validIPv6...)
	binary.BigEndian.PutUint16(longIPv6[18:20], 1000)
	extension := ipv6Frame("2001:db8::1", "2001:db8::2", 0, append(make([]byte, 8), tcpPayload...))
	ipv6Fragment := ipv6Frame("2001:db8::1", "2001:db8::2", 44, append(make([]byte, 8), tcpPayload...))
	jumbogram := append([]byte(nil), validIPv6...)
	binary.BigEndian.PutUint16(jumbogram[18:20], 0)
	arp := make([]byte, 42)
	binary.BigEndian.PutUint16(arp[12:14], 0x0806)
	unknownL2 := append([]byte(nil), matching...)
	binary.BigEndian.PutUint16(unknownL2[12:14], 0x88b5)
	fragment := append([]byte(nil), matching...)
	binary.BigEndian.PutUint16(fragment[20:22], 0x2000)
	vlan := make([]byte, len(matching)+4)
	copy(vlan, matching[:12])
	binary.BigEndian.PutUint16(vlan[12:14], 0x8100)
	binary.BigEndian.PutUint16(vlan[16:18], 0x0800)
	copy(vlan[18:], matching[14:])
	for _, test := range []struct {
		name     string
		packet   []byte
		expected uint32
	}{
		{"matching drop", matching, 1}, {"different port", wrongPort, 2},
		{"truncated IPv4", truncated, 1}, {"invalid TCP offset", badOffset, 1},
		{"fragment cannot bypass early ACL", fragment, 1}, {"VLAN preserves ACL", vlan, 1},
		{"short Ethernet", matching[:10], 1}, {"invalid IPv4 IHL", badIHL, 1},
		{"IPv4 total shorter than header", shortIP, 1}, {"IPv4 claims unavailable bytes", longIP, 1},
		{"reserved IPv4 fragment flag", reservedFragment, 1}, {"non-first fragment", nonFirstFragment, 1},
		{"IPv4 options strict profile", options, 1},
		{"valid UDP", validUDP, 2}, {"short UDP length", shortUDP, 1}, {"UDP exceeds IP payload", longUDP, 1},
		{"simple IPv6 TCP", validIPv6, 2}, {"truncated IPv6", truncatedIPv6, 1}, {"IPv6 length overrun", longIPv6, 1},
		{"IPv6 extension strict profile", extension, 1}, {"IPv6 fragment strict profile", ipv6Fragment, 1}, {"jumbogram strict profile", jumbogram, 1},
		{"ARP is preserved", arp, 2}, {"unsupported L2 strict profile", unknownL2, 1},
		{"SYN plus FIN", tcpFrame("192.0.2.10", "198.51.100.10", 42000, 8081, 0x03), 1},
		{"SYN plus RST", tcpFrame("192.0.2.10", "198.51.100.10", 42000, 8081, 0x06), 1},
		{"FIN plus RST", tcpFrame("192.0.2.10", "198.51.100.10", 42000, 8081, 0x05), 1},
		{"SYN ACK remains parseable", tcpFrame("192.0.2.10", "198.51.100.10", 42000, 8081, 0x12), 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			program, backend := kernelFixture(t, base, nil)
			verdict, _, err := program.Test(test.packet)
			if err != nil {
				t.Fatal(err)
			}
			if verdict != test.expected {
				t.Fatalf("XDP action = %d, want %d", verdict, test.expected)
			}
			assertNoKernelReaders(t, backend)
		})
	}
}

func TestKernelObserveBanAndLimiter(t *testing.T) {
	frame := tcpFrame("192.0.2.10", "198.51.100.10", 42000, 8080, 0x02)
	t.Run("fragment cannot evade a CIDR block on an allowed service", func(t *testing.T) {
		p := policy.Default()
		p.Mode = "enforce"
		p.Host.TCPPorts = []uint16{443}
		rule := dropRule()
		rule.DestinationPort = "443"
		p.Rules = []model.Rule{rule}
		fragment := tcpFrame("192.0.2.10", "198.51.100.10", 42000, 443, 0x02)
		binary.BigEndian.PutUint16(fragment[20:22], 0x2000)
		program, _ := kernelFixture(t, p, nil)
		verdict, _, err := program.Test(fragment)
		if err != nil || verdict != 1 {
			t.Fatalf("fragmented allowed-service packet escaped strict ACL profile: %d: %v", verdict, err)
		}
	})
	t.Run("observe counts without dropping", func(t *testing.T) {
		p := policy.Default()
		p.Mode = "observe"
		p.Rules = []model.Rule{dropRule()}
		program, backend := kernelFixture(t, p, nil)
		verdict, _, err := program.Test(frame)
		if err != nil || verdict != 2 {
			t.Fatalf("observe verdict %d: %v", verdict, err)
		}
		var values []Counter
		if err := backend.collection.Maps["counters"].Lookup(uint32(2), &values); err != nil {
			t.Fatal(err)
		}
		var count uint64
		for _, value := range values {
			count += value.Packets
		}
		if count != 1 {
			t.Fatalf("would_drop count = %d", count)
		}
		assertNoKernelReaders(t, backend)
	})
	t.Run("active ban and expired ban", func(t *testing.T) {
		p := policy.Default()
		p.Mode = "enforce"
		p.Rules = nil
		program, backend := kernelFixture(t, p, []model.Ban{{Address: "192.0.2.10", ExpiresAt: time.Now().Add(time.Minute)}})
		verdict, _, err := program.Test(frame)
		if err != nil || verdict != 1 {
			t.Fatalf("active ban verdict %d: %v", verdict, err)
		}
		// Expire the kernel entry in place. No userspace cleanup runs, proving
		// that the packet path itself enforces the deadline.
		var address [16]byte
		copy(address[:4], []byte{192, 0, 2, 10})
		if err := backend.collection.Maps["bans"].Put(banKey{Version: p.Version, Family: 4, Address: address}, uint64(0)); err != nil {
			t.Fatal(err)
		}
		verdict, _, err = program.Test(frame)
		if err != nil || verdict != 2 {
			t.Fatalf("expired ban verdict %d: %v", verdict, err)
		}
		assertNoKernelReaders(t, backend)
	})
	t.Run("aggregate burst is shared", func(t *testing.T) {
		p := policy.Default()
		p.Mode = "enforce"
		rule := dropRule()
		rule.Action = "limit"
		rule.PPS = 1
		rule.Burst = 1
		p.Rules = []model.Rule{rule}
		program, backend := kernelFixture(t, p, nil)
		now, err := monotonicNS()
		if err != nil {
			t.Fatal(err)
		}
		future := now + uint64(time.Hour)
		if err := backend.collection.Maps["service_buckets"].Put(bucketKey{Version: p.Version, Slot: 0}, bucketValue{UpdatedNS: future, Credits: 1_000_000_000}); err != nil {
			t.Fatal(err)
		}
		first, _, err := program.Test(frame)
		if err != nil {
			t.Fatal(err)
		}
		otherSource := tcpFrame("192.0.2.11", "198.51.100.10", 42001, 8080, 0x02)
		second, _, err := program.Test(otherSource)
		if err != nil {
			t.Fatal(err)
		}
		if first != 2 || second != 1 {
			t.Fatalf("burst actions = %d,%d", first, second)
		}
		var bucket bucketValue
		if err := backend.collection.Maps["service_buckets"].Lookup(bucketKey{Version: p.Version, Slot: 0}, &bucket); err != nil {
			t.Fatal(err)
		}
		if bucket.UpdatedNS != future {
			t.Fatalf("shared refill clock moved backwards: %d, want %d", bucket.UpdatedNS, future)
		}
		assertNoKernelReaders(t, backend)
	})
}
