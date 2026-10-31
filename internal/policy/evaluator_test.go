package policy

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TheDarkGuardian/WireWall/internal/model"
)

func testPacket() model.Packet {
	return model.Packet{Source: "203.0.113.10", Destination: "192.0.2.20", SourcePort: 49152, DestinationPort: 443, Protocol: "tcp", Length: 60, TCPFlags: "syn"}
}

func TestEvaluateANDAndPriority(t *testing.T) {
	p := testPolicy()
	p.Rules[0].Source = "203.0.113.0/24"
	p.Rules[0].Destination = "192.0.2.0/24"
	p.Rules[0].DestinationPort = "440-443"
	tests := []struct {
		name   string
		mutate func(*model.Packet)
		want   string
	}{
		{"all match", func(*model.Packet) {}, "drop"},
		{"source differs", func(v *model.Packet) { v.Source = "198.51.100.10" }, "pass"},
		{"destination differs", func(v *model.Packet) { v.Destination = "198.51.100.20" }, "pass"},
		{"port below", func(v *model.Packet) { v.DestinationPort = 439 }, "pass"},
		{"range lower boundary", func(v *model.Packet) { v.DestinationPort = 440 }, "drop"},
		{"port above", func(v *model.Packet) { v.DestinationPort = 444 }, "pass"},
		{"protocol differs", func(v *model.Packet) { v.Protocol = "udp"; v.TCPFlags = "" }, "pass"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			packet := testPacket()
			test.mutate(&packet)
			got := NewEvaluator().Evaluate(p, packet, nil)
			if got.Action != test.want {
				t.Fatalf("got %+v, want %s", got, test.want)
			}
		})
	}
	allow := testRule()
	allow.ID = "allow-specific"
	allow.Action = "pass"
	allow.Priority = 10
	p.Rules = append(p.Rules, allow)
	got := NewEvaluator().Evaluate(p, testPacket(), nil)
	if got.Action != "pass" || got.RuleID != allow.ID {
		t.Fatalf("first priority must win: %+v", got)
	}
	p.Rules[1].Enabled = false
	if got = NewEvaluator().Evaluate(p, testPacket(), nil); got.Action != "drop" {
		t.Fatalf("disabled allow changed decision: %+v", got)
	}
}

func TestObservePreservesHypotheticalDrop(t *testing.T) {
	p := testPolicy()
	p.Mode = "observe"
	got := NewEvaluator().Evaluate(p, testPacket(), nil)
	if got.Action != "pass" || !got.WouldDrop || got.Reason != "rule_drop" {
		t.Fatalf("observe decision: %+v", got)
	}
}

func TestEnforceDropIsNotHypothetical(t *testing.T) {
	p := testPolicy()
	p.Mode = "enforce"
	got := NewEvaluator().Evaluate(p, testPacket(), nil)
	if got.Action != "drop" || got.WouldDrop {
		t.Fatalf("enforce decision must be an actual drop: %+v", got)
	}
	p.Mode = "invalid"
	got = NewEvaluator().Evaluate(p, testPacket(), nil)
	if got.Action != "drop" || got.WouldDrop {
		t.Fatalf("invalid policy is fail-closed, not observation: %+v", got)
	}
}

func TestManagementExemptionIsNarrow(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	p := testPolicy()
	p.ManagementCIDRs = []string{"203.0.113.10/32"}
	p.Rules[0].DestinationPort = "any"
	ban := model.Ban{ID: "blocked", Address: "203.0.113.10", Reason: "Test", CreatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute)}
	e := NewEvaluatorWithClock(func() time.Time { return now })
	packet := testPacket()
	packet.DestinationPort = 22
	if got := e.Evaluate(p, packet, []model.Ban{ban}); got.Reason != "management_exemption" || got.Action != "pass" {
		t.Fatalf("management: %+v", got)
	}
	packet.DestinationPort = 443
	if got := e.Evaluate(p, packet, []model.Ban{ban}); got.Action != "drop" {
		t.Fatalf("management exemption leaked to web port: %+v", got)
	}
	packet.DestinationPort = 22
	packet.Protocol = "udp"
	packet.TCPFlags = ""
	if got := e.Evaluate(p, packet, []model.Ban{ban}); got.Action != "drop" {
		t.Fatalf("management exemption leaked to UDP: %+v", got)
	}
}

func TestBanExpirationUsesTrustedClock(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	p := Default()
	p.Mode = "enforce"
	ban := model.Ban{ID: "blocked", Address: "203.0.113.10", Reason: "Test", CreatedAt: now, ExpiresAt: now.Add(time.Minute)}
	e := NewEvaluatorWithClock(func() time.Time { return now })
	packet := testPacket()
	packet.Timestamp = now.Add(24 * time.Hour)
	if got := e.Evaluate(p, packet, []model.Ban{ban}); got.Action != "drop" {
		t.Fatalf("caller timestamp bypassed active ban: %+v", got)
	}
	now = now.Add(time.Minute)
	if got := e.Evaluate(p, packet, []model.Ban{ban}); got.Action != "pass" {
		t.Fatalf("ban active at expiration boundary: %+v", got)
	}
}

func TestSYNMatchingDoesNotTrustACK(t *testing.T) {
	p := testPolicy()
	p.Rules[0].TCPFlags = "syn"
	e := NewEvaluator()
	packet := testPacket()
	for _, flags := range []string{"syn", "SYN,ECE,CWR"} {
		packet.TCPFlags = flags
		if got := e.Evaluate(p, packet, nil); got.Action != "drop" {
			t.Fatalf("initial SYN flags %q: %+v", flags, got)
		}
	}
	for _, flags := range []string{"ack", "syn,ack", ""} {
		packet.TCPFlags = flags
		if got := e.Evaluate(p, packet, nil); got.Action != "pass" {
			t.Fatalf("noninitial flags %q matched SYN rule: %+v", flags, got)
		}
	}
}

func TestIPv6AndMalformedPackets(t *testing.T) {
	p := testPolicy()
	p.Rules[0].Source = "2001:db8:1::/48"
	p.Rules[0].Destination = "2001:db8:2::/48"
	packet := testPacket()
	packet.Source = "2001:db8:1::42"
	packet.Destination = "2001:db8:2::20"
	packet.Length = 80
	if got := NewEvaluator().Evaluate(p, packet, nil); got.Action != "drop" || got.Reason != "rule_drop" {
		t.Fatalf("IPv6: %+v", got)
	}
	for _, mutate := range []func(*model.Packet){func(v *model.Packet) { v.Source = "bad" }, func(v *model.Packet) { v.Length = 30 }, func(v *model.Packet) { v.Destination = "192.0.2.2" }, func(v *model.Packet) { v.TCPFlags = "trusted" }} {
		candidate := packet
		mutate(&candidate)
		if got := NewEvaluator().Evaluate(p, candidate, nil); got.Reason != "invalid_packet" {
			t.Fatalf("malformed packet accepted: %+v", got)
		}
	}
}

func ratePolicy(pps, burst uint64) model.Policy {
	p := testPolicy()
	p.Rules[0].Action = "limit"
	p.Rules[0].PPS = pps
	p.Rules[0].Burst = burst
	return p
}

func TestTokenBucketBurstRefillAndCallerTimestamp(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	e := NewEvaluatorWithClock(func() time.Time { return now })
	p := ratePolicy(4, 2)
	packet := testPacket()
	for i := 0; i < 2; i++ {
		if got := e.Evaluate(p, packet, nil); got.Action != "pass" {
			t.Fatal(got)
		}
	}
	packet.Timestamp = now.Add(24 * time.Hour)
	if got := e.Evaluate(p, packet, nil); got.Reason != "rate_limit" {
		t.Fatalf("timestamp bypass: %+v", got)
	}
	now = now.Add(249 * time.Millisecond)
	if got := e.Evaluate(p, packet, nil); got.Action != "drop" {
		t.Fatalf("fractional credits ignored: %+v", got)
	}
	now = now.Add(time.Millisecond)
	if got := e.Evaluate(p, packet, nil); got.Action != "pass" {
		t.Fatalf("refill boundary: %+v", got)
	}
	now = now.Add(-time.Second)
	if got := e.Evaluate(p, packet, nil); got.Action != "drop" {
		t.Fatalf("backward clock refilled bucket: %+v", got)
	}
	now = now.Add(100 * 365 * 24 * time.Hour)
	if got := e.Evaluate(p, packet, nil); got.Action != "pass" {
		t.Fatalf("long idle overflow: %+v", got)
	}
}

func TestAggregateLimitIsSharedAcrossGoroutinesAndSources(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	e := NewEvaluatorWithClock(func() time.Time { return now })
	p := ratePolicy(1, 25)
	var passed atomic.Int64
	var group sync.WaitGroup
	for i := 0; i < 200; i++ {
		group.Add(1)
		go func(i int) {
			defer group.Done()
			packet := testPacket()
			packet.Source = fmt.Sprintf("198.51.100.%d", i%250+1)
			if e.Evaluate(p, packet, nil).Action == "pass" {
				passed.Add(1)
			}
		}(i)
	}
	group.Wait()
	if passed.Load() != 25 {
		t.Fatalf("shared burst = %d; want exactly 25", passed.Load())
	}
}

func TestSourceLimitAndBoundedCapacityFallback(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	e := NewEvaluatorWithOptions(Options{Clock: func() time.Time { return now }, SourceCapacity: 1})
	p := ratePolicy(10, 4)
	p.Rules[0].SourcePPS = 1
	p.Rules[0].SourceBurst = 1
	packet := testPacket()
	if got := e.Evaluate(p, packet, nil); got.Action != "pass" {
		t.Fatal(got)
	}
	if got := e.Evaluate(p, packet, nil); got.Reason != "source_rate_limit" {
		t.Fatalf("source burst: %+v", got)
	}
	packet.Source = "198.51.100.1"
	if got := e.Evaluate(p, packet, nil); got.Reason != "source_capacity_fallback" || got.Action != "pass" {
		t.Fatalf("capacity fallback: %+v", got)
	}
	packet.Source = "198.51.100.2"
	e.Evaluate(p, packet, nil)
	if got := e.Evaluate(p, packet, nil); got.Reason != "rate_limit" {
		t.Fatalf("capacity fallback bypassed aggregate: %+v", got)
	}
	stats := e.Stats()
	if stats.SourceEntries != 1 || stats.CapacityFallbacks != 2 {
		t.Fatalf("stats: %+v", stats)
	}
	now = now.Add(6 * time.Minute)
	if got := e.Evaluate(p, packet, nil); got.Reason != "rate_limit_pass" {
		t.Fatalf("stale capacity not reclaimed: %+v", got)
	}
	if e.Stats().SourceEntries != 1 {
		t.Fatal("source capacity changed")
	}
}

func TestPolicyChangeDoesNotUseStaleMatchers(t *testing.T) {
	p := testPolicy()
	e := NewEvaluator()
	packet := testPacket()
	if got := e.Evaluate(p, packet, nil); got.Action != "drop" {
		t.Fatal(got)
	}
	p.Rules[0].DestinationPort = "80" // same version must not silently retain old contents
	if got := e.Evaluate(p, packet, nil); got.Action != "pass" {
		t.Fatalf("stale policy cache: %+v", got)
	}
	p.Rules[0].Action = "invalid"
	if got := e.Evaluate(p, packet, nil); got.Reason != "invalid_policy" || got.Action != "drop" {
		t.Fatalf("invalid policy failed open: %+v", got)
	}
}
