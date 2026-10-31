package policy

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TheDarkGuardian/WireWall/internal/model"
)

func TestByteBudgetRefillAndAtomicPacketCharge(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	p := ratePolicy(1, 1)
	p.Rules[0].BPS = 100
	p.Rules[0].ByteBurst = 50
	e := NewEvaluatorWithClock(func() time.Time { return now })
	packet := testPacket() // 60 IP bytes cannot fit the 50-byte burst.
	if got := e.Evaluate(p, packet, nil); got.Reason != "byte_limit" {
		t.Fatal(got)
	}
	packet.Length = 40
	if got := e.Evaluate(p, packet, nil); got.Action != "pass" {
		t.Fatalf("byte rejection consumed the packet token: %+v", got)
	}
	if got := e.Evaluate(p, packet, nil); got.Reason != "rate_limit" {
		t.Fatal(got)
	}
	now = now.Add(time.Second)
	if got := e.Evaluate(p, packet, nil); got.Action != "pass" {
		t.Fatalf("dual budget refill failed: %+v", got)
	}
}

func TestPacketRejectionDoesNotChargeByteBudget(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	p := ratePolicy(1, 1)
	p.Rules[0].BPS = 1
	p.Rules[0].ByteBurst = 120
	e := NewEvaluatorWithClock(func() time.Time { return now })
	packet := testPacket()
	if got := e.Evaluate(p, packet, nil); got.Action != "pass" {
		t.Fatal(got)
	}
	if got := e.Evaluate(p, packet, nil); got.Reason != "rate_limit" {
		t.Fatal(got)
	}
	now = now.Add(time.Second)
	if got := e.Evaluate(p, packet, nil); got.Action != "pass" {
		t.Fatalf("packet rejection consumed bytes: %+v", got)
	}
}

func TestByteRateUsesBytesAndFractionalRefill(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	p := ratePolicy(1000, 1000)
	p.Rules[0].BPS = 120
	p.Rules[0].ByteBurst = 60
	e := NewEvaluatorWithClock(func() time.Time { return now })
	packet := testPacket()
	if got := e.Evaluate(p, packet, nil); got.Action != "pass" {
		t.Fatal(got)
	}
	now = now.Add(499 * time.Millisecond)
	if got := e.Evaluate(p, packet, nil); got.Reason != "byte_limit" {
		t.Fatalf("byte rate refilled too early: %+v", got)
	}
	now = now.Add(time.Millisecond)
	if got := e.Evaluate(p, packet, nil); got.Action != "pass" {
		t.Fatalf("120 bytes/s did not refill 60 bytes in 500ms: %+v", got)
	}
	now = now.Add(-time.Second)
	if got := e.Evaluate(p, packet, nil); got.Reason != "byte_limit" {
		t.Fatalf("backward clock replenished byte budget: %+v", got)
	}
	now = now.Add(100 * 365 * 24 * time.Hour)
	if got := e.Evaluate(p, packet, nil); got.Action != "pass" {
		t.Fatalf("long idle overflow: %+v", got)
	}
}

func TestSourceByteBudgetWithoutSourcePPS(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	p := ratePolicy(1000, 1000)
	p.Rules[0].SourceBPS = 1
	p.Rules[0].SourceByteBurst = 60
	e := NewEvaluatorWithClock(func() time.Time { return now })
	packet := testPacket()
	if got := e.Evaluate(p, packet, nil); got.Action != "pass" {
		t.Fatal(got)
	}
	if got := e.Evaluate(p, packet, nil); got.Reason != "source_byte_limit" {
		t.Fatal(got)
	}
	packet.Source = "198.51.100.1"
	if got := e.Evaluate(p, packet, nil); got.Action != "pass" {
		t.Fatalf("separate source did not receive its own byte budget: %+v", got)
	}
	now = now.Add(6 * time.Minute)
	if got := e.Evaluate(p, packet, nil); got.Action != "pass" {
		t.Fatalf("byte-only source pruning failed: %+v", got)
	}
}

func TestSourceDualBudgetChargesTogether(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	p := ratePolicy(1000, 1000)
	p.Rules[0].SourcePPS, p.Rules[0].SourceBurst = 1, 1
	p.Rules[0].SourceBPS, p.Rules[0].SourceByteBurst = 100, 50
	e := NewEvaluatorWithClock(func() time.Time { return now })
	packet := testPacket()
	if got := e.Evaluate(p, packet, nil); got.Reason != "source_byte_limit" {
		t.Fatalf("oversized source packet: %+v", got)
	}
	packet.Length = 40
	if got := e.Evaluate(p, packet, nil); got.Action != "pass" {
		t.Fatalf("source-byte rejection consumed its packet token: %+v", got)
	}
	if got := e.Evaluate(p, packet, nil); got.Reason != "source_rate_limit" {
		t.Fatalf("source packet budget was not shared with byte budget: %+v", got)
	}
}

func TestSourcePacketRejectionPreservesSourceByteCredit(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	p := ratePolicy(1000, 1000)
	p.Rules[0].SourcePPS, p.Rules[0].SourceBurst = 1, 1
	p.Rules[0].SourceBPS, p.Rules[0].SourceByteBurst = 1, 120
	e := NewEvaluatorWithClock(func() time.Time { return now })
	packet := testPacket()
	if got := e.Evaluate(p, packet, nil); got.Action != "pass" {
		t.Fatal(got)
	}
	if got := e.Evaluate(p, packet, nil); got.Reason != "source_rate_limit" {
		t.Fatal(got)
	}
	now = now.Add(time.Second)
	if got := e.Evaluate(p, packet, nil); got.Action != "pass" {
		t.Fatalf("source packet rejection consumed the remaining bytes: %+v", got)
	}
}

func TestSourceByteCapacityFallbackStillEnforcesAggregateBytes(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	p := ratePolicy(1000, 1000)
	p.Rules[0].BPS = 1
	p.Rules[0].ByteBurst = 120
	p.Rules[0].SourceBPS = 1
	p.Rules[0].SourceByteBurst = 60
	e := NewEvaluatorWithOptions(Options{Clock: func() time.Time { return now }, SourceCapacity: 1})
	packet := testPacket()
	if got := e.Evaluate(p, packet, nil); got.Action != "pass" {
		t.Fatal(got)
	}
	packet.Source = "198.51.100.1"
	if got := e.Evaluate(p, packet, nil); got.Reason != "source_capacity_fallback" {
		t.Fatal(got)
	}
	packet.Source = "198.51.100.2"
	if got := e.Evaluate(p, packet, nil); got.Reason != "byte_limit" {
		t.Fatalf("source map pressure bypassed aggregate bytes: %+v", got)
	}
}

func TestByteBurstSharedAcrossSourcesAndGoroutines(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	p := ratePolicy(1000, 1000)
	p.Rules[0].BPS = 1
	p.Rules[0].ByteBurst = 600
	e := NewEvaluatorWithClock(func() time.Time { return now })
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
	if passed.Load() != 10 {
		t.Fatalf("600-byte shared burst accepted %d sixty-byte packets; want 10", passed.Load())
	}
}

func TestObserveByteLimitAndOverflowBounds(t *testing.T) {
	p := ratePolicy(1000, 1000)
	p.Mode = "observe"
	p.Rules[0].BPS = 1
	p.Rules[0].ByteBurst = 40
	got := NewEvaluator().Evaluate(p, testPacket(), nil)
	if got.Action != "pass" || !got.WouldDrop || got.Reason != "byte_limit" {
		t.Fatal(got)
	}
	maximum := MaxRate * tokenCredit
	if got := refillCredits(0, MaxRate, MaxRate, ^uint64(0)); got != maximum {
		t.Fatalf("saturated credit overflow: %d", got)
	}
	if got := refillCredits(maximum, 0, 0, ^uint64(0)); got != 0 {
		t.Fatalf("disabled budget credit=%d", got)
	}
}

func TestByteFieldValidation(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*model.Rule)
		valid  bool
	}{
		{"packet-only remains valid", func(*model.Rule) {}, true},
		{"aggregate bytes", func(r *model.Rule) { r.BPS = 100; r.ByteBurst = 1000 }, true},
		{"source bytes without source packets", func(r *model.Rule) { r.SourceBPS = 100; r.SourceByteBurst = 1000 }, true},
		{"missing aggregate burst", func(r *model.Rule) { r.BPS = 1 }, false},
		{"missing aggregate rate", func(r *model.Rule) { r.ByteBurst = 1 }, false},
		{"missing source burst", func(r *model.Rule) { r.SourceBPS = 1 }, false},
		{"missing source rate", func(r *model.Rule) { r.SourceByteBurst = 1 }, false},
		{"oversized aggregate rate", func(r *model.Rule) { r.BPS = MaxRate + 1; r.ByteBurst = 1 }, false},
		{"oversized source burst", func(r *model.Rule) { r.SourceBPS = 1; r.SourceByteBurst = MaxRate + 1 }, false},
		{"bytes on drop action", func(r *model.Rule) { r.Action = "drop"; r.PPS = 0; r.Burst = 0; r.BPS = 1; r.ByteBurst = 1 }, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			p := ratePolicy(1000, 1000)
			test.mutate(&p.Rules[0])
			err := Validate(p)
			if (err == nil) != test.valid {
				t.Fatalf("valid=%v error=%v", test.valid, err)
			}
		})
	}
}
