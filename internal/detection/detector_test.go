package detection

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TheDarkGuardian/WireWall/internal/model"
)

func testPacket(port uint16) model.Packet {
	return model.Packet{Source: "198.51.100.7", Destination: "203.0.113.10", SourcePort: 40000, DestinationPort: port, Protocol: "tcp", Length: 60, Timestamp: time.Unix(1, 0)}
}
func scan(detector *Detector, start, count int, sampled bool) []Alert {
	var alerts []Alert
	for i := start; i < start+count; i++ {
		alerts = append(alerts, detector.Observe(testPacket(uint16(i)), sampled)...)
	}
	return alerts
}

func TestUniquePortsProduceOneSuspectedScanWarning(t *testing.T) {
	now := time.Unix(100, 0)
	detector := New(Options{Clock: func() time.Time { return now }})
	for i := 0; i < 100; i++ {
		if alerts := detector.Observe(testPacket(443), false); len(alerts) != 0 {
			t.Fatal("repeated port generated scan warning")
		}
	}
	if alerts := scan(detector, 1000, 18, false); len(alerts) != 0 {
		t.Fatal("warning below threshold")
	}
	alerts := detector.Observe(testPacket(2000), false)
	if len(alerts) != 1 {
		t.Fatalf("threshold alerts=%+v", alerts)
	}
	alert := alerts[0]
	if alert.Type != "port_scan" || alert.Severity != "warning" || alert.UniquePorts != 20 || alert.Sampled || alert.WindowSeconds != 10 || !alert.Timestamp.Equal(now) || alert.ID == "" || !strings.Contains(alert.Message, "Olası") {
		t.Fatalf("alert=%+v", alert)
	}
	if alerts := scan(detector, 3000, 100, false); len(alerts) != 0 {
		t.Fatal("same-window alert repeated")
	}
	if stats := detector.Stats(); stats.Sources != 1 || stats.Alerts != 1 || stats.PortSetSaturations == 0 {
		t.Fatalf("bounded stats=%+v", stats)
	}
}

func TestWindowExpiryAndTrustedClock(t *testing.T) {
	now := time.Unix(100, 0)
	detector := New(Options{Threshold: 3, Window: time.Second, Clock: func() time.Time { return now }})
	packet := testPacket(1)
	packet.Timestamp = now.Add(24 * time.Hour)
	detector.Observe(packet, false)
	packet.DestinationPort = 2
	packet.Timestamp = now.Add(-24 * time.Hour)
	detector.Observe(packet, false)
	now = now.Add(time.Second)
	if alerts := detector.Observe(testPacket(3), false); len(alerts) != 0 {
		t.Fatal("expired ports contributed to new window")
	}
	if alerts := detector.Observe(testPacket(4), false); len(alerts) != 0 {
		t.Fatal("below new window threshold")
	}
	if alerts := detector.Observe(testPacket(5), false); len(alerts) != 1 || !alerts[0].Timestamp.Equal(now) {
		t.Fatalf("trusted clock alert=%+v", alerts)
	}
}

func TestCooldownSurvivesWindowResetsAndIdleCleanup(t *testing.T) {
	now := time.Unix(100, 0)
	detector := New(Options{Threshold: 2, Window: time.Second, Clock: func() time.Time { return now }})
	if alerts := scan(detector, 1, 2, false); len(alerts) != 1 {
		t.Fatal("initial warning missing")
	}
	now = now.Add(2 * time.Second)
	if alerts := scan(detector, 10, 2, false); len(alerts) != 0 {
		t.Fatal("window reset bypassed cooldown")
	}
	if detector.Stats().Sources != 1 {
		t.Fatal("cleanup evicted a cooling-down pair")
	}
	now = now.Add(28 * time.Second)
	if alerts := scan(detector, 20, 2, false); len(alerts) != 1 {
		t.Fatal("cooldown boundary did not permit fresh evidence")
	}
}

func TestCapacityDoesNotEvictActiveEvidenceAndIdleEntriesExpire(t *testing.T) {
	now := time.Unix(100, 0)
	detector := New(Options{SourceCapacity: 1, Threshold: 2, Window: time.Second, Clock: func() time.Time { return now }})
	detector.Observe(testPacket(1), false)
	other := testPacket(80)
	other.Source = "192.0.2.9"
	for i := 0; i < 20; i++ {
		detector.Observe(other, false)
	}
	if stats := detector.Stats(); stats.Sources != 1 || stats.CapacityDrops != 20 {
		t.Fatalf("capacity stats=%+v", stats)
	}
	if alerts := detector.Observe(testPacket(2), false); len(alerts) != 1 {
		t.Fatal("new sources evicted active evidence")
	}
	// A pair without a recent alert can be reclaimed after its idle window.
	detector = New(Options{SourceCapacity: 1, Threshold: 3, Window: time.Second, Clock: func() time.Time { return now }})
	detector.Observe(testPacket(1), false)
	now = now.Add(time.Second)
	detector.Observe(other, false)
	other.DestinationPort = 81
	detector.Observe(other, false)
	other.DestinationPort = 82
	alerts := detector.Observe(other, false)
	if len(alerts) != 1 || alerts[0].Source != other.Source {
		t.Fatal("idle pair did not free bounded capacity")
	}
}

func TestSamplingIsConservativeAndHistoryIsBoundedCopy(t *testing.T) {
	now := time.Unix(100, 0)
	detector := New(Options{Threshold: 2, MaxAlerts: 2, Clock: func() time.Time { return now }})
	detector.Observe(testPacket(1), true)
	alerts := detector.Observe(testPacket(2), false)
	if len(alerts) != 1 || !alerts[0].Sampled || !strings.Contains(alerts[0].Message, "Örneklenen") {
		t.Fatalf("mixed sampled evidence mislabeled: %+v", alerts)
	}
	for source := 1; source <= 3; source++ {
		for port := 1; port <= 2; port++ {
			packet := testPacket(uint16(port))
			packet.Source = fmt.Sprintf("192.0.2.%d", source)
			detector.Observe(packet, false)
		}
	}
	recent := detector.Recent()
	if len(recent) != 2 || recent[0].Source != "192.0.2.3" || recent[1].Source != "192.0.2.2" {
		t.Fatalf("history=%+v", recent)
	}
	recent[0].Message = "mutated"
	if detector.Recent()[0].Message == "mutated" {
		t.Fatal("caller mutated detector history")
	}
	if detector.Stats().Alerts != 2 {
		t.Fatal("retained alert capacity exceeded")
	}
}

func TestPairsProtocolsAndInvalidDescriptionsAreSeparate(t *testing.T) {
	now := time.Unix(100, 0)
	detector := New(Options{Threshold: 2, Clock: func() time.Time { return now }})
	for i := 0; i < 20; i++ {
		packet := testPacket(uint16(i))
		packet.Protocol = "udp"
		detector.Observe(packet, false)
	}
	for _, address := range []string{"invalid", "0.0.0.0", "224.0.0.1", "fe80::1%eth0"} {
		packet := testPacket(80)
		packet.Source = address
		detector.Observe(packet, false)
	}
	if detector.Stats().Sources != 0 || detector.Stats().ObservedTCPPackets != 0 {
		t.Fatal("invalid/UDP descriptions consumed detector capacity")
	}
	detector.Observe(testPacket(1), false)
	other := testPacket(2)
	other.Destination = "203.0.113.11"
	if alerts := detector.Observe(other, false); len(alerts) != 0 {
		t.Fatal("ports across destinations were combined")
	}
	other.DestinationPort = 3
	if alerts := detector.Observe(other, false); len(alerts) != 1 || alerts[0].Destination != other.Destination {
		t.Fatal("destination-pair warning missing")
	}
}

func TestDetectorConcurrentObserveAndThresholdClamp(t *testing.T) {
	now := time.Unix(100, 0)
	detector := New(Options{Threshold: 1000, Clock: func() time.Time { return now }})
	var wait sync.WaitGroup
	for i := 0; i < 128; i++ {
		wait.Add(1)
		go func(port int) {
			defer wait.Done()
			detector.Observe(testPacket(uint16(port)), false)
			detector.Recent()
			detector.Stats()
		}(i)
	}
	wait.Wait()
	alerts := detector.Recent()
	if len(alerts) != 1 || alerts[0].UniquePorts != MaxTrackedPorts {
		t.Fatalf("concurrent bounded warning=%+v", alerts)
	}
	if stats := detector.Stats(); stats.Sources != 1 || stats.ObservedTCPPackets != 128 {
		t.Fatalf("concurrent stats=%+v", stats)
	}
}
