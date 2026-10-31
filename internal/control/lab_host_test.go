package control

import (
	"github.com/TheDarkGuardian/WireWall/internal/model"
	"testing"
)

func TestLaboratoryHostProfilePreservesNarrowManagement(t *testing.T) {
	s := newTestService(t, "lab")
	s.policy.ManagementCIDRs = []string{"198.51.100.10/32"}
	s.policy.ManagementPort = 22
	s.policy.Host.TCPPorts = []uint16{22, 443}
	s.policy.Host.IPv6 = false
	base := model.Packet{Source: "198.51.100.10", Destination: "203.0.113.10", Protocol: "tcp", DestinationPort: 22, TCPFlags: "syn"}
	if !s.hostAllows(base) {
		t.Fatal("management initiation rejected")
	}
	base.Source = "198.51.100.99"
	if s.hostAllows(base) {
		t.Fatal("general service port list globally opened management port")
	}
	base.DestinationPort = 443
	if !s.hostAllows(base) {
		t.Fatal("public service SYN rejected")
	}
	for _, flags := range []string{"ack", "syn,ack", "syn,fin", "syn,rst", ""} {
		base.TCPFlags = flags
		if s.hostAllows(base) {
			t.Fatalf("new initiation accepted without safe SYN: %s", flags)
		}
	}
	base.TCPFlags = "syn"
	base.Destination = "2001:db8::10"
	if s.hostAllows(base) {
		t.Fatal("disabled IPv6 profile accepted")
	}
}
