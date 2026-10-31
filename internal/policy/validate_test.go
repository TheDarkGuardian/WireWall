package policy

import (
	"strings"
	"testing"
	"time"

	"github.com/TheDarkGuardian/WireWall/internal/model"
)

func testRule() model.Rule {
	return model.Rule{ID: "web", Name: "Web traffic", Enabled: true, Priority: 100,
		Action: "drop", Protocol: "tcp", Source: "any", Destination: "any", SourcePort: "any", DestinationPort: "443"}
}

func testPolicy() model.Policy {
	p := Default()
	p.Mode = "enforce"
	p.Rules = []model.Rule{testRule()}
	return p
}

func TestValidateRejectsAmbiguousPolicies(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*model.Policy)
		want   string
	}{
		{"version", func(p *model.Policy) { p.Version = 0 }, "version"},
		{"mode", func(p *model.Policy) { p.Mode = "disabled" }, "mode"},
		{"interface injection", func(p *model.Policy) { p.Interface = "eth0;reboot" }, "interface"},
		{"xdp mode", func(p *model.Policy) { p.XDPMode = "offload" }, "xdpMode"},
		{"management missing", func(p *model.Policy) { p.ManagementCIDRs = nil }, "managementCidrs"},
		{"management wildcard", func(p *model.Policy) { p.ManagementCIDRs = []string{"0.0.0.0/0"} }, "catch-all"},
		{"duplicate id", func(p *model.Policy) { r := testRule(); r.Priority++; p.Rules = append(p.Rules, r) }, "id is duplicated"},
		{"duplicate priority", func(p *model.Policy) { r := testRule(); r.ID = "second"; p.Rules = append(p.Rules, r) }, "priority is duplicated"},
		{"invalid action", func(p *model.Policy) { p.Rules[0].Action = "accept" }, "action"},
		{"bad cidr", func(p *model.Policy) { p.Rules[0].Source = "10.0.0.0/99" }, "source"},
		{"empty cidr", func(p *model.Policy) { p.Rules[0].Source = "" }, "source"},
		{"mapped cidr", func(p *model.Policy) { p.Rules[0].Source = "::ffff:10.0.0.0/120" }, "source"},
		{"mixed families", func(p *model.Policy) { p.Rules[0].Source = "10.0.0.0/24"; p.Rules[0].Destination = "2001:db8::/32" }, "different IP families"},
		{"descending port", func(p *model.Policy) { p.Rules[0].DestinationPort = "443-80" }, "ascending"},
		{"port overflow", func(p *model.Policy) { p.Rules[0].DestinationPort = "65536" }, "between 1 and 65535"},
		{"ambiguous protocol", func(p *model.Policy) { p.Rules[0].Protocol = "any" }, "port matching requires"},
		{"zero rate", func(p *model.Policy) { p.Rules[0].Action = "limit" }, "limit pps and burst"},
		{"overflow rate", func(p *model.Policy) { p.Rules[0].Action = "limit"; p.Rules[0].PPS = MaxRate + 1; p.Rules[0].Burst = 2 }, "limit pps and burst"},
		{"partial source rate", func(p *model.Policy) {
			p.Rules[0].Action = "limit"
			p.Rules[0].PPS = 20
			p.Rules[0].Burst = 20
			p.Rules[0].SourcePPS = 1
		}, "both be set"},
		{"rate on drop", func(p *model.Policy) { p.Rules[0].PPS = 1 }, "only valid for limit"},
		{"size inversion", func(p *model.Policy) { p.Rules[0].MinPacketBytes = 100; p.Rules[0].MaxPacketBytes = 50 }, "exceeds"},
		{"flag protocol", func(p *model.Policy) { p.Rules[0].Protocol = "udp"; p.Rules[0].TCPFlags = "syn" }, "requires tcp"},
		{"duplicate host port", func(p *model.Policy) { p.Host.TCPPorts = []uint16{80, 80} }, "duplicate port"},
		{"zero host port", func(p *model.Policy) { p.Host.UDPPorts = []uint16{0} }, "port zero"},
		{"rule capacity", func(p *model.Policy) {
			for i := 0; i < MaxRules; i++ {
				p.Rules = append(p.Rules, testRule())
			}
		}, "at most"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			p := testPolicy()
			test.mutate(&p)
			err := Validate(p)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Validate() = %v; want containing %q", err, test.want)
			}
		})
	}
}

func TestValidateAcceptsValidProfiles(t *testing.T) {
	if err := Validate(Default()); err != nil {
		t.Fatalf("default: %v", err)
	}
	p := testPolicy()
	p.Rules[0].Source = "192.0.2.123/24"
	p.Rules[0].DestinationPort = "8000-8080"
	p.Rules[0].Action = "limit"
	p.Rules[0].PPS, p.Rules[0].Burst = MaxRate, MaxRate
	p.Rules[0].SourcePPS, p.Rules[0].SourceBurst = 100, 200
	if err := Validate(p); err != nil {
		t.Fatal(err)
	}
}

func TestBanValidation(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	b := model.Ban{ID: "ban-1", Address: "203.0.113.1", Reason: "Laboratory test", CreatedAt: now, ExpiresAt: now.Add(time.Minute)}
	if err := ValidateBan(b); err != nil {
		t.Fatal(err)
	}
	b.Address = "203.0.113.0/24"
	if ValidateBan(b) == nil {
		t.Fatal("CIDR ban accepted; only exact addresses supported")
	}
	b.Address = "203.0.113.1"
	b.ExpiresAt = b.CreatedAt
	if ValidateBan(b) == nil {
		t.Fatal("zero-duration ban accepted")
	}
	b.ExpiresAt = b.CreatedAt.Add(31 * 24 * time.Hour)
	if ValidateBan(b) == nil {
		t.Fatal("overlong ban accepted")
	}
}
