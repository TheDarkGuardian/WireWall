package hostfirewall

import (
	"strings"
	"testing"

	"github.com/TheDarkGuardian/WireWall/internal/policy"
)

func TestRenderIsScopedAndProtectsManagement(t *testing.T) {
	p := policy.Default()
	p.Interface = "ens3"
	p.ManagementCIDRs = []string{"192.0.2.4/32"}
	p.Host.TCPPorts = []uint16{443, 22, 80}
	text, err := Render(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, needed := range []string{"iifname \"ens3\" jump protected_input", "ct state invalid", "ct state established,related", "ip saddr 192.0.2.4/32 tcp dport 22", "tcp dport { 80, 443 }", "tcp flags & (fin | syn | rst | ack) == syn", "counter drop comment \"default-deny\""} {
		if !strings.Contains(text, needed) {
			t.Fatalf("missing %q", needed)
		}
	}
	if strings.Contains(text, "flush ruleset") || strings.Contains(text, "tcp dport { 22,") {
		t.Fatal("renderer touches global state or opens management globally")
	}
	if strings.Contains(text, "hook output") || strings.Contains(text, "hook forward") {
		t.Fatal("host profile must not silently alter egress/forward policy")
	}
}

func TestIPv6DisabledBeforeEstablishedAcceptance(t *testing.T) {
	p := policy.Default()
	p.Host.IPv6 = false
	text, err := Render(p)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Index(text, "ipv6-disabled-profile") > strings.Index(text, "established-related") {
		t.Fatal("IPv6 disable must also affect existing flows")
	}
	if strings.Contains(text, "nd-neighbor-solicit") {
		t.Fatal("disabled IPv6 profile must not add IPv6 service exceptions")
	}
}

func TestRenderRejectsCommandInjection(t *testing.T) {
	p := policy.Default()
	p.Interface = "eth0\"; flush ruleset; #"
	if _, err := Render(p); err == nil {
		t.Fatal("unsafe interface accepted")
	}
}
