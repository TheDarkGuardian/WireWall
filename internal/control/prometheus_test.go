package control

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/TheDarkGuardian/WireWall/internal/hostfirewall"
)

func TestPrometheusFreshnessProvenanceAndAggregation(t *testing.T) {
	now := time.Now()
	s := Snapshot{System: System{Backend: "xdp", Attached: true, Mode: "enforce", XDPMode: "native", ObservedAt: now, StartedAt: now.Add(-time.Hour)}}
	s.Metrics.ReceivedPackets = 123
	s.Metrics.HostFirewall = hostfirewall.Counters{Available: true, Rules: []hostfirewall.RuleCounter{{Reason: "management-new-syn", Verdict: "accept", Packets: 3, Bytes: 180}, {Reason: "management-new-syn", Verdict: "accept", Packets: 7, Bytes: 420}}}
	s.Events = []Event{{Source: "192.0.2.40", RuleID: "sensitive-rule"}}
	text := RenderPrometheus(s, true, now)
	for _, want := range []string{"wirewall_up 1\n", "wirewall_simulated 0\n", "wirewall_received_packets_total 123\n", `wirewall_nft_packets_total{reason="management-new-syn",verdict="accept"} 10`} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %s", want)
		}
	}
	if strings.Contains(text, "192.0.2.40") || strings.Contains(text, "sensitive-rule") {
		t.Fatal("event identifiers leaked into metrics")
	}
	if strings.Count(text, `wirewall_nft_packets_total{reason="management-new-syn"`) != 1 {
		t.Fatal("duplicate series for multiple management CIDRs")
	}
	s.Metrics.HostFirewall.Available = false
	if !strings.Contains(RenderPrometheus(s, true, now), "wirewall_up 0\n") {
		t.Fatal("missing host observation reported healthy")
	}
	s.Metrics.HostFirewall.Available = true
	stale := RenderPrometheus(s, true, now.Add(11*time.Second))
	if !strings.Contains(stale, "wirewall_up 0\n") || strings.Contains(stale, "wirewall_received_packets_total") {
		t.Fatal("stale values exposed as fresh")
	}
	s.System.Simulated = true
	s.System.Attached = false
	if !strings.Contains(RenderPrometheus(s, true, now), "wirewall_simulated 1\n") {
		t.Fatal("laboratory provenance missing")
	}
}
func TestMetricsUnavailableAgentAndReadOnlyRoutes(t *testing.T) {
	h := NewMetricsHandler(t.TempDir() + "/missing.sock")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "wirewall_up 0\n") {
		t.Fatalf("unavailable response=%d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "/api/v1/policy", strings.NewReader(`{}`)))
	if w.Code != 404 {
		t.Fatal("metrics listener exposed mutation route")
	}
}
