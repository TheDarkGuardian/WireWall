package control

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// NewMetricsHandler exposes aggregates only. It has no credential, policy
// mutation or arbitrary proxy surface. Mount only on the CLI's loopback listener.
func NewMetricsHandler(socketPath string) http.Handler {
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", socketPath)
	}, MaxIdleConnsPerHost: 2, IdleConnTimeout: 30 * time.Second}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		var snapshot Snapshot
		reachable := false
		request, err := http.NewRequestWithContext(r.Context(), "GET", "http://wirewall.internal/api/v1/snapshot", nil)
		if err == nil {
			response, e := client.Do(request)
			if e == nil {
				if response.StatusCode == http.StatusOK {
					reachable = json.NewDecoder(io.LimitReader(response.Body, 2<<20)).Decode(&snapshot) == nil
				}
				response.Body.Close()
			}
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		// An unreachable agent still yields wirewall_up=0 rather than stale data.
		_, _ = io.WriteString(w, RenderPrometheus(snapshot, reachable, time.Now()))
	})
	return mux
}

func RenderPrometheus(snapshot Snapshot, reachable bool, now time.Time) string {
	var out strings.Builder
	metric := func(name, kind, help string, value any) {
		fmt.Fprintf(&out, "# HELP %s %s\n# TYPE %s %s\n%s %v\n", name, help, name, kind, name, value)
	}
	flag := func(value bool) int {
		if value {
			return 1
		}
		return 0
	}
	fresh := reachable && !snapshot.System.ObservedAt.IsZero() && now.Sub(snapshot.System.ObservedAt) >= 0 && now.Sub(snapshot.System.ObservedAt) < 10*time.Second
	healthy := fresh && (snapshot.System.Simulated || snapshot.System.Attached && snapshot.Metrics.HostFirewall.Available)
	for _, health := range snapshot.System.Health {
		if health.Status == "error" {
			healthy = false
		}
	}
	metric("wirewall_agent_reachable", "gauge", "Whether the private agent API responded.", flag(reachable))
	metric("wirewall_up", "gauge", "Fresh healthy dataplane observation; synthetic provenance is separate.", flag(healthy))
	if !reachable {
		return out.String()
	}
	metric("wirewall_simulated", "gauge", "One for laboratory data; zero for real Linux observations.", flag(snapshot.System.Simulated))
	metric("wirewall_activation_pending", "gauge", "One while a network activation awaits operator confirmation.", flag(snapshot.System.ActivationPending))
	metric("wirewall_attached", "gauge", "Whether the expected XDP program is attached.", flag(snapshot.System.Attached))
	if !snapshot.System.ObservedAt.IsZero() {
		metric("wirewall_observation_timestamp_seconds", "gauge", "Time of the last successful dataplane read.", snapshot.System.ObservedAt.Unix())
	}
	if !fresh {
		return out.String()
	}
	quote := func(v string) string {
		return `"` + strings.NewReplacer(`\`, `\\`, "\n", `\n`, `"`, `\"`).Replace(v) + `"`
	}
	fmt.Fprintf(&out, "# HELP wirewall_info Deployment mode without IP, rule-ID or policy-version labels.\n# TYPE wirewall_info gauge\nwirewall_info{backend=%s,xdp_mode=%s,interface=%s,firewall_mode=%s} 1\n", quote(snapshot.System.Backend), quote(snapshot.System.XDPMode), quote(snapshot.System.Interface), quote(snapshot.System.Mode))
	metric("wirewall_policy_version", "gauge", "Persisted policy version.", snapshot.Policy.Version)
	metric("wirewall_start_timestamp_seconds", "gauge", "Agent start time; XDP counters reset on reload.", snapshot.System.StartedAt.Unix())
	m := snapshot.Metrics
	for _, value := range []struct {
		name, help string
		value      uint64
	}{
		{"received_packets", "Packets observed at XDP ingress.", m.ReceivedPackets}, {"passed_packets", "Packets passed by XDP, not final application acceptance.", m.PassedPackets}, {"dropped_packets", "Packets dropped by XDP.", m.DroppedPackets}, {"would_drop_packets", "Observe-mode drop recommendations.", m.WouldDropPackets}, {"received_bytes", "Ingress byte accounting; not physical wire overhead.", m.ReceivedBytes}, {"map_capacity_failures", "Source budget capacity fallbacks.", m.MapCapacityFailures}, {"event_drops", "Lost event records, not packet drops.", m.EventDrops}, {"service_stats_overflow_packets", "Unclassified service packets after bounded service table fills.", m.ServiceStatsOverflow},
	} {
		metric("wirewall_"+value.name+"_total", "counter", value.help, value.value)
	}
	metric("wirewall_active_bans", "gauge", "Currently active temporary source bans.", m.BlockedSources)
	metric("wirewall_conntrack_displayed", "gauge", "Displayed conntrack rows; capped at256, not host total.", m.ActiveConnections)
	metric("wirewall_rules_enabled", "gauge", "Enabled ordered rules.", enabledRules(snapshot))
	out.WriteString("# HELP wirewall_reason_packets_total Unsampled XDP reason counters; observe recommendations included.\n# TYPE wirewall_reason_packets_total counter\n")
	for _, v := range m.Reasons {
		fmt.Fprintf(&out, "wirewall_reason_packets_total{reason=%s} %d\n", quote(v.Reason), v.Count)
	}
	out.WriteString("# HELP wirewall_protocol_packets_total Unsampled ingress protocol classifications.\n# TYPE wirewall_protocol_packets_total counter\n")
	for _, v := range m.Protocols {
		fmt.Fprintf(&out, "wirewall_protocol_packets_total{protocol=%s} %d\n", quote(v.Protocol), v.Packets)
	}
	out.WriteString("# HELP wirewall_service_packets_total Current top20 tracked destination ports; maximum1024 distinct keys.\n# TYPE wirewall_service_packets_total counter\n")
	for _, v := range m.Services {
		fmt.Fprintf(&out, "wirewall_service_packets_total{protocol=%s,port=%s} %d\n", quote(v.Protocol), quote(strconv.Itoa(int(v.Port))), v.Packets)
	}
	metric("wirewall_nft_available", "gauge", "Whether owned nftables counters are available.", flag(m.HostFirewall.Available))
	if m.HostFirewall.Available {
		// Multiple management CIDRs share a comment: aggregate duplicate labels.
		type counter struct {
			reason, verdict string
			packets, bytes  uint64
		}
		groups := map[string]counter{}
		for _, v := range m.HostFirewall.Rules {
			key := v.Reason + "\x00" + v.Verdict
			g := groups[key]
			g.reason = v.Reason
			g.verdict = v.Verdict
			g.packets += v.Packets
			g.bytes += v.Bytes
			groups[key] = g
		}
		keys := make([]string, 0, len(groups))
		for key := range groups {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, field := range []string{"packets", "bytes"} {
			fmt.Fprintf(&out, "# HELP wirewall_nft_%s_total Owned host-input verdicts after XDP; resets on table replacement.\n# TYPE wirewall_nft_%s_total counter\n", field, field)
			for _, key := range keys {
				g := groups[key]
				value := g.packets
				if field == "bytes" {
					value = g.bytes
				}
				fmt.Fprintf(&out, "wirewall_nft_%s_total{reason=%s,verdict=%s} %d\n", field, quote(g.reason), quote(g.verdict), value)
			}
		}
	}
	r := snapshot.System.Resources
	metric("wirewall_host_resources_available", "gauge", "Whether Linux host observations are supported.", flag(r.Available))
	if r.CPUPercent != nil {
		metric("wirewall_host_cpu_ratio", "gauge", "Shared host busy fraction, includes hypervisor steal.", *r.CPUPercent/100)
	}
	for _, v := range []struct {
		name, help string
		value      *uint64
	}{{"memory_used_bytes", "Shared host used memory.", r.MemoryUsedBytes}, {"memory_total_bytes", "Shared host total memory.", r.MemoryTotalBytes}, {"conntrack_entries", "Host conntrack entries, not displayed rows.", r.ConntrackCount}, {"conntrack_capacity", "Host configured conntrack maximum.", r.ConntrackMax}} {
		if v.value != nil {
			metric("wirewall_host_"+v.name, "gauge", v.help, *v.value)
		}
	}
	return out.String()
}
func enabledRules(s Snapshot) int {
	n := 0
	for _, r := range s.Rules {
		if r.Enabled {
			n++
		}
	}
	return n
}
