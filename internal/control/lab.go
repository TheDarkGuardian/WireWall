package control

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/TheDarkGuardian/WireWall/internal/model"
)

// labTick evaluates synthetic descriptions only. It never opens a packet socket,
// sends packets, attaches BPF, or changes the host firewall.
func (s *Service) labTick(now time.Time) {
	s.mu.Lock()
	s.observedAt = now
	s.expireBansLocked(now)
	previous := s.metrics.ReceivedPackets
	previousBytes := s.metrics.ReceivedBytes
	previousDrop := s.metrics.DroppedPackets
	total := 180 + int(now.Unix()%31)
	if s.scenario != "normal" {
		total += 1200
	}
	sampled := []Event{}
	s.connections = []Connection{}
	for i := 0; i < total; i++ {
		p := model.Packet{Timestamp: now.Add(time.Duration(i) * time.Second / time.Duration(total)), Source: fmt.Sprintf("198.51.100.%d", 10+i%8), Destination: "203.0.113.10", SourcePort: uint16(40000 + i%512), DestinationPort: 443, Protocol: "tcp", Length: 1040, TCPFlags: "syn"}
		if i%7 == 0 {
			p.Protocol = "udp"
			p.DestinationPort = 53
			p.Length = 92
			p.TCPFlags = ""
		}
		if i >= 180 && s.scenario != "normal" {
			scenario := s.scenario
			if scenario == "mixed" {
				scenario = []string{"syn-burst", "udp-burst", "port-scan"}[i%3]
			}
			switch scenario {
			case "syn-burst":
				p.Source = "198.51.100.66"
				p.Protocol = "tcp"
				p.DestinationPort = 443
				p.Length = 60
				p.TCPFlags = "syn"
			case "udp-burst":
				p.Source = fmt.Sprintf("192.0.2.%d", 1+i%200)
				p.Protocol = "udp"
				p.DestinationPort = 27015
				p.Length = 1200
				p.TCPFlags = ""
			case "port-scan":
				p.Source = "198.51.100.77"
				p.Protocol = "tcp"
				p.DestinationPort = uint16(20 + i%1000)
				p.Length = 60
				p.TCPFlags = "syn"
			}
		}
		s.labClock = p.Timestamp
		s.detector.Observe(p, false)
		decision := s.evaluator.Evaluate(s.policy, p, s.bans)
		// Model host service policy separately. This is an approximation, never a
		// claim to exercise conntrack or TCP handshake validation on Windows.
		if decision.Action == "pass" && !s.hostAllows(p) {
			decision.Action = "drop"
			decision.Reason = "host_service_denied"
		}
		s.metrics.ReceivedPackets++
		s.metrics.ReceivedBytes += uint64(p.Length)
		s.protocols[p.Protocol]++
		key := fmt.Sprintf("%s/%d", p.Protocol, p.DestinationPort)
		service := s.services[key]
		service.Port = p.DestinationPort
		service.Protocol = p.Protocol
		service.Packets++
		if len(s.services) < 256 || s.services[key].Packets > 0 {
			s.services[key] = service
		}
		if decision.WouldDrop {
			s.metrics.WouldDropPackets++
		}
		if decision.Action == "drop" {
			s.metrics.DroppedPackets++
			if len(s.blocked) < 8192 {
				s.blocked[p.Source] = true
			}
			s.reasons[decision.Reason]++
		} else {
			s.metrics.PassedPackets++
		}
		if (decision.Action == "drop" || decision.WouldDrop) && len(sampled) < 12 || i == 0 {
			e := Event{ID: newID(), PolicyVersion: s.policy.Version, Timestamp: p.Timestamp, Source: p.Source, Destination: p.Destination, SourcePort: p.SourcePort, DestinationPort: p.DestinationPort, Protocol: p.Protocol, Length: p.Length, Action: decision.Action, Reason: decision.Reason, RuleID: decision.RuleID, WouldDrop: decision.WouldDrop, Simulated: true}
			sampled = append(sampled, e)
		}
		if decision.Action == "pass" && len(s.connections) < 24 {
			s.connections = append(s.connections, Connection{ID: fmt.Sprintf("lab-%s-%d-%d", p.Protocol, p.SourcePort, p.DestinationPort), Source: p.Source, Destination: p.Destination, SourcePort: p.SourcePort, DestinationPort: p.DestinationPort, Protocol: p.Protocol, State: "LAB_FLOW", Direction: "inbound", Packets: 1, Bytes: uint64(p.Length), ObservedAt: p.Timestamp, Simulated: true})
		}
	}
	s.metrics.PPS = float64(s.metrics.ReceivedPackets - previous)
	s.metrics.BPS = float64(s.metrics.ReceivedBytes-previousBytes) * 8
	s.metrics.DropPPS = float64(s.metrics.DroppedPackets - previousDrop)
	s.metrics.MapCapacityFailures = s.evaluator.Stats().CapacityFallbacks
	s.history = append(s.history, Point{Timestamp: now, PPS: s.metrics.PPS, BPS: s.metrics.BPS, DropPPS: s.metrics.DropPPS})
	if len(s.history) > 120 {
		s.history = s.history[len(s.history)-120:]
	}
	for _, e := range sampled {
		s.events = append([]Event{e}, s.events...)
	}
	if len(s.events) > 300 {
		s.events = s.events[:300]
	}
	if err := s.store.SaveEvents(sampled); err != nil {
		s.storageError = err.Error()
	}
	s.mu.Unlock()
}
func (s *Service) hostAllows(p model.Packet) bool {
	destination, err := netip.ParseAddr(p.Destination)
	if err != nil || destination.Is6() && !s.policy.Host.IPv6 {
		return false
	}
	if p.Protocol == "icmp" || p.Protocol == "icmpv6" {
		return true
	}
	if p.Protocol != "tcp" && p.Protocol != "udp" {
		return false
	}
	if p.Protocol == "tcp" {
		flags := map[string]bool{}
		for _, flag := range strings.FieldsFunc(strings.ToLower(p.TCPFlags), func(r rune) bool { return r == ',' || r == '|' || r == ' ' }) {
			flags[flag] = true
		}
		// Laboratory rows describe new initiations, never established TCP.
		if !flags["syn"] || flags["ack"] || flags["fin"] || flags["rst"] {
			return false
		}
		if p.DestinationPort == s.policy.ManagementPort {
			source, e := netip.ParseAddr(p.Source)
			if e != nil {
				return false
			}
			for _, network := range s.policy.ManagementCIDRs {
				prefix, e := netip.ParsePrefix(network)
				if e == nil && prefix.Contains(source) {
					return true
				}
			}
			return false
		}
	}
	ports := s.policy.Host.TCPPorts
	if p.Protocol == "udp" {
		ports = s.policy.Host.UDPPorts
	}
	for _, port := range ports {
		if port == p.DestinationPort {
			return true
		}
	}
	return false
}
