// Package policy validates and evaluates portable early-filter policies.
// It models XDP decisions for laboratory use, not TCP connection tracking.
package policy

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/TheDarkGuardian/WireWall/internal/model"
)

const (
	MaxRules              = 64
	MaxManagementCIDRs    = 16
	MaxRate               = uint64(1_000_000_000)
	DefaultSourceCapacity = 8192
	MaxBans               = 4096
)

var (
	identifierPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`)
	interfacePattern  = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,15}$`)
)

// Default starts in observe mode and exposes only the configured SSH and web
// service ports to the eventual host firewall. It does not attach any program.
func Default() model.Policy {
	return model.Policy{
		Version:         1,
		Mode:            "observe",
		Interface:       "eth0",
		XDPMode:         "generic",
		ManagementCIDRs: []string{"127.0.0.1/32", "::1/128"},
		ManagementPort:  22,
		Rules:           []model.Rule{},
		Host:            model.HostPolicy{TCPPorts: []uint16{22, 80, 443}, UDPPorts: []uint16{}, IPv6: true},
	}
}

// Validate rejects ambiguous or unsupported policy input before application.
func Validate(p model.Policy) error {
	var problems []error
	add := func(format string, args ...any) { problems = append(problems, fmt.Errorf(format, args...)) }
	if p.Version == 0 {
		add("version must be greater than zero")
	}
	if p.Mode != "observe" && p.Mode != "enforce" {
		add("mode must be observe or enforce")
	}
	if !interfacePattern.MatchString(p.Interface) || p.Interface == "." || p.Interface == ".." {
		add("interface must be a valid 1–15 character Linux interface name")
	}
	if p.XDPMode != "native" && p.XDPMode != "generic" {
		add("xdpMode must be native or generic")
	}
	if p.ManagementPort == 0 {
		add("managementPort must be between 1 and 65535")
	}
	if len(p.ManagementCIDRs) == 0 || len(p.ManagementCIDRs) > MaxManagementCIDRs {
		add("managementCidrs must contain between 1 and %d entries", MaxManagementCIDRs)
	}
	management := make(map[netip.Prefix]bool)
	for i, value := range p.ManagementCIDRs {
		prefix, err := parsePrefix(value)
		if err != nil {
			add("managementCidrs[%d]: %v", i, err)
			continue
		}
		if prefix.Bits() == 0 {
			add("managementCidrs[%d]: a catch-all management exemption is forbidden", i)
		}
		if management[prefix] {
			add("managementCidrs[%d]: duplicate network", i)
		}
		management[prefix] = true
	}
	validateHostPorts := func(name string, ports []uint16) {
		if len(ports) > 256 {
			add("host.%s supports at most 256 ports", name)
		}
		seen := make(map[uint16]bool)
		for _, port := range ports {
			if port == 0 {
				add("host.%s cannot contain port zero", name)
			}
			if seen[port] {
				add("host.%s contains duplicate port %d", name, port)
			}
			seen[port] = true
		}
	}
	validateHostPorts("tcpPorts", p.Host.TCPPorts)
	validateHostPorts("udpPorts", p.Host.UDPPorts)
	if len(p.Rules) > MaxRules {
		add("rules supports at most %d entries", MaxRules)
	}
	ids := make(map[string]bool)
	priorities := make(map[int]bool)
	for i, r := range p.Rules {
		label := fmt.Sprintf("rules[%d]", i)
		if !identifierPattern.MatchString(r.ID) {
			add("%s.id must be a 1–64 character identifier", label)
		}
		if ids[r.ID] {
			add("%s.id is duplicated", label)
		}
		ids[r.ID] = true
		if strings.TrimSpace(r.Name) == "" || len(r.Name) > 120 {
			add("%s.name must contain 1–120 bytes", label)
		}
		if r.Priority < 0 || r.Priority > 65535 {
			add("%s.priority must be between 0 and 65535", label)
		}
		if priorities[r.Priority] {
			add("%s.priority is duplicated", label)
		}
		priorities[r.Priority] = true
		if r.Action != "drop" && r.Action != "pass" && r.Action != "limit" {
			add("%s.action must be drop, pass or limit", label)
		}
		if !validProtocol(r.Protocol, true) {
			add("%s.protocol is unsupported", label)
		}
		var source, destination netip.Prefix
		if r.Source != "any" {
			var err error
			source, err = parsePrefix(r.Source)
			if err != nil {
				add("%s.source: %v", label, err)
			}
		}
		if r.Destination != "any" {
			var err error
			destination, err = parsePrefix(r.Destination)
			if err != nil {
				add("%s.destination: %v", label, err)
			}
		}
		if source.IsValid() && destination.IsValid() && source.Addr().BitLen() != destination.Addr().BitLen() {
			add("%s source and destination use different IP families", label)
		}
		if r.Protocol == "icmp" && (source.IsValid() && source.Addr().Is6() || destination.IsValid() && destination.Addr().Is6()) {
			add("%s icmp requires IPv4 networks", label)
		}
		if r.Protocol == "icmpv6" && (source.IsValid() && source.Addr().Is4() || destination.IsValid() && destination.Addr().Is4()) {
			add("%s icmpv6 requires IPv6 networks", label)
		}
		if _, err := parsePort(r.SourcePort); err != nil {
			add("%s.sourcePort: %v", label, err)
		}
		if _, err := parsePort(r.DestinationPort); err != nil {
			add("%s.destinationPort: %v", label, err)
		}
		if r.Protocol != "tcp" && r.Protocol != "udp" && (r.SourcePort != "any" || r.DestinationPort != "any") {
			add("%s port matching requires tcp or udp protocol", label)
		}
		if r.MinPacketBytes > 65535 || r.MaxPacketBytes > 65535 {
			add("%s packet size must not exceed 65535", label)
		}
		if r.MaxPacketBytes != 0 && r.MinPacketBytes > r.MaxPacketBytes {
			add("%s minPacketBytes exceeds maxPacketBytes", label)
		}
		if r.TCPFlags != "" && r.TCPFlags != "syn" {
			add("%s.tcpFlags supports only syn", label)
		}
		if r.TCPFlags != "" && r.Protocol != "tcp" {
			add("%s.tcpFlags requires tcp protocol", label)
		}
		if r.Action == "limit" {
			if r.PPS == 0 || r.Burst == 0 || r.PPS > MaxRate || r.Burst > MaxRate {
				add("%s limit pps and burst must be between 1 and %d", label, MaxRate)
			}
			if (r.SourcePPS == 0) != (r.SourceBurst == 0) {
				add("%s sourcePps and sourceBurst must both be set or both be zero", label)
			}
			if r.SourcePPS > MaxRate || r.SourceBurst > MaxRate {
				add("%s source limits must not exceed %d", label, MaxRate)
			}
			if (r.BPS == 0) != (r.ByteBurst == 0) {
				add("%s bps and byteBurst must both be set or both be zero", label)
			}
			if (r.SourceBPS == 0) != (r.SourceByteBurst == 0) {
				add("%s sourceBps and sourceByteBurst must both be set or both be zero", label)
			}
			if r.BPS > MaxRate || r.ByteBurst > MaxRate || r.SourceBPS > MaxRate || r.SourceByteBurst > MaxRate {
				add("%s byte rates and bursts must not exceed %d bytes", label, MaxRate)
			}
		} else if r.PPS != 0 || r.Burst != 0 || r.SourcePPS != 0 || r.SourceBurst != 0 || r.BPS != 0 || r.ByteBurst != 0 || r.SourceBPS != 0 || r.SourceByteBurst != 0 {
			add("%s rate fields are only valid for limit actions", label)
		}
	}
	return errors.Join(problems...)
}

// ValidateBan validates an individual temporary, exact-address ban. Expiration
// is checked while evaluating packets, so an expired ban cannot last forever.
func ValidateBan(b model.Ban) error {
	if !identifierPattern.MatchString(b.ID) {
		return errors.New("ban id must be a 1–64 character identifier")
	}
	address, err := netip.ParseAddr(b.Address)
	if err != nil || address.Zone() != "" {
		return errors.New("ban address must be a single IPv4 or IPv6 address without a zone")
	}
	if strings.TrimSpace(b.Reason) == "" || len(b.Reason) > 240 {
		return errors.New("ban reason must contain 1–240 bytes")
	}
	if b.CreatedAt.IsZero() || b.ExpiresAt.IsZero() || !b.ExpiresAt.After(b.CreatedAt) {
		return errors.New("ban expiration must be after its creation")
	}
	if b.ExpiresAt.Sub(b.CreatedAt) > 30*24*time.Hour {
		return errors.New("ban duration must not exceed 30 days")
	}
	return nil
}

type portRange struct {
	first, last uint16
	any         bool
}

func parsePort(value string) (portRange, error) {
	if value == "any" {
		return portRange{any: true}, nil
	}
	parts := strings.Split(value, "-")
	if len(parts) < 1 || len(parts) > 2 {
		return portRange{}, errors.New("expected any, a port or an ascending port range")
	}
	parse := func(s string) (uint16, error) {
		if s == "" {
			return 0, errors.New("empty port")
		}
		for _, ch := range s {
			if ch < '0' || ch > '9' {
				return 0, errors.New("port must contain decimal digits")
			}
		}
		v, err := strconv.ParseUint(s, 10, 16)
		if err != nil || v == 0 {
			return 0, errors.New("port must be between 1 and 65535")
		}
		return uint16(v), nil
	}
	first, err := parse(parts[0])
	if err != nil {
		return portRange{}, err
	}
	last := first
	if len(parts) == 2 {
		last, err = parse(parts[1])
		if err != nil {
			return portRange{}, err
		}
	}
	if last < first {
		return portRange{}, errors.New("port range must be ascending")
	}
	return portRange{first: first, last: last}, nil
}

func parsePrefix(value string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(value)
	if err != nil || prefix.Addr().Zone() != "" || prefix.Addr().Is4In6() {
		return netip.Prefix{}, errors.New("expected an IPv4 or IPv6 CIDR network")
	}
	return prefix.Masked(), nil
}

func validProtocol(value string, allowAny bool) bool {
	return value == "tcp" || value == "udp" || value == "icmp" || value == "icmpv6" || allowAny && value == "any"
}
