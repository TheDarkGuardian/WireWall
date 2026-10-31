package dataplane

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/TheDarkGuardian/WireWall/internal/model"
	"github.com/TheDarkGuardian/WireWall/internal/policy"
)

const (
	maxRules      = 64
	maxManagement = 16
	policySize    = 9064
)

type kernelPrefix struct {
	Family  uint8
	Bits    uint8
	Padding uint16
	Address [16]byte
}

type kernelRule struct {
	Index, Action, Protocol, SYNOnly                 uint32
	Source, Destination                              kernelPrefix
	SourceLo, SourceHi, DestinationLo, DestinationHi uint16
	MinBytes, MaxBytes                               uint32
	PPS, Burst, SourcePPS, SourceBurst               uint64
	BPS, ByteBurst, SourceBPS, SourceByteBurst       uint64
}

type kernelPolicy struct {
	Version                         uint64
	Enforce, RuleCount              uint32
	ManagementPort, ManagementCount uint32
	Management                      [maxManagement]kernelPrefix
	Rules                           [maxRules]kernelRule
	Reserved                        [2]uint64
}

type compiledPolicy struct {
	value kernelPolicy
	rules []model.Rule
}

func compilePolicy(p model.Policy) (compiledPolicy, error) {
	if err := policy.Validate(p); err != nil {
		return compiledPolicy{}, err
	}
	if p.Version == 0 {
		return compiledPolicy{}, fmt.Errorf("policy version must be positive")
	}
	if len(p.ManagementCIDRs) > maxManagement {
		return compiledPolicy{}, fmt.Errorf("at most %d management networks are supported", maxManagement)
	}
	result := compiledPolicy{value: kernelPolicy{
		Version: p.Version, ManagementPort: uint32(p.ManagementPort),
		ManagementCount: uint32(len(p.ManagementCIDRs)),
		// Reserved ABI fields: complex packets currently fail closed. A future
		// fallback path requires a complete downstream ACL mirror first.
	}}
	if p.Mode == "enforce" {
		result.value.Enforce = 1
	}
	for i, prefix := range p.ManagementCIDRs {
		value, err := compilePrefix(prefix)
		if err != nil {
			return compiledPolicy{}, err
		}
		result.value.Management[i] = value
	}
	for _, rule := range p.Rules {
		if rule.Enabled {
			result.rules = append(result.rules, rule)
		}
	}
	sort.Slice(result.rules, func(i, j int) bool { return result.rules[i].Priority < result.rules[j].Priority })
	for i, rule := range result.rules {
		source, err := compilePrefix(rule.Source)
		if err != nil {
			return compiledPolicy{}, err
		}
		destination, err := compilePrefix(rule.Destination)
		if err != nil {
			return compiledPolicy{}, err
		}
		sourceLo, sourceHi, err := compilePorts(rule.SourcePort)
		if err != nil {
			return compiledPolicy{}, err
		}
		destinationLo, destinationHi, err := compilePorts(rule.DestinationPort)
		if err != nil {
			return compiledPolicy{}, err
		}
		value := kernelRule{
			Index: uint32(i), Source: source, Destination: destination,
			SourceLo: sourceLo, SourceHi: sourceHi,
			DestinationLo: destinationLo, DestinationHi: destinationHi,
			MinBytes: rule.MinPacketBytes, MaxBytes: rule.MaxPacketBytes,
			PPS: rule.PPS, Burst: rule.Burst, SourcePPS: rule.SourcePPS, SourceBurst: rule.SourceBurst,
			BPS: rule.BPS, ByteBurst: rule.ByteBurst, SourceBPS: rule.SourceBPS, SourceByteBurst: rule.SourceByteBurst,
		}
		switch rule.Action {
		case "drop":
			value.Action = 1
		case "limit":
			value.Action = 2
		}
		switch rule.Protocol {
		case "tcp":
			value.Protocol = 6
		case "udp":
			value.Protocol = 17
		case "icmp":
			value.Protocol = 1
		case "icmpv6":
			value.Protocol = 58
		}
		if rule.TCPFlags == "syn" {
			value.SYNOnly = 1
		}
		result.value.Rules[i] = value
	}
	result.value.RuleCount = uint32(len(result.rules))
	return result, nil
}

func compilePrefix(value string) (kernelPrefix, error) {
	if value == "any" || value == "" {
		return kernelPrefix{}, nil
	}
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return kernelPrefix{}, fmt.Errorf("CIDR %q: %w", value, err)
	}
	prefix = prefix.Masked()
	result := kernelPrefix{Bits: uint8(prefix.Bits())}
	if prefix.Addr().Is4() {
		result.Family = 4
		address := prefix.Addr().As4()
		copy(result.Address[:4], address[:])
	} else {
		result.Family = 6
		result.Address = prefix.Addr().As16()
	}
	return result, nil
}

func compilePorts(value string) (uint16, uint16, error) {
	if value == "any" || value == "" {
		return 0, 65535, nil
	}
	parts := strings.Split(value, "-")
	if len(parts) < 1 || len(parts) > 2 {
		return 0, 0, fmt.Errorf("invalid port range %q", value)
	}
	first, err := strconv.ParseUint(parts[0], 10, 16)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid port %q", value)
	}
	last := first
	if len(parts) == 2 {
		last, err = strconv.ParseUint(parts[1], 10, 16)
		if err != nil || last < first {
			return 0, 0, fmt.Errorf("invalid port range %q", value)
		}
	}
	return uint16(first), uint16(last), nil
}

func (value kernelPolicy) marshal() ([]byte, error) {
	var buffer bytes.Buffer
	if err := binary.Write(&buffer, binary.LittleEndian, value); err != nil {
		return nil, err
	}
	if buffer.Len() != policySize {
		return nil, fmt.Errorf("policy ABI mismatch: %d bytes, need %d", buffer.Len(), policySize)
	}
	return buffer.Bytes(), nil
}
