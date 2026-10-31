package policy

import (
	"crypto/sha256"
	"encoding/json"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/TheDarkGuardian/WireWall/internal/model"
)

const tokenCredit = uint64(1_000_000_000)

type Options struct {
	Clock          func() time.Time
	SourceCapacity int
}

type EvaluatorStats struct {
	SourceEntries     int    `json:"sourceEntries"`
	SourceCapacity    int    `json:"sourceCapacity"`
	CapacityFallbacks uint64 `json:"capacityFallbacks"`
}

// Evaluator is the deterministic userspace reference implementation for the
// early-filter contract. It never attaches XDP or accepts a host connection.
// Its shared buckets are protected by one mutex, including all CPUs/goroutines.
type Evaluator struct {
	mu         sync.Mutex
	clock      func() time.Time
	capacity   int
	signature  [32]byte
	compiled   []compiledRule
	management []netip.Prefix
	aggregate  map[string]*bucket
	sources    map[string]*bucket
	fallbacks  uint64
	lastPrune  time.Time
}

type compiledRule struct {
	rule        model.Rule
	source      netip.Prefix
	destination netip.Prefix
	sourcePort  portRange
	destPort    portRange
}

type bucket struct {
	credits     uint64
	byteCredits uint64
	updated     time.Time
	lastSeen    time.Time
	rate        uint64
	burst       uint64
	byteRate    uint64
	byteBurst   uint64
}

func NewEvaluator() *Evaluator { return NewEvaluatorWithOptions(Options{}) }

func NewEvaluatorWithClock(clock func() time.Time) *Evaluator {
	return NewEvaluatorWithOptions(Options{Clock: clock})
}

func NewEvaluatorWithOptions(options Options) *Evaluator {
	if options.Clock == nil {
		options.Clock = time.Now
	}
	if options.SourceCapacity <= 0 {
		options.SourceCapacity = DefaultSourceCapacity
	}
	if options.SourceCapacity > DefaultSourceCapacity {
		options.SourceCapacity = DefaultSourceCapacity
	}
	return &Evaluator{
		clock:     options.Clock,
		capacity:  options.SourceCapacity,
		aggregate: make(map[string]*bucket),
		sources:   make(map[string]*bucket),
	}
}

func (e *Evaluator) Stats() EvaluatorStats {
	e.mu.Lock()
	defer e.mu.Unlock()
	return EvaluatorStats{SourceEntries: len(e.sources), SourceCapacity: e.capacity, CapacityFallbacks: e.fallbacks}
}

// Reset clears laboratory limiter state. It does not affect a real data plane.
func (e *Evaluator) Reset() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.aggregate = make(map[string]*bucket)
	e.sources = make(map[string]*bucket)
	e.fallbacks = 0
	e.lastPrune = time.Time{}
}

// Evaluate applies the early-filter policy. Packet.Timestamp is descriptive;
// the injected trusted clock controls expiration and token replenishment.
// Aggregate buckets police offered matching traffic, including packets later
// rejected by a source bucket, before expensive per-source accounting.
func (e *Evaluator) Evaluate(p model.Policy, packet model.Packet, bans []model.Ban) model.Decision {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.prepare(p) {
		return model.Decision{Action: "drop", Reason: "invalid_policy"}
	}
	finish := func(action, reason, ruleID string) model.Decision {
		decision := model.Decision{Action: action, Reason: reason, RuleID: ruleID, WouldDrop: p.Mode == "observe" && action == "drop"}
		if p.Mode == "observe" && action == "drop" {
			decision.Action = "pass"
		}
		return decision
	}
	source, sourceErr := netip.ParseAddr(packet.Source)
	destination, destinationErr := netip.ParseAddr(packet.Destination)
	if sourceErr != nil || destinationErr != nil || source.Zone() != "" || destination.Zone() != "" ||
		source.Is4In6() || destination.Is4In6() || source.BitLen() != destination.BitLen() ||
		!validProtocol(packet.Protocol, false) || packet.Length == 0 || packet.Length > 65535 ||
		packet.Protocol == "icmp" && !source.Is4() || packet.Protocol == "icmpv6" && !source.Is6() ||
		packet.Protocol != "tcp" && packet.TCPFlags != "" {
		return finish("drop", "invalid_packet", "")
	}
	minimum := uint32(20)
	if source.Is6() {
		minimum = 40
	}
	if packet.Protocol == "tcp" {
		minimum += 20
	} else {
		minimum += 8
	}
	if packet.Length < minimum || !validTCPFlags(packet.TCPFlags) {
		return finish("drop", "invalid_packet", "")
	}
	if packet.Protocol == "tcp" && packet.DestinationPort == p.ManagementPort {
		for _, prefix := range e.management {
			if prefix.Contains(source) {
				return finish("pass", "management_exemption", "")
			}
		}
	}
	now := e.clock()
	if len(bans) > MaxBans {
		return finish("drop", "invalid_bans", "")
	}
	for _, ban := range bans {
		if ValidateBan(ban) != nil || now.Before(ban.CreatedAt) || !now.Before(ban.ExpiresAt) {
			continue
		}
		address, _ := netip.ParseAddr(ban.Address)
		if address.Unmap() == source {
			return finish("drop", "temporary_ban", "")
		}
	}
	for _, compiled := range e.compiled {
		rule := compiled.rule
		if !matches(compiled, packet, source, destination) {
			continue
		}
		switch rule.Action {
		case "drop":
			return finish("drop", "rule_drop", rule.ID)
		case "pass":
			return finish("pass", "rule_pass", rule.ID)
		case "limit":
			aggregate := e.aggregate[rule.ID]
			if aggregate == nil {
				aggregate = newBucket(now, rule.PPS, rule.Burst, rule.BPS, rule.ByteBurst)
				e.aggregate[rule.ID] = aggregate
			}
			if failure := aggregate.take(now, packet.Length); failure != "" {
				reason := "rate_limit"
				if failure == "bytes" {
					reason = "byte_limit"
				}
				return finish("drop", reason, rule.ID)
			}
			if rule.SourcePPS == 0 && rule.SourceBPS == 0 {
				return finish("pass", "rate_limit_pass", rule.ID)
			}
			e.pruneSources(now)
			key := rule.ID + "\x00" + source.String()
			sourceBucket := e.sources[key]
			if sourceBucket == nil {
				if len(e.sources) >= e.capacity {
					e.fallbacks++
					return finish("pass", "source_capacity_fallback", rule.ID)
				}
				sourceBucket = newBucket(now, rule.SourcePPS, rule.SourceBurst, rule.SourceBPS, rule.SourceByteBurst)
				e.sources[key] = sourceBucket
			}
			if failure := sourceBucket.take(now, packet.Length); failure != "" {
				reason := "source_rate_limit"
				if failure == "bytes" {
					reason = "source_byte_limit"
				}
				return finish("drop", reason, rule.ID)
			}
			return finish("pass", "rate_limit_pass", rule.ID)
		}
	}
	return finish("pass", "default_pass", "")
}

func (e *Evaluator) prepare(p model.Policy) bool {
	encoded, err := json.Marshal(p)
	if err != nil {
		return false
	}
	signature := sha256.Sum256(encoded)
	if signature == e.signature {
		return true
	}
	if Validate(p) != nil {
		return false
	}
	rules := make([]compiledRule, 0, len(p.Rules))
	for _, r := range p.Rules {
		if !r.Enabled {
			continue
		}
		source, _ := parsePrefix(r.Source)
		destination, _ := parsePrefix(r.Destination)
		sourcePort, _ := parsePort(r.SourcePort)
		destPort, _ := parsePort(r.DestinationPort)
		rules = append(rules, compiledRule{rule: r, source: source, destination: destination, sourcePort: sourcePort, destPort: destPort})
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].rule.Priority < rules[j].rule.Priority })
	management := make([]netip.Prefix, 0, len(p.ManagementCIDRs))
	for _, value := range p.ManagementCIDRs {
		prefix, _ := parsePrefix(value)
		management = append(management, prefix)
	}
	e.compiled, e.management, e.signature = rules, management, signature
	e.aggregate = make(map[string]*bucket)
	e.sources = make(map[string]*bucket)
	e.lastPrune = time.Time{}
	return true
}

func matches(c compiledRule, packet model.Packet, source, destination netip.Addr) bool {
	r := c.rule
	return (r.Protocol == "any" || r.Protocol == packet.Protocol) &&
		(!c.source.IsValid() || c.source.Contains(source)) &&
		(!c.destination.IsValid() || c.destination.Contains(destination)) &&
		(c.sourcePort.any || packet.SourcePort >= c.sourcePort.first && packet.SourcePort <= c.sourcePort.last) &&
		(c.destPort.any || packet.DestinationPort >= c.destPort.first && packet.DestinationPort <= c.destPort.last) &&
		(r.MinPacketBytes == 0 || packet.Length >= r.MinPacketBytes) &&
		(r.MaxPacketBytes == 0 || packet.Length <= r.MaxPacketBytes) &&
		(r.TCPFlags == "" || hasTCPFlag(packet.TCPFlags, "syn") && !hasTCPFlag(packet.TCPFlags, "ack"))
}

func newBucket(now time.Time, rate, burst, byteRate, byteBurst uint64) *bucket {
	return &bucket{credits: burst * tokenCredit, byteCredits: byteBurst * tokenCredit, updated: now, lastSeen: now, rate: rate, burst: burst, byteRate: byteRate, byteBurst: byteBurst}
}

func refillCredits(credits, rate, burst, elapsed uint64) uint64 {
	if rate == 0 {
		return 0
	}
	maximum := burst * tokenCredit
	if credits > maximum {
		credits = maximum
	}
	missing := maximum - credits
	needed := missing / rate
	if missing%rate != 0 {
		needed++
	}
	if elapsed >= needed {
		return maximum
	}
	return credits + elapsed*rate
}

// Packet and byte budgets are charged together or neither is charged. The
// aggregate bucket still counts offered traffic subsequently rejected by the
// independent per-source bucket, just as the packet-only limiter does.
func (b *bucket) take(now time.Time, length uint32) string {
	if now.After(b.updated) {
		elapsed := uint64(now.Sub(b.updated).Nanoseconds())
		b.credits = refillCredits(b.credits, b.rate, b.burst, elapsed)
		b.byteCredits = refillCredits(b.byteCredits, b.byteRate, b.byteBurst, elapsed)
		b.updated = now
	}
	if now.After(b.lastSeen) {
		b.lastSeen = now
	}
	if b.rate > 0 && b.credits < tokenCredit {
		return "packets"
	}
	byteCost := uint64(length) * tokenCredit
	if b.byteRate > 0 && b.byteCredits < byteCost {
		return "bytes"
	}
	if b.rate > 0 {
		b.credits -= tokenCredit
	}
	if b.byteRate > 0 {
		b.byteCredits -= byteCost
	}
	return ""
}

func (e *Evaluator) pruneSources(now time.Time) {
	if !e.lastPrune.IsZero() && now.Sub(e.lastPrune) < time.Minute {
		return
	}
	e.lastPrune = now
	for key, b := range e.sources {
		idle := now.Sub(b.lastSeen)
		// Never evict an active/depleted source merely to reset its burst.
		var refill time.Duration
		for _, budget := range [][2]uint64{{b.rate, b.burst}, {b.byteRate, b.byteBurst}} {
			if budget[0] == 0 {
				continue
			}
			duration := time.Duration((budget[1]*tokenCredit + budget[0] - 1) / budget[0])
			if duration > refill {
				refill = duration
			}
		}
		if idle >= 5*time.Minute && idle >= refill {
			delete(e.sources, key)
		}
	}
}

func tcpFlagParts(value string) []string {
	return strings.FieldsFunc(strings.ToLower(value), func(r rune) bool {
		return r == ',' || r == ' ' || r == '+' || r == '|' || r == '-'
	})
}

func hasTCPFlag(value, flag string) bool {
	for _, part := range tcpFlagParts(value) {
		if part == flag {
			return true
		}
	}
	return false
}

func validTCPFlags(value string) bool {
	if value == "" {
		return true
	}
	parts := tcpFlagParts(value)
	if len(parts) == 0 {
		return false
	}
	seen := make(map[string]bool)
	for _, part := range parts {
		switch part {
		case "syn", "ack", "fin", "rst", "psh", "urg", "ece", "cwr":
		default:
			return false
		}
		if seen[part] {
			return false
		}
		seen[part] = true
	}
	if seen["syn"] && (seen["fin"] || seen["rst"]) || seen["fin"] && seen["rst"] {
		return false
	}
	return true
}
