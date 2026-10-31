package hostfirewall

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

type RuleCounter struct {
	Reason  string `json:"reason"`
	Verdict string `json:"verdict"`
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}
type Counters struct {
	Available       bool          `json:"available"`
	ObservedAt      time.Time     `json:"observedAt"`
	AcceptedPackets uint64        `json:"acceptedPackets"`
	DroppedPackets  uint64        `json:"droppedPackets"`
	AcceptedBytes   uint64        `json:"acceptedBytes"`
	DroppedBytes    uint64        `json:"droppedBytes"`
	Rules           []RuleCounter `json:"rules"`
	Error           string        `json:"error,omitempty"`
}

// ReadCounters observes only the owned table. Counters reset on its replacement;
// these are host-input verdicts after XDP, never total end-to-end acceptance.
func ReadCounters(ctx context.Context) (Counters, error) {
	// nft1.0.2 omits the table comment in JSON although text output preserves
	// it. Verify the same dedicated table through the existing ownership gate.
	snapshot, err := Capture(ctx)
	if err != nil {
		return Counters{}, err
	}
	if !snapshot.Exists {
		return Counters{}, errors.New("nft counters: owned table missing")
	}
	raw, err := nft(ctx, "", "-j", "list", "table", "inet", TableName)
	if err != nil {
		return Counters{}, err
	}
	return parseCounters(raw, true)
}
func parseCounters(raw []byte, verifiedTextOwnership ...bool) (Counters, error) {
	var document struct {
		NFTables []struct {
			Table *struct{ Family, Name, Comment string } `json:"table"`
			Rule  *struct {
				Family, Table, Chain, Comment string
				Expr                          []map[string]json.RawMessage
			} `json:"rule"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		return Counters{}, err
	}
	result := Counters{ObservedAt: time.Now().UTC(), Rules: []RuleCounter{}}
	owned := false
	for _, entry := range document.NFTables {
		if t := entry.Table; t != nil && t.Family == "inet" && t.Name == TableName && (t.Comment == ownershipMarker || t.Comment == "" && len(verifiedTextOwnership) > 0 && verifiedTextOwnership[0]) {
			owned = true
		}
		r := entry.Rule
		if r == nil || r.Family != "inet" || r.Table != TableName || r.Chain != "protected_input" {
			continue
		}
		c := RuleCounter{Reason: r.Comment}
		counted := false
		for _, expression := range r.Expr {
			if value, ok := expression["counter"]; ok {
				var counter struct{ Packets, Bytes uint64 }
				if err := json.Unmarshal(value, &counter); err != nil {
					return Counters{}, err
				}
				c.Packets, c.Bytes, counted = counter.Packets, counter.Bytes, true
			}
			if _, ok := expression["accept"]; ok {
				c.Verdict = "accept"
			}
			if _, ok := expression["drop"]; ok {
				c.Verdict = "drop"
			}
		}
		if !counted || c.Verdict == "" {
			continue
		}
		result.Rules = append(result.Rules, c)
		if c.Verdict == "accept" {
			result.AcceptedPackets += c.Packets
			result.AcceptedBytes += c.Bytes
		} else {
			result.DroppedPackets += c.Packets
			result.DroppedBytes += c.Bytes
		}
	}
	if !owned {
		return Counters{}, errors.New("nft counters: owned table marker missing")
	}
	result.Available = true
	return result, nil
}
