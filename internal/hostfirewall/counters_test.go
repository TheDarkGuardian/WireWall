package hostfirewall

import "testing"

func TestCountersOwnershipAndVerdicts(t *testing.T) {
	raw := []byte(`{"nftables":[{"table":{"family":"inet","name":"wirewall","comment":"managed-by-wirewall"}},{"rule":{"family":"inet","table":"wirewall","chain":"protected_input","comment":"established-related","expr":[{"counter":{"packets":12,"bytes":720}},{"accept":null}]}},{"rule":{"family":"inet","table":"wirewall","chain":"protected_input","comment":"default-deny","expr":[{"counter":{"packets":3,"bytes":180}},{"drop":null}]}}]}`)
	c, err := parseCounters(raw)
	if err != nil || !c.Available || c.AcceptedPackets != 12 || c.DroppedBytes != 180 || len(c.Rules) != 2 {
		t.Fatalf("counters=%+v error=%v", c, err)
	}
	if _, err := parseCounters([]byte(`{"nftables":[]}`)); err == nil {
		t.Fatal("foreign/missing table accepted")
	}
	legacy := []byte(`{"nftables":[{"table":{"family":"inet","name":"wirewall"}}]}`)
	if _, err := parseCounters(legacy); err == nil {
		t.Fatal("legacy JSON accepted without separate ownership verification")
	}
	if c, err := parseCounters(legacy, true); err != nil || !c.Available {
		t.Fatalf("verified nft1.0.2 JSON refused: %+v %v", c, err)
	}
}
