package control

import (
	"context"
	"fmt"
	"net/url"
	"testing"
	"time"
)

func TestHistoryBeyondLiveWindowKeysetIsolationAndSummary(t *testing.T) {
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	base := time.Now().UTC().Add(-time.Hour)
	events := []Event{}
	for i := 0; i < 510; i++ {
		events = append(events, Event{ID: fmt.Sprintf("%024x", i), Timestamp: base, Source: "198.51.100.10", Destination: "203.0.113.10", DestinationPort: 443, Protocol: "tcp", Action: "drop", Reason: "rule_drop", RuleID: "deny", Length: 60, PolicyVersion: 3, Simulated: i >= 500})
	}
	if err = store.SaveEvents(events); err != nil {
		t.Fatal(err)
	}
	q := EventFilter{Limit: 73, Source: "198.51.100.10", Action: "drop"}
	seen := map[string]bool{}
	for {
		result, err := store.QueryEvents(context.Background(), q)
		if err != nil {
			t.Fatal(err)
		}
		if result.Summary.MatchedEvents != 500 || result.Summary.SampleBytes != 30000 || result.Summary.UniqueSources != 1 || result.Simulated || !result.Sampled || result.RetainedEvents != 500 {
			t.Fatalf("summary=%+v", result)
		}
		for _, e := range result.Items {
			if seen[e.ID] || e.Simulated {
				t.Fatal("duplicate or synthetic event in real history")
			}
			seen[e.ID] = true
		}
		if !result.HasMore {
			break
		}
		if result.NextCursor == "" {
			t.Fatal("missing continuation")
		}
		q.Cursor = result.NextCursor
	}
	if len(seen) != 500 {
		t.Fatalf("keyset yielded%d", len(seen))
	}
	first, err := store.QueryEvents(context.Background(), EventFilter{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveEvents([]Event{{ID: "new-after-anchor", Timestamp: time.Now().Add(time.Second), Action: "drop"}}); err != nil {
		t.Fatal(err)
	}
	next, err := store.QueryEvents(context.Background(), EventFilter{Limit: 10, Cursor: first.NextCursor})
	if err != nil {
		t.Fatal(err)
	}
	if next.Summary.MatchedEvents != 500 {
		t.Fatal("new arrivals changed anchored report")
	}
	if _, err := store.QueryEvents(context.Background(), EventFilter{Limit: 10, Action: "pass", Cursor: first.NextCursor}); err == nil {
		t.Fatal("cursor reused with different filters")
	}
	none, err := store.QueryEvents(context.Background(), EventFilter{Limit: 10, Query: "%' OR1=1--"})
	if err != nil || none.Summary.MatchedEvents != 0 {
		t.Fatal("query was not treated as literal parameter", err)
	}
	legacy, err := store.QueryEvents(context.Background(), EventFilter{Limit: 10, Simulated: true})
	if err != nil || len(legacy.Items) != 10 || legacy.Sampled {
		t.Fatal("synthetic provenance wrong", err)
	}
}
func TestHistoryFilterBoundsAndCSV(t *testing.T) {
	for _, raw := range []string{"source=not-an-ip", "port=0", "limit=201", "protocol=garbage", "action=delete", "q=" + string(make([]byte, 121)), "source=192.0.2.1&source=192.0.2.2"} {
		v, err := url.ParseQuery(raw)
		if err != nil {
			continue
		}
		if _, err = parseEventFilter(v, false, 200); err == nil {
			t.Fatalf("invalid query accepted:%q", raw)
		}
	}
	for _, value := range []string{"=SUM(A1)", " +1", "-cmd", "@command", "\t=1"} {
		if safeCSVCell(value) != "'"+value {
			t.Fatal("CSV formula not neutralized")
		}
	}
	if safeCSVCell("192.0.2.1") != "192.0.2.1" {
		t.Fatal("ordinary value changed")
	}
	now := time.Now().UTC()
	if _, _, _, _, _, _, err := historyBounds(EventFilter{From: now.Add(-31 * 24 * time.Hour), To: now}, now); err == nil {
		t.Fatal("unbounded range accepted")
	}
	if _, _, _, _, _, _, err := historyBounds(EventFilter{From: now.Add(-60 * 24 * time.Hour), To: now.Add(-59 * 24 * time.Hour)}, now); err == nil {
		t.Fatal("expired range accepted")
	}
}
