package control

import (
	"context"
	"os"
	"testing"
	"time"
)

// Opt-in SQLite fixture, not packet/network evidence. Exercises the actual
// 100000-record boundary and aggregate query cost without host network changes.
func TestHistoryRetentionCapacityFixture(t *testing.T) {
	if os.Getenv("WIREWALL_HISTORY_STRESS") != "1" {
		t.Skip("opt-in100k synthetic SQLite fixture")
	}
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	base := time.Now().UTC().Add(-time.Hour).Format(storedTimeFormat)
	_, err = store.db.Exec(`WITH RECURSIVE n(x) AS (SELECT 0 UNION ALL SELECT x+1 FROM n WHERE x<100004) INSERT INTO events(id,timestamp,payload) SELECT printf('%024x',x),?,json_object('id',printf('%024x',x),'timestamp',?,'simulated',json('false'),'source','192.0.2.1','action','drop','length',60,'reason','rule_drop','protocol','tcp') FROM n`, base, base)
	if err != nil {
		t.Fatal(err)
	}
	stamp, _ := time.Parse(storedTimeFormat, base)
	if err := store.SaveEvents([]Event{{ID: "fffffffffffffffffffffff0", Timestamp: stamp, Source: "192.0.2.1", Action: "drop", Length: 60, Reason: "rule_drop", Protocol: "tcp"}}); err != nil {
		t.Fatal(err)
	}
	var count int
	var oldest string
	if err := store.db.QueryRow("SELECT count(*),min(id) FROM events").Scan(&count, &oldest); err != nil {
		t.Fatal(err)
	}
	if count != eventRecordLimit || oldest != "000000000000000000000006" {
		t.Fatalf("cap=%d oldest=%s", count, oldest)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	start := time.Now()
	report, err := store.QueryEvents(ctx, EventFilter{Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	if report.Summary.MatchedEvents != 100000 || !report.HasMore || len(report.Items) != 50 {
		t.Fatal("full-size report wrong")
	}
	t.Logf("Synthetic SQLite fixture: retained=%d; full aggregate query=%s", count, time.Since(start))
}
