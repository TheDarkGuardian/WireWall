package control

import (
	"testing"
	"time"
)

func TestSampleHistoryPersistenceIsolationAndOrdering(t *testing.T) {
	dir := t.TempDir()
	store, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now().UTC().Truncate(time.Second).Add(-time.Hour)
	samples := []Event{{ID: "lab-low", Timestamp: base.Add(100 * time.Millisecond), Simulated: true}, {ID: "lab-high", Timestamp: base.Add(110 * time.Millisecond), Simulated: true}, {ID: "real", Timestamp: base.Add(120 * time.Millisecond), Simulated: false}, {ID: "expired", Timestamp: base.Add(-31 * 24 * time.Hour), Simulated: true}}
	if err = store.SaveEvents(samples); err != nil {
		t.Fatal(err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	lab, err := store.LoadEvents(300, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(lab) != 2 || lab[0].ID != "lab-high" || lab[1].ID != "lab-low" {
		t.Fatalf("history order or isolation: %+v", lab)
	}
	real, err := store.LoadEvents(300, false)
	if err != nil || len(real) != 1 || real[0].ID != "real" {
		t.Fatalf("real history %+v %v", real, err)
	}
	if err = store.ClearLabEvents(); err != nil {
		t.Fatal(err)
	}
	lab, err = store.LoadEvents(300, true)
	if err != nil || len(lab) != 0 {
		t.Fatalf("lab reset: %+v %v", lab, err)
	}
	real, err = store.LoadEvents(300, false)
	if err != nil || len(real) != 1 {
		t.Fatal("lab reset removed real history")
	}
}
