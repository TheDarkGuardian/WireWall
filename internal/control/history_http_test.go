package control

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestHistoryHTTPAuthenticationScopeAndExport(t *testing.T) {
	_, handler, service := newHTTPTest(t)
	base := time.Now().UTC().Add(-time.Minute)
	if err := service.store.SaveEvents([]Event{{ID: "synthetic", Timestamp: base, Source: "198.51.100.10", Action: "drop", RuleID: "=FORMULA()", Simulated: true}, {ID: "real", Timestamp: base, Source: "192.0.2.40", Action: "drop", Simulated: false}}); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/api/v1/events", "/api/v1/events/export?format=csv"} {
		if w := apiRequest(handler, "GET", path, nil, nil); w.Code != 401 {
			t.Fatalf("history exposed without login: %d", w.Code)
		}
	}
	w := apiRequest(handler, "GET", "/api/v1/events", nil, authHeaders())
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	var history EventHistory
	if err := json.Unmarshal(w.Body.Bytes(), &history); err != nil {
		t.Fatal(err)
	}
	if len(history.Items) != 1 || history.Items[0].ID != "synthetic" || !history.Simulated || history.Sampled {
		t.Fatal("history provenance mixed", history)
	}
	w = apiRequest(handler, "GET", "/api/v1/events/export?format=csv", nil, authHeaders())
	if w.Code != 200 || !strings.Contains(w.Body.String(), "'=FORMULA()") || strings.Contains(w.Body.String(), "192.0.2.40") || w.Header().Get("X-WireWall-Export-Truncated") != "false" {
		t.Fatalf("CSV export invalid: %d %s", w.Code, w.Body)
	}
	w = apiRequest(handler, "GET", "/api/v1/events?simulated=false", nil, authHeaders())
	if w.Code != 400 {
		t.Fatal("caller selected another provenance")
	}
}
