package control

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/TheDarkGuardian/WireWall/internal/model"
)

func TestLabScanWarningAndResetDoNotChangeConfiguration(t *testing.T) {
	s := newTestService(t, "lab")
	p := s.Policy()
	p.Mode = "enforce"
	p.Rules = []model.Rule{{ID: "deny-tcp", Name: "Integration TCP deny", Enabled: true, Priority: 10, Action: "drop", Protocol: "tcp", Source: "any", Destination: "any", SourcePort: "any", DestinationPort: "any"}}
	p, err := s.ApplyPolicy(p, p.Version)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.SetScenario("port-scan"); err != nil {
		t.Fatal(err)
	}
	s.labTick(time.Now().UTC())
	snapshot := s.Snapshot()
	if len(snapshot.Alerts) != 1 {
		t.Fatalf("expected one bounded scan warning, got %+v", snapshot.Alerts)
	}
	alert := snapshot.Alerts[0]
	if alert.Source != "198.51.100.77" || alert.Type != "port_scan" || alert.Sampled || alert.UniquePorts < 20 {
		t.Fatalf("full synthetic scan evidence was mislabelled: %+v", alert)
	}
	if len(snapshot.Bans) != 0 {
		t.Fatal("observational scan warning automatically added a ban")
	}
	if snapshot.Metrics.DroppedPackets == 0 || snapshot.Metrics.WouldDropPackets != 0 {
		t.Fatalf("enforced drops were reported as hypothetical observation: %+v", snapshot.Metrics)
	}
	for _, event := range snapshot.Events {
		if event.Action == "drop" && event.WouldDrop {
			t.Fatalf("enforced drop incorrectly carries observation flag: %+v", event)
		}
	}
	ban, err := s.AddBan("192.0.2.55", "Manual operator decision", 3600)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Reset(); err != nil {
		t.Fatal(err)
	}
	reset := s.Snapshot()
	if len(reset.Alerts) != 0 || len(reset.Events) != 0 || reset.Metrics.ReceivedPackets != 0 {
		t.Fatal("reset retained laboratory alert/event/counter state")
	}
	if !reflect.DeepEqual(reset.Policy, p) || len(reset.Bans) != 1 || reset.Bans[0].ID != ban.ID {
		t.Fatal("reset deleted persistent policy or operator ban")
	}
}

func TestLiveSampleWarningsAndHistoryRemainExplicitAcrossBackendReload(t *testing.T) {
	s := newTestService(t, "xdp")
	now := time.Now().UTC()
	events := make([]Event, 20)
	for index := range events {
		events[index] = Event{ID: fmt.Sprintf("live-scan-%d", index), Timestamp: now.Add(time.Duration(index) * time.Millisecond), Source: "198.51.100.99", Destination: "203.0.113.10", SourcePort: 44000, DestinationPort: uint16(1000 + index), Protocol: "tcp", Length: 60, Action: "drop", Reason: "rule_drop", Simulated: false}
	}
	r := &recordingRuntime{live: LiveSnapshot{Attached: true, XDPMode: "generic", Metrics: Metrics{ReceivedPackets: 1000, DroppedPackets: 1000}, Events: events}}
	s.SetRuntime(r)
	s.liveTick(now)
	snapshot := s.Snapshot()
	if snapshot.System.Simulated || !snapshot.System.Attached || len(snapshot.Alerts) != 1 || !snapshot.Alerts[0].Sampled {
		t.Fatalf("live sampled evidence lost its provenance: system=%+v alerts=%+v", snapshot.System, snapshot.Alerts)
	}
	if len(snapshot.Bans) != 0 {
		t.Fatal("live warning triggered automatic enforcement")
	}
	stored, err := s.store.LoadEvents(300, false)
	if err != nil || len(stored) != len(events) {
		t.Fatalf("real event history was not persisted: count=%d err=%v", len(stored), err)
	}
	for _, event := range stored {
		if event.Simulated {
			t.Fatal("stored live sample relabelled as laboratory data")
		}
	}
	// Restarting the service reads history without pretending the detached
	// process has current XDP traffic or a newly observed connection.
	reloaded, err := NewService(s.store, nil, "xdp")
	if err != nil {
		t.Fatal(err)
	}
	restart := reloaded.Snapshot()
	if len(restart.Events) != len(events) || restart.System.Attached || restart.Metrics.ReceivedPackets != 0 || len(restart.Alerts) != 0 {
		t.Fatalf("historical samples became current runtime evidence: %+v", restart)
	}
	laboratory, err := NewService(s.store, nil, "lab")
	if err != nil {
		t.Fatal(err)
	}
	if len(laboratory.Snapshot().Events) != 0 {
		t.Fatal("laboratory loaded real samples as synthetic history")
	}
	if err = laboratory.Reset(); err != nil {
		t.Fatal(err)
	}
	stored, err = s.store.LoadEvents(300, false)
	if err != nil || len(stored) != len(events) {
		t.Fatal("laboratory reset removed real event history")
	}
}

type recoveryFailureRuntime struct {
	applyCalls int
	recovery   error
}

func (r *recoveryFailureRuntime) Apply(model.Policy, []model.Ban) error {
	r.applyCalls++
	if r.applyCalls == 2 {
		return r.recovery
	}
	return nil
}
func (*recoveryFailureRuntime) Snapshot() (LiveSnapshot, error) { return LiveSnapshot{}, nil }
func (*recoveryFailureRuntime) Close() error                    { return nil }

func TestPersistenceAndRuntimeRecoveryFailuresAreBothVisible(t *testing.T) {
	s := newTestService(t, "xdp")
	r := &recoveryFailureRuntime{recovery: fmt.Errorf("synthetic kernel recovery failure")}
	s.SetRuntime(r)
	original := s.Policy()
	next := s.Policy()
	next.Mode = "enforce"
	if err := s.store.Close(); err != nil {
		t.Fatal(err)
	}
	_, err := s.ApplyPolicy(next, original.Version)
	if err == nil || !strings.Contains(err.Error(), "database is closed") || !strings.Contains(err.Error(), "synthetic kernel recovery failure") {
		t.Fatalf("one recovery failure concealed the other: %v", err)
	}
	if !reflect.DeepEqual(s.Policy(), original) {
		t.Fatal("failed persistence changed the desired policy")
	}
	snapshot := s.Snapshot()
	if snapshot.System.Attached {
		t.Fatal("uncertain kernel recovery was reported as attached")
	}
	visible := false
	for _, health := range snapshot.System.Health {
		if health.Status == "error" && strings.Contains(health.Detail, "synthetic kernel recovery failure") {
			visible = true
		}
	}
	if !visible {
		t.Fatal("runtime recovery failure missing from operator health")
	}
}

type activationAuditRuntime struct {
	recordingRuntime
	pending bool
}

func (r *activationAuditRuntime) Confirm() error { r.pending = false; return nil }
func (r *activationAuditRuntime) ActivationStatus() (bool, time.Time) {
	return r.pending, time.Now().Add(time.Minute)
}

func TestConfirmedActivationWithAuditFailureReportsActualOutcome(t *testing.T) {
	s := newTestService(t, "xdp")
	r := &activationAuditRuntime{pending: true}
	s.SetRuntime(r)
	if err := s.store.Close(); err != nil {
		t.Fatal(err)
	}
	err := s.ConfirmActivation()
	if err == nil || !strings.Contains(err.Error(), "Aktivasyon onaylandı") || !strings.Contains(err.Error(), "audit") {
		t.Fatalf("confirmation/audit outcome was ambiguous: %v", err)
	}
	snapshot := s.Snapshot()
	if snapshot.System.ActivationPending {
		t.Fatal("already-confirmed activation is still presented as pending")
	}
	found := false
	for _, health := range snapshot.System.Health {
		if health.Name == "Kayıt" && health.Status == "error" && strings.Contains(health.Detail, "audit") {
			found = true
		}
	}
	if !found {
		t.Fatal("audit write failure missing from operator health")
	}
}
