package control

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/TheDarkGuardian/WireWall/internal/model"
	"github.com/TheDarkGuardian/WireWall/internal/policy"
)

func newTestService(t *testing.T, backend string) *Service {
	t.Helper()
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	service, err := NewService(store, nil, backend)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

type recordingRuntime struct {
	applyCalls []model.Policy
	applyError error
	live       LiveSnapshot
	liveError  error
	closed     bool
}

func (r *recordingRuntime) Apply(p model.Policy, _ []model.Ban) error {
	r.applyCalls = append(r.applyCalls, clonePolicy(p))
	return r.applyError
}
func (r *recordingRuntime) Snapshot() (LiveSnapshot, error) { return r.live, r.liveError }
func (r *recordingRuntime) Close() error                    { r.closed = true; return nil }

func TestServicePolicyConflictAndInvalidStatePreservation(t *testing.T) {
	s := newTestService(t, "lab")
	original := s.Policy()
	next := s.Policy()
	next.Mode = "enforce"
	applied, err := s.ApplyPolicy(next, original.Version)
	if err != nil {
		t.Fatal(err)
	}
	if applied.Version != original.Version+1 || applied.Mode != "enforce" {
		t.Fatalf("applied: %+v", applied)
	}
	if _, err = s.ApplyPolicy(next, original.Version); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale update: %v", err)
	}
	bad := s.Policy()
	bad.Host.TCPPorts = []uint16{0}
	if _, err = s.ApplyPolicy(bad, applied.Version); err == nil {
		t.Fatal("invalid policy accepted")
	}
	if got := s.Policy(); !reflect.DeepEqual(got, applied) {
		t.Fatalf("rejected update changed active policy: %+v", got)
	}
	// Callers receive independent slices; editing a response cannot mutate state.
	copy := s.Policy()
	copy.ManagementCIDRs[0] = "203.0.113.0/24"
	copy.Host.TCPPorts[0] = 65535
	if !reflect.DeepEqual(s.Policy(), applied) {
		t.Fatal("Policy response aliases internal state")
	}
}

func TestServiceClonesExplicitInitialPolicy(t *testing.T) {
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	p := policy.Default()
	expected := clonePolicy(p)
	s, err := NewService(store, &p, "lab")
	if err != nil {
		t.Fatal(err)
	}
	p.ManagementCIDRs[0] = "198.51.100.0/24"
	p.Host.TCPPorts[0] = 8080
	if !reflect.DeepEqual(s.Policy(), expected) {
		t.Fatal("initial caller policy aliases active service state")
	}
	stored, _, found, err := store.Load()
	if err != nil || !found || !reflect.DeepEqual(stored, expected) {
		t.Fatalf("explicit initial policy was not durably saved: found=%t policy=%+v err=%v", found, stored, err)
	}
}

func TestServiceInitialAuditIdentifiesBackend(t *testing.T) {
	for _, backend := range []string{"lab", "xdp"} {
		t.Run(backend, func(t *testing.T) {
			service := newTestService(t, backend)
			entries, err := service.store.Audit(10)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 1 || entries[0].Action != "initialize" {
				t.Fatalf("initial audit does not identify the actual backend: %+v", entries)
			}
			if isLaboratory := strings.Contains(entries[0].Detail, "laboratuvar"); isLaboratory != (backend == "lab") {
				t.Fatalf("initial audit misattributes real and synthetic policy initialization: %+v", entries)
			}
		})
	}
}

func TestServiceRuntimeFailurePreservesActivePolicy(t *testing.T) {
	s := newTestService(t, "xdp")
	r := &recordingRuntime{applyError: errors.New("kernel rejected policy")}
	s.SetRuntime(r)
	original := s.Policy()
	next := s.Policy()
	next.Mode = "enforce"
	if _, err := s.ApplyPolicy(next, original.Version); err == nil {
		t.Fatal("runtime failure was ignored")
	}
	if !reflect.DeepEqual(s.Policy(), original) {
		t.Fatal("runtime failure changed active policy")
	}
	if len(r.applyCalls) != 1 {
		t.Fatalf("runtime applies = %d", len(r.applyCalls))
	}
	stored, _, found, err := s.store.Load()
	if err != nil || !found || !reflect.DeepEqual(stored, original) {
		t.Fatalf("persistent policy changed: %+v, %v", stored, err)
	}
}

func TestServiceStorageFailureRollsBackRuntimePolicy(t *testing.T) {
	s := newTestService(t, "xdp")
	r := &recordingRuntime{}
	s.SetRuntime(r)
	original := s.Policy()
	next := s.Policy()
	next.Mode = "enforce"
	if err := s.store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApplyPolicy(next, original.Version); err == nil {
		t.Fatal("closed database accepted policy")
	}
	if !reflect.DeepEqual(s.Policy(), original) {
		t.Fatal("store failure changed in-memory policy")
	}
	if len(r.applyCalls) != 2 || !reflect.DeepEqual(r.applyCalls[1], original) {
		t.Fatalf("old runtime policy was not restored: %+v", r.applyCalls)
	}
}

func TestServiceBanValidationProtectionAndExpiration(t *testing.T) {
	s := newTestService(t, "lab")
	for _, test := range []struct {
		address, reason string
		seconds         int
	}{
		{"127.0.0.1", "Management ban", 60}, {"::1", "Management ban", 60},
		{"198.51.100.0/24", "CIDR unsupported", 60}, {"fe80::1%eth0", "Zoned unsupported", 60},
		{"0.0.0.0", "Unspecified", 60}, {"224.0.0.1", "Multicast", 60},
		{"198.51.100.66", "   ", 60}, {"198.51.100.66", "Test", 0}, {"198.51.100.66", "Test", 86401},
	} {
		if _, err := s.AddBan(test.address, test.reason, test.seconds); err == nil {
			t.Fatalf("invalid ban accepted: %+v", test)
		}
	}
	before := time.Now()
	b, err := s.AddBan("198.51.100.66", "Laboratory rule", 60)
	if err != nil {
		t.Fatal(err)
	}
	if b.CreatedAt.Before(before) || b.ExpiresAt.Sub(b.CreatedAt) != time.Minute {
		t.Fatalf("bad TTL: %+v", b)
	}
	if err = policy.ValidateBan(b); err != nil {
		t.Fatalf("service produced invalid evaluator ban: %v", err)
	}
	if _, err = s.AddBan(b.Address, "Duplicate ban", 60); err == nil {
		t.Fatal("duplicate ban accepted")
	}
	if len(s.Snapshot().Bans) != 1 {
		t.Fatal("active ban missing from snapshot")
	}
	s.mu.Lock()
	s.expireBansLocked(b.ExpiresAt)
	s.mu.Unlock()
	if len(s.Bans()) != 0 || len(s.Snapshot().Bans) != 0 {
		t.Fatal("ban survived expiration boundary")
	}
}

func TestSQLiteReloadAndLabResetPreserveConfiguration(t *testing.T) {
	dir := t.TempDir()
	store, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewService(store, nil, "lab")
	if err != nil {
		t.Fatal(err)
	}
	p := s.Policy()
	p.Mode = "enforce"
	p.Host.UDPPorts = []uint16{53}
	p, err = s.ApplyPolicy(p, p.Version)
	if err != nil {
		t.Fatal(err)
	}
	ban, err := s.AddBan("198.51.100.66", "Synthetic test", 3600)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.SetScenario("mixed"); err != nil {
		t.Fatal(err)
	}
	s.labTick(time.Now().UTC())
	if s.Snapshot().Metrics.ReceivedPackets == 0 {
		t.Fatal("lab did not evaluate synthetic packets")
	}
	auditBefore, err := store.Audit(100)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Reset(); err != nil {
		t.Fatal(err)
	}
	reset := s.Snapshot()
	if reset.Metrics.ReceivedPackets != 0 || len(reset.Events) != 0 || len(reset.History) != 0 || len(reset.Connections) != 0 {
		t.Fatal("reset retained laboratory counters")
	}
	if !reflect.DeepEqual(reset.Policy, p) || len(reset.Bans) != 1 || reset.Bans[0].ID != ban.ID {
		t.Fatal("reset deleted persistent configuration")
	}
	auditAfter, err := store.Audit(100)
	if err != nil || len(auditAfter) < len(auditBefore) {
		t.Fatal("reset deleted audit trail")
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	reloaded, err := NewService(store, nil, "lab")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(reloaded.Policy(), p) || len(reloaded.Bans()) != 1 || reloaded.Bans()[0].ID != ban.ID {
		t.Fatal("SQLite reload lost policy or ban")
	}
}

func TestLabIdentityAndCounterInvariants(t *testing.T) {
	s := newTestService(t, "lab")
	if err := s.SetScenario("mixed"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		s.labTick(time.Now().UTC().Add(time.Duration(i) * time.Second))
	}
	snapshot := s.Snapshot()
	if snapshot.System.Attached || !snapshot.System.Simulated || snapshot.System.XDPMode != "unattached" {
		t.Fatalf("lab implies kernel attachment: %+v", snapshot.System)
	}
	m := snapshot.Metrics
	if m.ReceivedPackets == 0 || m.ReceivedPackets != m.PassedPackets+m.DroppedPackets {
		t.Fatalf("packet counter invariant: %+v", m)
	}
	if m.WouldDropPackets > m.ReceivedPackets {
		t.Fatal("would-drop count exceeds received packets")
	}
	var protocols, reasons uint64
	for _, item := range m.Protocols {
		protocols += item.Packets
	}
	for _, item := range m.Reasons {
		reasons += item.Count
	}
	if protocols != m.ReceivedPackets || reasons != m.DroppedPackets {
		t.Fatalf("breakdown mismatch: protocols=%d reasons=%d metrics=%+v", protocols, reasons, m)
	}
	for _, event := range snapshot.Events {
		if !event.Simulated {
			t.Fatal("lab event missing simulated label")
		}
	}
	for _, connection := range snapshot.Connections {
		if !connection.Simulated || connection.State != "LAB_FLOW" {
			t.Fatal("lab connection claims real conntrack state")
		}
	}
	if len(snapshot.Events) > 300 || len(snapshot.Connections) > 24 || len(snapshot.History) > 120 {
		t.Fatal("laboratory memory bounds exceeded")
	}
}

func TestLiveSnapshotPreservesBackendTruthAndBreakdowns(t *testing.T) {
	s := newTestService(t, "xdp")
	r := &recordingRuntime{live: LiveSnapshot{Attached: false, XDPMode: "unattached", Metrics: Metrics{ReceivedPackets: 10, PassedPackets: 7, DroppedPackets: 3, Reasons: []ReasonCount{{Reason: "rule_drop", Count: 3}}, Protocols: []ProtocolCount{{Protocol: "tcp", Packets: 10}}, Services: []ServiceCount{{Protocol: "tcp", Port: 443, Packets: 10}}}, Health: []Health{{Name: "Attachment", Status: "error", Detail: "Kernel program detached"}}}}
	s.SetRuntime(r)
	s.liveTick(time.Now().UTC())
	snapshot := s.Snapshot()
	if snapshot.System.Attached || snapshot.System.XDPMode != "unattached" {
		t.Fatalf("runtime handle misreported as attached: %+v", snapshot.System)
	}
	if len(snapshot.Metrics.Reasons) != 1 || snapshot.Metrics.Reasons[0].Count != 3 || len(snapshot.Metrics.Protocols) != 1 || len(snapshot.Metrics.Services) != 1 {
		t.Fatalf("live breakdowns overwritten: %+v", snapshot.Metrics)
	}
	found := false
	for _, health := range snapshot.System.Health {
		if health.Name == "Attachment" && health.Status == "error" {
			found = true
		}
	}
	if !found {
		t.Fatal("live health discarded")
	}
	if err := s.SetScenario("normal"); err == nil {
		t.Fatal("live runtime accepted synthetic scenario")
	}
	if err := s.Reset(); err == nil {
		t.Fatal("live runtime accepted lab reset")
	}
}
