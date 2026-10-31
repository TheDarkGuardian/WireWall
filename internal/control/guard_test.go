package control

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TheDarkGuardian/WireWall/internal/hostfirewall"
	"github.com/TheDarkGuardian/WireWall/internal/model"
	"github.com/TheDarkGuardian/WireWall/internal/policy"
)

func newGuardFixture(t *testing.T) (*activationGuard, guardState) {
	t.Helper()
	root, err := filepath.Abs(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	directory, err := ensureGuardDirectory(root)
	if err != nil {
		t.Fatal(err)
	}
	state := guardState{ID: "guard-test-1", Interface: "eth0", XDPMode: "generic", Deadline: time.Now().UTC().Add(90 * time.Second), PreviousPolicy: policy.Default(), PreviousBans: []model.Ban{}, DataDir: root}
	path := filepath.Join(directory, state.ID+".json")
	if err := writeGuardJSON(path, state); err != nil {
		t.Fatal(err)
	}
	return &activationGuard{state: state, path: path, deadline: state.Deadline}, state
}

func TestGuardStateValidationRejectsUnsafeRecords(t *testing.T) {
	_, valid := newGuardFixture(t)
	if err := validateGuardState(valid, time.Now(), true); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*guardState)
	}{
		{"path identifier", func(s *guardState) { s.ID = "../../escape" }},
		{"interface shell", func(s *guardState) { s.Interface = "eth0;reboot" }},
		{"partial attachment", func(s *guardState) { s.ProgramID = 42 }},
		{"missing deadline", func(s *guardState) { s.Deadline = time.Time{} }},
		{"expired deadline", func(s *guardState) { s.Deadline = time.Now().Add(-time.Second) }},
		{"overlong deadline", func(s *guardState) { s.Deadline = time.Now().Add(121 * time.Second) }},
		{"relative root", func(s *guardState) { s.DataDir = "relative" }},
		{"unsupported XDP", func(s *guardState) { s.XDPMode = "hardware" }},
		{"invalid previous policy", func(s *guardState) { s.PreviousPolicy.Mode = "invalid" }},
		{"foreign table", func(s *guardState) { s.NFT = hostfirewall.Snapshot{Exists: true, Source: "table inet foreign {}"} }},
		{"unexpected table source", func(s *guardState) { s.NFT = hostfirewall.Snapshot{Exists: false, Source: "table inet wirewall {}"} }},
		{"invalid previous ban", func(s *guardState) { s.PreviousBans = []model.Ban{{Address: "bad"}} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := valid
			candidate.PreviousPolicy = clonePolicy(valid.PreviousPolicy)
			test.mutate(&candidate)
			if err := validateGuardState(candidate, time.Now(), true); err == nil {
				t.Fatal("unsafe record accepted")
			}
		})
	}
}

func TestGuardPrivateAtomicStateRoundTripAndParser(t *testing.T) {
	g, state := newGuardFixture(t)
	loaded, err := loadGuardState(g.path)
	if err != nil || loaded.ID != state.ID {
		t.Fatalf("roundtrip: %+v %v", loaded, err)
	}
	state.ProgramID, state.LinkID = 11, 22
	if err := writeGuardJSON(g.path, state); err != nil {
		t.Fatal(err)
	}
	loaded, err = loadGuardState(g.path)
	if err != nil || loaded.ProgramID != 11 || loaded.LinkID != 22 {
		t.Fatalf("atomic replacement: %+v %v", loaded, err)
	}
	if runtime.GOOS == "linux" {
		info, _ := os.Stat(g.path)
		if info.Mode().Perm() != 0600 {
			t.Fatalf("state permissions=%o", info.Mode().Perm())
		}
		info, _ = os.Stat(filepath.Dir(g.path))
		if info.Mode().Perm() != 0700 {
			t.Fatalf("directory permissions=%o", info.Mode().Perm())
		}
	}
	raw, err := os.ReadFile(g.path)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{string(raw) + `{}`, strings.TrimSuffix(strings.TrimSpace(string(raw)), "}") + `,"unexpected":true}`, "{broken"} {
		if err := writePrivateAtomic(g.path, []byte(bad)); err != nil {
			t.Fatal(err)
		}
		if _, err := loadGuardState(g.path); err == nil {
			t.Fatalf("malformed record accepted: %s", bad)
		}
	}
	if err := writeGuardJSON(g.path, state); err != nil {
		t.Fatal(err)
	}
	wrong := filepath.Join(filepath.Dir(g.path), "wrong.json")
	if err := writeGuardJSON(wrong, state); err != nil {
		t.Fatal(err)
	}
	if _, err := loadGuardState(wrong); err == nil {
		t.Fatal("state loaded from mismatched path")
	}
}

func TestGuardOutcomePublicationHasExactlyOneWinner(t *testing.T) {
	g, _ := newGuardFixture(t)
	var won atomic.Int64
	var group sync.WaitGroup
	for i := 0; i < 64; i++ {
		group.Add(1)
		go func(i int) {
			defer group.Done()
			value := "confirmed"
			if i%2 == 0 {
				value = "rollback"
			}
			ok, err := claimGuardOutcome(g.path, value)
			if err != nil {
				t.Errorf("claim: %v", err)
			}
			if ok {
				won.Add(1)
			}
			if _, err := readGuardOutcome(g.path); err != nil {
				t.Errorf("partially published outcome: %v", err)
			}
		}(i)
	}
	group.Wait()
	if won.Load() != 1 {
		t.Fatalf("decision winners=%d, want 1", won.Load())
	}
	if value, err := readGuardOutcome(g.path); err != nil || value == "" {
		t.Fatalf("outcome=%q err=%v", value, err)
	}
}

func TestGuardConfirmationAndAttachmentLifecycle(t *testing.T) {
	g, _ := newGuardFixture(t)
	if !g.Pending() || g.RolledBack() {
		t.Fatal("new guard lifecycle wrong")
	}
	if err := g.Err(); err != nil {
		t.Fatalf("healthy guard reports error: %v", err)
	}
	if err := g.SetAttachment(11, 22); err != nil {
		t.Fatal(err)
	}
	state, err := loadGuardState(g.path)
	if err != nil || state.ProgramID != 11 || state.LinkID != 22 {
		t.Fatalf("attachment not persisted: %+v %v", state, err)
	}
	if !g.Deadline().Equal(state.Deadline) {
		t.Fatal("deadline changed")
	}
	if err := g.Confirm(); err != nil {
		t.Fatal(err)
	}
	if err := g.Confirm(); err != nil {
		t.Fatalf("confirmation not idempotent: %v", err)
	}
	if g.Pending() || g.RolledBack() {
		t.Fatal("confirmed lifecycle wrong")
	}
	if err := g.Err(); err != nil {
		t.Fatalf("confirmed guard reports error: %v", err)
	}
	if _, err := os.Stat(guardMarker(g.path, "confirmed")); err != nil {
		t.Fatal("confirmation marker missing")
	}
	if err := g.SetAttachment(33, 44); err == nil {
		t.Fatal("attachment updated after confirmation")
	}
}

func TestGuardLateConfirmationCannotCancelRollback(t *testing.T) {
	g, _ := newGuardFixture(t)
	if ok, err := claimGuardOutcome(g.path, "rollback"); err != nil || !ok {
		t.Fatal(err)
	}
	if err := g.Confirm(); err == nil {
		t.Fatal("confirmation overrode rollback")
	}
	if !g.Pending() || g.Err() == nil {
		t.Fatal("rollback in progress must remain pending and block new activation")
	}
	if _, err := os.Stat(guardMarker(g.path, "confirmed")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("late confirmation marker created")
	}
	g, _ = newGuardFixture(t)
	g.deadline = time.Now().Add(-time.Second)
	if err := g.Confirm(); err == nil {
		t.Fatal("expired deadline accepted confirmation")
	}
	if err := g.SetAttachment(1, 2); err == nil {
		t.Fatal("expired deadline accepted attachment")
	}
	if g.Err() == nil {
		t.Fatal("expired pending guard reports healthy status")
	}
}

func TestGuardErrorMakesPartialFailureAndCorruptionExplicit(t *testing.T) {
	g, _ := newGuardFixture(t)
	if err := writeGuardMarker(g.path, "failed", "nft recovery failed"); err != nil {
		t.Fatal(err)
	}
	if err := g.Err(); err == nil || !strings.Contains(err.Error(), "nft recovery failed") {
		t.Fatalf("partial failure hidden: %v", err)
	}
	if g.Pending() {
		t.Fatal("failed recovery still pending")
	}
	g, _ = newGuardFixture(t)
	if err := writePrivateAtomic(guardMarker(g.path, "outcome"), []byte("invalid")); err != nil {
		t.Fatal(err)
	}
	if g.Err() == nil {
		t.Fatal("corrupt outcome reports healthy status")
	}
}

type fakeGuardOperations struct {
	currentID                                        uint32
	currentErr, errorRestore, errorDetach, errorSave error
	calls                                            []string
	now                                              func() time.Time
	saved                                            guardState
}

func (f *fakeGuardOperations) operations() guardOperations {
	if f.now == nil {
		f.now = time.Now
	}
	return guardOperations{now: f.now, current: func(context.Context, string) (uint32, error) {
		f.calls = append(f.calls, "current")
		return f.currentID, f.currentErr
	}, detach: func(_ context.Context, _ string, programID, linkID uint32) error {
		f.calls = append(f.calls, "detach")
		if programID == 0 || linkID == 0 {
			panic("unknown attachment detach attempted")
		}
		return f.errorDetach
	}, restore: func(context.Context, hostfirewall.Snapshot) error {
		f.calls = append(f.calls, "restore")
		return f.errorRestore
	}, save: func(state guardState) error { f.calls = append(f.calls, "save"); f.saved = state; return f.errorSave }}
}

func TestGuardRollbackOnlyDetachesOwnedAttachment(t *testing.T) {
	_, state := newGuardFixture(t)
	state.ProgramID, state.LinkID = 11, 22
	for _, test := range []struct {
		name              string
		programID         uint32
		wantError, detach bool
	}{
		{"owned", 11, false, true}, {"already absent", 0, false, false}, {"foreign replacement", 99, true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := &fakeGuardOperations{currentID: test.programID}
			err := executeGuardRollback(state, f.operations())
			if (err != nil) != test.wantError {
				t.Fatalf("rollback err=%v", err)
			}
			didDetach := false
			for _, call := range f.calls {
				if call == "detach" {
					didDetach = true
				}
			}
			if didDetach != test.detach {
				t.Fatalf("detach=%t want %t; calls=%v", didDetach, test.detach, f.calls)
			}
			if f.saved.PreviousPolicy.Version != state.PreviousPolicy.Version {
				t.Fatal("previous policy not persisted")
			}
		})
	}
	state.ProgramID, state.LinkID = 0, 0
	f := &fakeGuardOperations{currentID: 99}
	if err := executeGuardRollback(state, f.operations()); err != nil {
		t.Fatal(err)
	}
	if strings.Join(f.calls, ",") != "restore,save" {
		t.Fatalf("unknown ownership inspected/detached: %v", f.calls)
	}
}

func TestGuardRollbackAttemptsRemainingRecoveryAfterFailure(t *testing.T) {
	_, state := newGuardFixture(t)
	state.ProgramID, state.LinkID = 11, 22
	f := &fakeGuardOperations{currentID: 11, errorRestore: errors.New("nft failure"), errorDetach: errors.New("link failure"), errorSave: errors.New("sqlite failure")}
	err := executeGuardRollback(state, f.operations())
	if err == nil || !strings.Contains(err.Error(), "nft failure") || !strings.Contains(err.Error(), "link failure") || !strings.Contains(err.Error(), "sqlite failure") {
		t.Fatalf("partial recovery failures hidden: %v", err)
	}
	if strings.Join(f.calls, ",") != "restore,current,detach,save" {
		t.Fatalf("recovery steps skipped: %v", f.calls)
	}
}

func TestGuardLoopTimeoutProducesRollbackMarkerWithoutNetworkCommands(t *testing.T) {
	g, state := newGuardFixture(t)
	state.ProgramID, state.LinkID = 11, 22
	if err := writeGuardJSON(g.path, state); err != nil {
		t.Fatal(err)
	}
	calls := 0
	f := &fakeGuardOperations{currentID: 11, now: func() time.Time {
		calls++
		if calls == 1 {
			return state.Deadline.Add(-time.Second)
		}
		return state.Deadline
	}}
	if err := runGuardLoop(g.path, f.operations()); err != nil {
		t.Fatal(err)
	}
	if !g.RolledBack() || g.Pending() {
		t.Fatal("timeout lifecycle markers missing")
	}
	if len(f.calls) != 4 {
		t.Fatalf("rollback not executed: %v", f.calls)
	}
	if _, err := os.Stat(guardMarker(g.path, "ready")); err != nil {
		t.Fatal("readiness marker missing")
	}
}

func TestGuardLoopConfirmationExitsWithoutRecovery(t *testing.T) {
	g, _ := newGuardFixture(t)
	if err := g.Confirm(); err != nil {
		t.Fatal(err)
	}
	f := &fakeGuardOperations{}
	if err := runGuardLoop(g.path, f.operations()); err != nil {
		t.Fatal(err)
	}
	if len(f.calls) != 0 {
		t.Fatalf("confirmed guard touched recovery: %v", f.calls)
	}
}

func TestGuardLoopPartialFailureIsExplicit(t *testing.T) {
	g, state := newGuardFixture(t)
	state.ProgramID, state.LinkID = 11, 22
	if err := writeGuardJSON(g.path, state); err != nil {
		t.Fatal(err)
	}
	calls := 0
	f := &fakeGuardOperations{currentID: 99, now: func() time.Time {
		calls++
		if calls == 1 {
			return state.Deadline.Add(-time.Second)
		}
		return state.Deadline
	}}
	if err := runGuardLoop(g.path, f.operations()); err == nil {
		t.Fatal("foreign program ownership failure hidden")
	}
	if g.RolledBack() {
		t.Fatal("partial failure marked as completed rollback")
	}
	if _, err := os.Stat(guardMarker(g.path, "failed")); err != nil {
		t.Fatal("failure marker missing")
	}
}

func TestGuardStartupRefusesUnresolvedRecoveryRecords(t *testing.T) {
	for _, test := range []struct {
		name, outcome, completion, failure string
		corrupt, allow                     bool
	}{
		{name: "pending"},
		{name: "rollback running", outcome: "rollback"},
		{name: "partial recovery failed", outcome: "rollback", failure: "nft restore failed"},
		{name: "startup failed", failure: "watchdog failed to start"},
		{name: "invalid completion", outcome: "rollback", completion: "incomplete"},
		{name: "completion without decision", completion: "rollback completed"},
		{name: "corrupt record", corrupt: true},
		{name: "confirmed", outcome: "confirmed", allow: true},
		{name: "completed recovery", outcome: "rollback", completion: "rollback completed", allow: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			g, state := newGuardFixture(t)
			// A past deadline does not make a pending or failed recovery safe.
			state.Deadline = time.Now().Add(-time.Hour)
			if err := writeGuardJSON(g.path, state); err != nil {
				t.Fatal(err)
			}
			if test.corrupt {
				if err := writePrivateAtomic(g.path, []byte("invalid")); err != nil {
					t.Fatal(err)
				}
			}
			if test.outcome != "" {
				if _, err := claimGuardOutcome(g.path, test.outcome); err != nil {
					t.Fatal(err)
				}
			}
			for suffix, value := range map[string]string{"rolledback": test.completion, "failed": test.failure} {
				if value != "" {
					if err := writeGuardMarker(g.path, suffix, value); err != nil {
						t.Fatal(err)
					}
				}
			}
			err := checkGuardRecovery(state.DataDir)
			if (err == nil) != test.allow {
				t.Fatalf("startup allow=%t, err=%v", test.allow, err)
			}
			if err != nil && !strings.Contains(err.Error(), "no record was removed") {
				t.Fatalf("recovery instructions missing: %v", err)
			}
			if _, err := os.Stat(g.path); err != nil {
				t.Fatalf("startup deleted recovery evidence: %v", err)
			}
		})
	}
	if err := checkGuardRecovery(t.TempDir()); err != nil {
		t.Fatalf("clean startup refused: %v", err)
	}
}

func TestWindowsCannotArmOrRunLinuxGuard(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("Windows unsupported path")
	}
	_, state := newGuardFixture(t)
	if _, err := armGuard(state.DataDir, state, nil); err == nil {
		t.Fatal("non-Linux guard armed")
	}
	if err := RunGuard([]string{"--state", "unused"}); err == nil {
		t.Fatal("non-Linux guard ran")
	}
	if ownership, err := AcquireNetworkOwnership(t.TempDir()); err == nil {
		_ = ownership.Close()
		t.Fatal("non-Linux process claimed real network ownership")
	}
}
