package control

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/TheDarkGuardian/WireWall/internal/dataplane"
	"github.com/TheDarkGuardian/WireWall/internal/hostfirewall"
	"github.com/TheDarkGuardian/WireWall/internal/model"
	"github.com/TheDarkGuardian/WireWall/internal/policy"
)

const (
	guardDefaultDuration = 90 * time.Second
	guardMaximumDuration = 120 * time.Second
	guardStateLimit      = 4 << 20
)

// guardState is a private rollback record, never accepted over the HTTP API.
// The initial program/link IDs may be zero until the parent attaches its XDP
// program. An unknown attachment is never detached by the guard.
type guardState struct {
	ID             string                `json:"id"`
	Interface      string                `json:"interface"`
	ProgramID      uint32                `json:"programId"`
	LinkID         uint32                `json:"linkId"`
	XDPMode        string                `json:"xdpMode"`
	Deadline       time.Time             `json:"deadline"`
	NFT            hostfirewall.Snapshot `json:"nft"`
	PreviousPolicy model.Policy          `json:"previousPolicy"`
	PreviousBans   []model.Ban           `json:"previousBans"`
	DataDir        string                `json:"dataDir"`
}

type activationGuard struct {
	mu       sync.Mutex
	state    guardState
	path     string
	deadline time.Time
}

// armGuard starts an independent process before network changes. The daemon
// does not own the child's lifetime: it uses no CommandContext or parent-death
// signal, and Linux puts the child in a new session. Readiness is acknowledged
// before this function returns; failure prevents the caller from applying nft.
func armGuard(dataDir string, state guardState, owner *NetworkOwnership) (*activationGuard, error) {
	if runtime.GOOS != "linux" {
		return nil, errors.New("activation rollback watchdog requires Linux")
	}
	if err := owner.check(dataDir); err != nil {
		return nil, err
	}
	root, err := filepath.Abs(dataDir)
	if err != nil {
		return nil, err
	}
	if state.DataDir != "" {
		given, err := filepath.Abs(state.DataDir)
		if err != nil || filepath.Clean(given) != filepath.Clean(root) {
			return nil, errors.New("guard data directory mismatch")
		}
	}
	state.DataDir = root
	if state.ID == "" {
		state.ID = newID()
	}
	if state.Deadline.IsZero() {
		state.Deadline = time.Now().UTC().Add(guardDefaultDuration)
	}
	if err := validateGuardState(state, time.Now(), true); err != nil {
		return nil, err
	}
	directory, err := ensureGuardDirectory(root)
	if err != nil {
		return nil, err
	}
	if err := checkGuardRecovery(root); err != nil {
		return nil, err
	}
	path := filepath.Join(directory, state.ID+".json")
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("guard identifier already exists or cannot be inspected")
	}
	if err := writeGuardJSON(path, state); err != nil {
		return nil, err
	}
	executable, err := os.Executable()
	if err != nil {
		return nil, err
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(executable)
	if err != nil || !filepath.IsAbs(executable) || !info.Mode().IsRegular() {
		return nil, errors.New("current executable is not a regular absolute file")
	}
	logFile, err := os.OpenFile(guardMarker(path, "log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	defer logFile.Close()
	command, err := startGuardProcess(executable, path, logFile, owner)
	if err != nil {
		_ = writeGuardMarker(path, "failed", err.Error())
		return nil, fmt.Errorf("start independent rollback watchdog: %w", err)
	}
	exit := make(chan error, 1)
	go func() { exit <- command.Wait() }()
	readyTimeout := time.NewTimer(5 * time.Second)
	defer readyTimeout.Stop()
	poll := time.NewTicker(25 * time.Millisecond)
	defer poll.Stop()
	for {
		if content, err := os.ReadFile(guardMarker(path, "ready")); err == nil && strings.TrimSpace(string(content)) == state.ID {
			return &activationGuard{state: state, path: path, deadline: state.Deadline}, nil
		}
		select {
		case err := <-exit:
			if err == nil {
				err = errors.New("watchdog exited before readiness acknowledgement")
			}
			return nil, fmt.Errorf("rollback watchdog unavailable: %w (see %s)", err, guardMarker(path, "log"))
		case <-readyTimeout.C:
			_ = command.Process.Kill()
			<-exit
			_ = writeGuardMarker(path, "failed", "startup acknowledgement timed out")
			return nil, errors.New("rollback watchdog did not acknowledge startup; network activation aborted")
		case <-poll.C:
		}
	}
}

// SetAttachment publishes both ownership IDs atomically. If this fails after
// attachment, the parent must close its newly created BPF link itself.
func (g *activationGuard) SetAttachment(programID, linkID uint32) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if programID == 0 || linkID == 0 {
		return errors.New("rollback ownership requires nonzero program and link IDs")
	}
	if !time.Now().Before(g.deadline) {
		return errors.New("rollback deadline elapsed before attachment ownership was recorded")
	}
	if outcome, err := readGuardOutcome(g.path); err != nil || outcome != "" {
		if err != nil {
			return err
		}
		return errors.New("rollback guard already decided")
	}
	updated := g.state
	updated.ProgramID, updated.LinkID = programID, linkID
	if err := writeGuardJSON(g.path, updated); err != nil {
		return err
	}
	g.state = updated
	return nil
}

// Confirm and the watchdog's rollback decision compete for the same exclusive
// outcome file. Exactly one wins; a late confirmation cannot cancel rollback.
func (g *activationGuard) Confirm() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	outcome, err := readGuardOutcome(g.path)
	if err != nil {
		return err
	}
	if outcome == "confirmed" {
		return writeGuardMarker(g.path, "confirmed", "confirmed")
	}
	if outcome == "rollback" {
		return errors.New("rollback has started; activation can no longer be confirmed")
	}
	if !time.Now().Before(g.deadline) {
		return errors.New("rollback deadline elapsed; confirmation refused")
	}
	won, err := claimGuardOutcome(g.path, "confirmed")
	if err != nil {
		return err
	}
	if !won {
		outcome, err = readGuardOutcome(g.path)
		if err != nil {
			return err
		}
		if outcome != "confirmed" {
			return errors.New("rollback won the activation decision")
		}
	}
	return writeGuardMarker(g.path, "confirmed", "confirmed")
}

func (g *activationGuard) RolledBack() bool {
	_, err := os.Stat(guardMarker(g.path, "rolledback"))
	return err == nil
}

func (g *activationGuard) Deadline() time.Time { return g.deadline }

// Err tells the parent to stop all network mutations as soon as rollback starts,
// rather than waiting for completion. A failed or late recovery is never treated
// as a healthy activation merely because the child process has exited.
func (g *activationGuard) Err() error {
	if raw, err := os.ReadFile(guardMarker(g.path, "failed")); err == nil {
		return fmt.Errorf("independent rollback watchdog failed: %s", strings.TrimSpace(string(raw)))
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("cannot inspect rollback failure status: %w", err)
	}
	outcome, err := readGuardOutcome(g.path)
	if err != nil {
		return err
	}
	if outcome == "rollback" {
		return errors.New("activation rollback has started; restart is required")
	}
	if outcome == "confirmed" {
		return nil
	}
	if !time.Now().Before(g.deadline) {
		return errors.New("activation deadline elapsed; independent rollback is pending")
	}
	if _, err := os.Stat(g.path); err != nil {
		return fmt.Errorf("rollback state unavailable: %w", err)
	}
	return nil
}

func (g *activationGuard) Pending() bool {
	outcome, err := readGuardOutcome(g.path)
	if err != nil || outcome == "confirmed" {
		return false
	}
	if g.RolledBack() {
		return false
	}
	if _, err := os.Stat(guardMarker(g.path, "failed")); err == nil {
		return false
	}
	_, err = os.Stat(g.path)
	return err == nil
}

// RunGuard is the private child CLI entrypoint. Its inherited ownership handle
// keeps restart exclusion alive after a daemon crash and throughout recovery.
// It is intentionally unavailable on Windows and never invokes a shell.
func RunGuard(args []string) error {
	if runtime.GOOS != "linux" {
		return errors.New("rollback watchdog requires Linux")
	}
	flags := flag.NewFlagSet("rollback-guard", flag.ContinueOnError)
	path := flags.String("state", "", "private rollback state JSON")
	lockFD := flags.Int("network-lock-fd", -1, "inherited private network ownership handle")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *path == "" || *lockFD != 3 || flags.NArg() != 0 {
		return errors.New("rollback-guard requires --state FILE and its inherited --network-lock-fd 3")
	}
	ownership := os.NewFile(uintptr(*lockFD), "inherited-wirewall-network-ownership")
	defer ownership.Close()
	if err := verifyNetworkOwnership(ownership, networkOwnershipName); err != nil {
		return err
	}
	absolute, err := filepath.Abs(*path)
	if err != nil {
		return err
	}
	return runGuardLoop(absolute, realGuardOperations())
}

type guardOperations struct {
	now     func() time.Time
	current func(context.Context, string) (uint32, error)
	detach  func(context.Context, string, uint32, uint32) error
	restore func(context.Context, hostfirewall.Snapshot) error
	save    func(guardState) error
}

func realGuardOperations() guardOperations {
	return guardOperations{
		now:     time.Now,
		current: dataplane.CurrentProgramID,
		detach:  dataplane.DetachOwned,
		restore: hostfirewall.Restore,
		save: func(state guardState) error {
			store, err := OpenStore(state.DataDir)
			if err != nil {
				return err
			}
			defer store.Close()
			return store.Save(state.PreviousPolicy, state.PreviousBans, "activation.rollback", "Bağımsız kurtarma süreci: geçici aktivasyon zaman aşımına uğradı")
		},
	}
}

func runGuardLoop(path string, operations guardOperations) error {
	initial, err := loadGuardState(path)
	if err != nil {
		return err
	}
	if err = validateGuardState(initial, operations.now(), true); err != nil {
		return err
	}
	if err = writeGuardMarker(path, "ready", initial.ID); err != nil {
		return err
	}
	poll := time.NewTicker(100 * time.Millisecond)
	defer poll.Stop()
	for {
		outcome, err := readGuardOutcome(path)
		if err != nil {
			return guardFailure(path, err)
		}
		if outcome == "confirmed" {
			return nil
		}
		if outcome == "rollback" {
			return guardFailure(path, errors.New("another process already claimed this rollback"))
		}
		if !operations.now().Before(initial.Deadline) {
			won, err := claimGuardOutcome(path, "rollback")
			if err != nil {
				return guardFailure(path, err)
			}
			if !won {
				continue
			}
			current, err := loadGuardState(path)
			if err != nil {
				return guardFailure(path, err)
			}
			if current.ID != initial.ID || !current.Deadline.Equal(initial.Deadline) {
				return guardFailure(path, errors.New("rollback record identity or deadline changed"))
			}
			if err := validateGuardState(current, operations.now(), false); err != nil {
				return guardFailure(path, err)
			}
			if err := executeGuardRollback(current, operations); err != nil {
				return guardFailure(path, err)
			}
			return writeGuardMarker(path, "rolledback", "rollback completed")
		}
		<-poll.C
	}
}

func executeGuardRollback(state guardState, operations guardOperations) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var failures []error
	if err := operations.restore(ctx, state.NFT); err != nil {
		failures = append(failures, fmt.Errorf("restore owned nftables table: %w", err))
	}
	if state.ProgramID != 0 && state.LinkID != 0 {
		current, err := operations.current(ctx, state.Interface)
		if err != nil {
			failures = append(failures, fmt.Errorf("inspect current XDP ownership: %w", err))
		} else if current == state.ProgramID {
			if err := operations.detach(ctx, state.Interface, state.ProgramID, state.LinkID); err != nil {
				failures = append(failures, fmt.Errorf("detach owned XDP link: %w", err))
			}
		} else if current != 0 {
			failures = append(failures, fmt.Errorf("XDP ownership changed to program %d; refusing to detach it", current))
		}
	}
	// Restore persisted policy even when one kernel recovery step fails. The
	// .failed marker still makes a partial rollback explicit to the parent.
	if err := operations.save(state); err != nil {
		failures = append(failures, fmt.Errorf("restore stored policy: %w", err))
	}
	return errors.Join(failures...)
}

func validateGuardState(state guardState, now time.Time, starting bool) error {
	if !guardIdentifier(state.ID) {
		return errors.New("invalid rollback identifier")
	}
	if !guardInterfaceName(state.Interface) {
		return errors.New("invalid rollback interface")
	}
	if state.XDPMode != "native" && state.XDPMode != "generic" {
		return errors.New("invalid rollback XDP mode")
	}
	if (state.ProgramID == 0) != (state.LinkID == 0) {
		return errors.New("rollback attachment ownership is incomplete")
	}
	if state.Deadline.IsZero() {
		return errors.New("rollback deadline is required")
	}
	if starting && (!state.Deadline.After(now) || state.Deadline.Sub(now) > guardMaximumDuration) {
		return errors.New("rollback deadline must be within the next 120 seconds")
	}
	if !filepath.IsAbs(state.DataDir) {
		return errors.New("rollback data directory must be absolute")
	}
	if err := policy.Validate(state.PreviousPolicy); err != nil {
		return fmt.Errorf("invalid previous policy: %w", err)
	}
	if len(state.PreviousBans) > policy.MaxBans {
		return errors.New("rollback ban capacity exceeded")
	}
	for _, ban := range state.PreviousBans {
		if err := policy.ValidateBan(ban); err != nil {
			return fmt.Errorf("invalid previous ban: %w", err)
		}
	}
	if state.NFT.Exists && !strings.Contains(state.NFT.Source, `comment "managed-by-wirewall"`) {
		return errors.New("rollback snapshot lacks WireWall ownership marker")
	}
	if !state.NFT.Exists && state.NFT.Source != "" {
		return errors.New("absent rollback table cannot contain source")
	}
	return nil
}

func guardIdentifier(value string) bool {
	if len(value) < 1 || len(value) > 64 {
		return false
	}
	for _, ch := range value {
		if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-' || ch == '_') {
			return false
		}
	}
	return true
}

func guardInterfaceName(value string) bool {
	if len(value) < 1 || len(value) > 15 || value == "." || value == ".." {
		return false
	}
	for _, ch := range value {
		if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-' || ch == '_' || ch == '.') {
			return false
		}
	}
	return true
}

func ensureGuardDirectory(root string) (string, error) {
	if err := os.MkdirAll(root, 0700); err != nil {
		return "", err
	}
	rootInfo, err := os.Lstat(root)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("guard data directory must be a real directory")
	}
	if err := os.Chmod(root, 0700); err != nil {
		return "", err
	}
	directory := filepath.Join(root, "guards")
	if err := os.MkdirAll(directory, 0700); err != nil {
		return "", err
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("guard directory must be a real directory")
	}
	if err := os.Chmod(directory, 0700); err != nil {
		return "", err
	}
	return directory, nil
}

func loadGuardState(path string) (guardState, error) {
	var state guardState
	info, err := os.Lstat(path)
	if err != nil {
		return state, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return state, errors.New("rollback state must be a regular non-symlink file")
	}
	if runtime.GOOS == "linux" && info.Mode().Perm()&0077 != 0 {
		return state, errors.New("rollback state file permissions must be private")
	}
	if info.Size() > guardStateLimit {
		return state, errors.New("rollback state exceeds size limit")
	}
	file, err := os.Open(path)
	if err != nil {
		return state, err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, guardStateLimit+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil {
		return state, err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return state, errors.New("rollback state requires one JSON object")
	}
	expected := filepath.Join(state.DataDir, "guards", state.ID+".json")
	absolute, err := filepath.Abs(path)
	if err != nil || filepath.Clean(absolute) != filepath.Clean(expected) {
		return state, errors.New("rollback state path does not match its private record")
	}
	return state, nil
}

func guardMarker(path, suffix string) string { return path + "." + suffix }

func readGuardOutcome(path string) (string, error) {
	raw, err := os.ReadFile(guardMarker(path, "outcome"))
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	value := strings.TrimSpace(string(raw))
	if value != "confirmed" && value != "rollback" {
		return "", errors.New("invalid rollback outcome record")
	}
	return value, nil
}

func claimGuardOutcome(path, value string) (bool, error) {
	if value != "confirmed" && value != "rollback" {
		return false, errors.New("invalid guard decision")
	}
	// Publish a fully written file through an exclusive hard link. Creating an
	// empty O_EXCL file and then writing it would expose a partial decision to
	// the other process and make a confirmation/timeout race look corrupt.
	file, err := os.CreateTemp(filepath.Dir(path), ".guard-decision-*")
	if err != nil {
		return false, err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if err := file.Chmod(0600); err != nil {
		file.Close()
		return false, err
	}
	_, writeErr := file.WriteString(value + "\n")
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if writeErr != nil {
		return false, writeErr
	}
	if closeErr != nil {
		return false, closeErr
	}
	if err := os.Link(temporary, guardMarker(path, "outcome")); errors.Is(err, os.ErrExist) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return true, nil
}

func writeGuardJSON(path string, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return writePrivateAtomic(path, append(raw, '\n'))
}

func writeGuardMarker(path, suffix, message string) error {
	return writePrivateAtomic(guardMarker(path, suffix), []byte(message+"\n"))
}

func writePrivateAtomic(path string, raw []byte) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".guard-*")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if err := file.Chmod(0600); err != nil {
		file.Close()
		return err
	}
	if _, err := file.Write(raw); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}

func guardFailure(path string, err error) error {
	if markerErr := writeGuardMarker(path, "failed", err.Error()); markerErr != nil {
		return errors.Join(err, markerErr)
	}
	return err
}
