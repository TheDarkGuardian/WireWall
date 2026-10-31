package control

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const networkOwnershipName = "@wirewall-network-ownership-v1"

// NetworkOwnership serializes the one WireWall nftables table in a network
// namespace. The daemon owns it for its full lifetime; each independent guard
// inherits the same kernel handle and retains it until recovery has finished.
// A parent crash therefore cannot allow a new daemon to race an older guard,
// even when the new daemon selects a different state directory.
type NetworkOwnership struct {
	file    *os.File
	dataDir string
	once    sync.Once
	err     error
}

// AcquireNetworkOwnership must precede opening/persisting the service store.
// It never deletes old recovery records or cancels a pending watchdog.
func AcquireNetworkOwnership(dataDir string) (*NetworkOwnership, error) {
	return acquireNetworkOwnership(dataDir, networkOwnershipName)
}

func acquireNetworkOwnership(dataDir, name string) (*NetworkOwnership, error) {
	root, err := filepath.Abs(dataDir)
	if err != nil {
		return nil, err
	}
	file, err := openNetworkOwnership(name)
	if err != nil {
		return nil, err
	}
	owner := &NetworkOwnership{file: file, dataDir: root}
	if err := checkGuardRecovery(root); err != nil {
		_ = owner.Close()
		return nil, err
	}
	return owner, nil
}

func (owner *NetworkOwnership) Close() error {
	if owner == nil {
		return nil
	}
	owner.once.Do(func() { owner.err = owner.file.Close() })
	return owner.err
}

func (owner *NetworkOwnership) check(dataDir string) error {
	if owner == nil || owner.file == nil {
		return errors.New("XDP activation requires network ownership acquired before service initialization")
	}
	root, err := filepath.Abs(dataDir)
	if err != nil || filepath.Clean(root) != filepath.Clean(owner.dataDir) {
		return errors.New("network ownership state directory mismatch")
	}
	if _, err := owner.file.Stat(); err != nil {
		return fmt.Errorf("network ownership is no longer held: %w", err)
	}
	return nil
}

func checkGuardRecovery(root string) error {
	directory, err := ensureGuardDirectory(root)
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(directory, entry.Name())
		state, err := loadGuardState(path)
		if err == nil {
			err = validateGuardState(state, state.Deadline, false)
		}
		if err != nil {
			return fmt.Errorf("unresolved rollback record %s: %w; inspect recovery before restarting; no record was removed", path, err)
		}
		outcome, err := readGuardOutcome(path)
		if err != nil {
			return fmt.Errorf("unresolved rollback record %s: %w; inspect recovery before restarting; no record was removed", path, err)
		}
		if outcome == "confirmed" {
			continue // An exclusive confirmed decision can never run rollback.
		}
		if outcome == "rollback" {
			if raw, err := os.ReadFile(guardMarker(path, "rolledback")); err == nil && strings.TrimSpace(string(raw)) == "rollback completed" {
				continue // Completion is published only after nft, BPF and store recovery.
			}
		}
		return fmt.Errorf("unresolved rollback record %s: wait for the previous watchdog and inspect its .log/.failed status; complete recovery before restarting; no record was removed", path)
	}
	return nil
}
