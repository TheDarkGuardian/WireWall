package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/TheDarkGuardian/WireWall/internal/control"
	"github.com/TheDarkGuardian/WireWall/internal/model"
	"github.com/TheDarkGuardian/WireWall/internal/policy"
)

func writeTestPolicy(t *testing.T, p model.Policy) string {
	t.Helper()
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "policy.json")
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
func TestReadPolicyStrictJSON(t *testing.T) {
	p := policy.Default()
	path := writeTestPolicy(t, p)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		data  []byte
		valid bool
	}{
		{"regular", raw, true}, {"utf8-bom", append([]byte{0xef, 0xbb, 0xbf}, raw...), true}, {"trailing-object", append(append([]byte{}, raw...), []byte(" {}")...), false}, {"unknown-field", []byte(`{"typo":true}`), false}, {"truncated", []byte(`{"version":`), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(path, tc.data, 0600); err != nil {
				t.Fatal(err)
			}
			got, err := readPolicy(path)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v err=%v", tc.valid, err)
			}
			if tc.valid && got.Version != p.Version {
				t.Fatal("version not decoded")
			}
		})
	}
	if err = os.WriteFile(path, make([]byte, (1<<20)+1), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = readPolicy(path); err == nil {
		t.Fatal("oversized policy accepted")
	}
}
func TestBootstrapDoesNotDiscardPanelEdits(t *testing.T) {
	store, err := control.OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	p := policy.Default()
	path := writeTestPolicy(t, p)
	initial, err := startupPolicy(store, path, false, "", "")
	if err != nil || initial == nil {
		t.Fatalf("first bootstrap: %v", err)
	}
	changed := p
	changed.Version = 7
	changed.Host.TCPPorts = []uint16{443, 8443}
	if err = store.Save(changed, []model.Ban{}, "test", "saved panel edit"); err != nil {
		t.Fatal(err)
	}
	initial, err = startupPolicy(store, path, false, "", "")
	if err != nil || initial != nil {
		t.Fatalf("bootstrap replaced persisted edits: %v", err)
	}
	initial, err = startupPolicy(store, path, true, "", "")
	if err != nil || initial == nil || initial.Version != 8 {
		t.Fatalf("explicit replace must increment version: %+v %v", initial, err)
	}
	initial, err = startupPolicy(store, path, false, "test0", "generic")
	if err != nil || initial == nil || initial.Interface != "test0" || initial.Version != 8 {
		t.Fatalf("explicit restart override: %+v %v", initial, err)
	}
	if _, err = startupPolicy(store, "", true, "", ""); err == nil {
		t.Fatal("replace without source accepted")
	}
}
func TestOperatorTokenPersistence(t *testing.T) {
	t.Setenv("WIREWALL_TOKEN", "")
	dir := t.TempDir()
	a, err := tokenFor(dir)
	if err != nil {
		t.Fatal(err)
	}
	b, err := tokenFor(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != 64 || a != b {
		t.Fatal("operator key was not persisted")
	}
	t.Setenv("WIREWALL_TOKEN", "short")
	if _, err = tokenFor(dir); err == nil {
		t.Fatal("short environment token accepted")
	}
}
