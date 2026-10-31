//go:build linux

package control

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func rootAgentTestDirectory(t *testing.T) string {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("private agent listener tests require root; they never load BPF or change firewall rules")
	}
	directory, err := os.MkdirTemp("/tmp", "wirewall-agent-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	if err := os.Chmod(directory, 0750); err != nil {
		t.Fatal(err)
	}
	return directory
}

func TestAgentDirectoryDoesNotChangeExistingPermissions(t *testing.T) {
	directory := rootAgentTestDirectory(t)
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	if err := ensureAgentDirectory(directory); err == nil {
		t.Fatal("existing private directory mode was silently changed")
	}
	info, err := os.Stat(directory)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0700 {
		t.Fatalf("existing directory mode changed: %o", info.Mode().Perm())
	}
}

func TestAgentRefusesExistingAndSymlinkPaths(t *testing.T) {
	directory := rootAgentTestDirectory(t)
	path := filepath.Join(directory, "agent.sock")
	if err := os.WriteFile(path, []byte("foreign-file"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := ServeAgent(context.Background(), path, newTestService(t, "lab")); err == nil {
		t.Fatal("existing socket path was replaced")
	}
	raw, err := os.ReadFile(path)
	if err != nil || string(raw) != "foreign-file" {
		t.Fatalf("foreign path changed: %q %v", raw, err)
	}
	alias := filepath.Join(directory, "alias")
	if err := os.Symlink(directory, alias); err != nil {
		t.Fatal(err)
	}
	if err := ServeAgent(context.Background(), filepath.Join(alias, "second.sock"), newTestService(t, "lab")); err == nil {
		t.Fatal("symlinked socket parent accepted")
	}
}

func TestPrivateAgentUnixListenerLifecycle(t *testing.T) {
	directory := rootAgentTestDirectory(t)
	path := filepath.Join(directory, "agent.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	service := newTestService(t, "lab")
	go func() { done <- ServeAgent(ctx, path, service) }()
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", path)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second}
	deadline := time.Now().Add(2 * time.Second)
	var response *http.Response
	var err error
	for time.Now().Before(deadline) {
		response, err = client.Get("http://wirewall.internal/api/v1/health")
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("private agent did not become ready: %v", err)
	}
	response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatalf("agent health=%d", response.StatusCode)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0660 {
		t.Fatalf("socket mode=%v", info.Mode())
	}
	response, err = client.Get("http://wirewall.internal/api/v1/snapshot")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatalf("private snapshot=%d", response.StatusCode)
	}
	response, err = client.Get("http://wirewall.internal/api/v1/session")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 404 {
		t.Fatalf("private session path exposed: %d", response.StatusCode)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("agent listener did not stop")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("owned socket was not removed at shutdown: %v", err)
	}
}
