//go:build linux

package control

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestNetworkOwnershipInheritedLifetime(t *testing.T) {
	if os.Getenv("WIREWALL_TEST_OWNERSHIP_CHILD") == "1" {
		file := os.NewFile(3, "test-inherited-ownership")
		if err := verifyNetworkOwnership(file, os.Getenv("WIREWALL_TEST_OWNERSHIP_NAME")); err != nil {
			t.Fatal(err)
		}
		flags, err := unix.FcntlInt(file.Fd(), unix.F_GETFD, 0)
		if err != nil || flags&unix.FD_CLOEXEC == 0 {
			t.Fatalf("imported ownership handle is not close-on-exec: flags=%d err=%v", flags, err)
		}
		fmt.Println("ownership ready")
		if _, err := bufio.NewReader(os.Stdin).ReadByte(); err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		return
	}
	for _, parentCloses := range []bool{false, true} {
		t.Run(fmt.Sprintf("parent_closes_%t", parentCloses), func(t *testing.T) {
			// Never contend with the real application's well-known socket name.
			name := fmt.Sprintf("@wirewall-test-%d-%s", os.Getpid(), newID())
			root, otherRoot := t.TempDir(), t.TempDir()
			owner, err := acquireNetworkOwnership(root, name)
			if err != nil {
				t.Fatal(err)
			}
			defer owner.Close()
			if err := owner.check(root); err != nil {
				t.Fatal(err)
			}
			if err := owner.check(otherRoot); err == nil {
				t.Fatal("ownership accepted a different state directory")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestNetworkOwnershipInheritedLifetime$")
			command.Env = append(os.Environ(), "WIREWALL_TEST_OWNERSHIP_CHILD=1", "WIREWALL_TEST_OWNERSHIP_NAME="+name)
			command.ExtraFiles = []*os.File{owner.file}
			var stderr bytes.Buffer
			command.Stderr = &stderr
			output, err := command.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			input, err := command.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			reader := bufio.NewReader(output)
			line, err := reader.ReadString('\n')
			if err != nil || strings.TrimSpace(line) != "ownership ready" {
				t.Fatalf("inherited child not ready: %q %v; %s", line, err, stderr.String())
			}
			if parentCloses {
				if err := owner.Close(); err != nil {
					t.Fatal(err)
				}
				if err := owner.check(root); err == nil {
					t.Fatal("closed parent ownership still appears usable")
				}
			}
			if second, err := acquireNetworkOwnership(otherRoot, name); err == nil {
				_ = second.Close()
				t.Fatal("new state directory bypassed a live daemon/watchdog")
			}
			if _, err := input.Write([]byte("\n")); err != nil {
				t.Fatal(err)
			}
			_ = input.Close()
			if err := command.Wait(); err != nil {
				t.Fatalf("inherited child failed: %v; %s", err, stderr.String())
			}
			if !parentCloses {
				if second, err := acquireNetworkOwnership(otherRoot, name); err == nil {
					_ = second.Close()
					t.Fatal("confirmed guard exit released the active daemon's ownership")
				}
				if err := owner.Close(); err != nil {
					t.Fatal(err)
				}
			}
			next, err := acquireNetworkOwnership(otherRoot, name)
			if err != nil {
				t.Fatalf("all owners exited but next activation refused: %v", err)
			}
			_ = next.Close()
		})
	}
}

func TestNetworkOwnershipRejectsUnresolvedRecordAndReleasesHandle(t *testing.T) {
	g, state := newGuardFixture(t)
	name := fmt.Sprintf("@wirewall-test-%d-%s", os.Getpid(), newID())
	if owner, err := acquireNetworkOwnership(state.DataDir, name); err == nil {
		_ = owner.Close()
		t.Fatal("startup accepted a pending record")
	}
	if err := g.Confirm(); err != nil {
		t.Fatal(err)
	}
	owner, err := acquireNetworkOwnership(state.DataDir, name)
	if err != nil {
		t.Fatalf("refused confirmed recovery or leaked failed-start handle: %v", err)
	}
	defer owner.Close()
	file, err := os.CreateTemp(t.TempDir(), "not-a-socket")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := verifyNetworkOwnership(file, name); err == nil {
		t.Fatal("ordinary file accepted as inherited network ownership")
	}
}
