//go:build linux

package control

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

// ServeAgent publishes the privileged control API on a private Unix socket.
// The directory must be root-owned and not group/world-writable. Its group is
// inherited by the socket, allowing a dedicated unprivileged web service with
// that group to use the narrow API. Existing socket paths are never removed.
func ServeAgent(ctx context.Context, socketPath string, service *Service) error {
	if service == nil {
		return errors.New("agent service is required")
	}
	if os.Geteuid() != 0 {
		return errors.New("the firewall agent must run as root; the web proxy runs unprivileged")
	}
	if !filepath.IsAbs(socketPath) || filepath.Clean(socketPath) != socketPath || len(socketPath) > 100 {
		return errors.New("agent socket requires a clean absolute path of at most 100 bytes")
	}
	parent := filepath.Dir(socketPath)
	if parent == "/" || filepath.Dir(parent) == "/" {
		return errors.New("agent socket requires its own dedicated directory, for example /run/wirewall")
	}
	if err := ensureAgentDirectory(parent); err != nil {
		return err
	}
	if _, err := os.Lstat(socketPath); !errors.Is(err, os.ErrNotExist) {
		return errors.New("agent socket path already exists or cannot be inspected; refusing replacement")
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		return err
	}
	listener.SetUnlinkOnClose(false)
	created, err := os.Lstat(socketPath)
	if err != nil {
		listener.Close()
		return err
	}
	defer func() {
		listener.Close()
		// Never unlink a replacement created by another process.
		if current, err := os.Lstat(socketPath); err == nil && os.SameFile(created, current) {
			_ = os.Remove(socketPath)
		}
	}()
	parentInfo, err := os.Stat(parent)
	if err != nil {
		return err
	}
	owner, ok := parentInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("cannot inspect agent directory ownership")
	}
	if err := os.Chown(socketPath, 0, int(owner.Gid)); err != nil {
		return fmt.Errorf("set agent socket group: %w", err)
	}
	if err := os.Chmod(socketPath, 0660); err != nil {
		return err
	}
	server := &http.Server{
		Handler:           NewAgentHandler(service),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 16,
		BaseContext:       func(net.Listener) context.Context { return ctx },
		ConnContext: func(connectionContext context.Context, _ net.Conn) context.Context {
			return context.WithValue(connectionContext, agentSocketContextKey{}, true)
		},
	}
	finished := make(chan struct{})
	defer close(finished)
	go func() {
		select {
		case <-ctx.Done():
			shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := server.Shutdown(shutdown); err != nil {
				_ = server.Close()
			}
		case <-finished:
		}
	}()
	err = server.Serve(&agentLimitedListener{Listener: listener, ctx: ctx, slots: make(chan struct{}, 32)})
	if errors.Is(err, http.ErrServerClosed) || ctx.Err() != nil {
		return nil
	}
	return err
}

func ensureAgentDirectory(path string) error {
	existing, existingErr := os.Lstat(path)
	if existingErr != nil && !errors.Is(existingErr, os.ErrNotExist) {
		return existingErr
	}
	// Inspect each existing component before MkdirAll: a symlinked ancestor
	// would undermine the socket permission boundary.
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err == nil {
			if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return errors.New("agent socket parent components must be real directories")
			}
			owner, ok := info.Sys().(*syscall.Stat_t)
			if !ok || owner.Uid != 0 {
				return errors.New("agent socket directory ancestors must be owned by root")
			}
			// A writable, non-sticky ancestor could let another user rename
			// the otherwise private final directory after it was inspected.
			if info.Mode().Perm()&0022 != 0 && info.Mode()&os.ModeSticky == 0 {
				return errors.New("agent socket directory ancestors must not be group/world-writable unless sticky")
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if current == filepath.Dir(current) {
			break
		}
	}
	if err := os.MkdirAll(path, 0750); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("agent socket directory is not a real directory")
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != 0 {
		return errors.New("agent socket directory must be owned by root")
	}
	if info.Mode().Perm()&0022 != 0 {
		return errors.New("agent socket directory must not be group/world-writable")
	}
	if existingErr == nil {
		if existing.Mode().Perm() != 0750 {
			return errors.New("existing agent socket directory must have mode 0750; refusing to alter unrelated directory permissions")
		}
		return nil
	}
	return os.Chmod(path, 0750)
}

// Bound the root process's connection count, including long-lived SSE streams.
// Socket permissions still limit callers to the dedicated web-service group.
type agentLimitedListener struct {
	net.Listener
	ctx   context.Context
	slots chan struct{}
}

func (listener *agentLimitedListener) Accept() (net.Conn, error) {
	select {
	case listener.slots <- struct{}{}:
	case <-listener.ctx.Done():
		return nil, listener.ctx.Err()
	}
	connection, err := listener.Listener.Accept()
	if err != nil {
		<-listener.slots
		return nil, err
	}
	return &agentLimitedConnection{Conn: connection, release: func() { <-listener.slots }}, nil
}

type agentLimitedConnection struct {
	net.Conn
	once    sync.Once
	release func()
}

func (connection *agentLimitedConnection) Close() error {
	err := connection.Conn.Close()
	connection.once.Do(connection.release)
	return err
}
