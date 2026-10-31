//go:build linux

package control

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"golang.org/x/sys/unix"
)

func startGuardProcess(executable, path string, logFile *os.File, owner *NetworkOwnership) (*exec.Cmd, error) {
	command := exec.Command(executable, "rollback-guard", "--state", path, "--network-lock-fd", "3")
	command.Stdin = nil
	command.Stdout, command.Stderr = logFile, logFile
	command.ExtraFiles = []*os.File{owner.file}
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := command.Start(); err != nil {
		return nil, err
	}
	return command, nil
}

func openNetworkOwnership(name string) (*os.File, error) {
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	if err := unix.Bind(fd, &unix.SockaddrUnix{Name: name}); err != nil {
		_ = unix.Close(fd)
		if errors.Is(err, unix.EADDRINUSE) {
			return nil, errors.New("another WireWall daemon or rollback watchdog still owns this network namespace; wait for recovery before restarting")
		}
		return nil, fmt.Errorf("claim WireWall network ownership: %w", err)
	}
	return os.NewFile(uintptr(fd), "wirewall-network-ownership"), nil
}

func verifyNetworkOwnership(file *os.File, name string) error {
	address, err := unix.Getsockname(int(file.Fd()))
	if err != nil {
		return fmt.Errorf("inspect inherited network ownership: %w", err)
	}
	local, ok := address.(*unix.SockaddrUnix)
	if !ok || local.Name != name {
		return errors.New("rollback watchdog did not inherit the WireWall network ownership socket")
	}
	typeID, err := unix.GetsockoptInt(int(file.Fd()), unix.SOL_SOCKET, unix.SO_TYPE)
	if err != nil || typeID != unix.SOCK_DGRAM {
		return errors.New("rollback watchdog inherited an invalid network ownership socket type")
	}
	// ExtraFiles deliberately clears close-on-exec while starting this guard.
	// Reinstate it before nft/ip helpers can inherit an unrelated lifetime lease.
	flags, err := unix.FcntlInt(file.Fd(), unix.F_GETFD, 0)
	if err != nil {
		return fmt.Errorf("inspect ownership handle flags: %w", err)
	}
	if _, err := unix.FcntlInt(file.Fd(), unix.F_SETFD, flags|unix.FD_CLOEXEC); err != nil {
		return fmt.Errorf("protect ownership handle from helper inheritance: %w", err)
	}
	return nil
}
