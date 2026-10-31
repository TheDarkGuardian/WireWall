//go:build !linux

package control

import (
	"errors"
	"os"
	"os/exec"
)

func startGuardProcess(string, string, *os.File, *NetworkOwnership) (*exec.Cmd, error) {
	return nil, errors.New("rollback watchdog process requires Linux")
}

func openNetworkOwnership(string) (*os.File, error) {
	return nil, errors.New("network ownership requires Linux")
}

func verifyNetworkOwnership(*os.File, string) error {
	return errors.New("network ownership requires Linux")
}
