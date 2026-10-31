//go:build !linux

package control

import (
	"context"
	"errors"
)

func ServeAgent(context.Context, string, *Service) error {
	return errors.New("the privileged Unix-socket firewall agent requires Linux")
}
