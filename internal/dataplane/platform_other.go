//go:build !linux

package dataplane

import "context"

func newPlatformBackend(Options) (implementation, error) { return nil, ErrUnsupported }

func CurrentProgramID(context.Context, string) (uint32, error)  { return 0, ErrUnsupported }
func DetachOwned(context.Context, string, uint32, uint32) error { return ErrUnsupported }
