//go:build !linux && !darwin && !windows

package schedule

import "context"

// New returns a scheduler that explains scheduling is not supported here.
func New(Options) Scheduler { return unsupported{} }

type unsupported struct{}

func (unsupported) Install(context.Context, Job) (Result, error) { return Result{}, ErrUnsupported }
func (unsupported) Uninstall(context.Context) ([]string, error)  { return nil, nil }
func (unsupported) Status(context.Context) (Status, error)       { return Status{}, nil }
func (unsupported) RunNow(context.Context) error                 { return ErrUnsupported }
