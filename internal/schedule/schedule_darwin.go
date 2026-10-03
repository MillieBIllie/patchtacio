package schedule

// New returns the scheduler for this operating system.
func New(o Options) Scheduler { return &Darwin{O: o} }
