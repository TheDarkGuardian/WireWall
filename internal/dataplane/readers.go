package dataplane

const maxRetiredGenerations = 8

// Each XDP invocation increments its CPU's active count before looking up the
// outer policy map and decrements it after its final decision. XDP execution
// does not migrate between CPUs. A post-publication scan can observe CPUs at
// different times: once a CPU is observed at zero, every invocation there that
// could have obtained the previous policy reference has finished. Invocations
// starting afterwards can obtain only the newly published policy.
//
// If any CPU is busy, cleanup is conservatively deferred. The bounded retired
// generation count and bounded maps reject further staging instead of deleting
// state while a retired reader may still depend on it. An empty observation is
// never considered proof of quiescence.
func readersQuiescent(active []uint64) bool {
	if len(active) == 0 {
		return false
	}
	for _, count := range active {
		if count != 0 {
			return false
		}
	}
	return true
}
