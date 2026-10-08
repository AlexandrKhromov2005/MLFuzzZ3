// Package worker implements the Execution Server's fork-based
// worker pool, which runs target binaries for each fuzzing
// input.
//
// This is the Phase 1 baseline per ADR 0011: a conventional
// AFL-style model where os/exec.Command spawns a new target
// process for every Execute call. The persistent-mode design
// described in Architecture Doc §4 is deferred to Phase 1.5,
// when LLVM instrumentation provides the reset hook that
// persistent mode requires. The Pool.Execute API is
// intentionally stable across that transition — the
// implementation changes, the interface does not.
//
// See docs/DECISIONS/0011-fork-based-worker-pool-baseline.md
// for the full rationale and migration plan.
package worker
