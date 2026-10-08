// Package crashrec persists reproducible-outcome artifacts
// (input bytes + metadata JSON) to disk so operators and
// the corpus manager can replay crashes and hangs.
//
// This is the Phase 1 baseline per ADR 0014. Stderr capture
// and stack-hash dedupe described in the placeholder vision
// are Phase 1.5 work — baseline lacks the prerequisites
// (worker.Pool does not capture target stderr).
//
// Thread-safe; no-op when Config.Dir is empty. Errors are
// logged as warnings, not propagated — recording is
// best-effort and never blocks fuzzing progress.
//
// See docs/DECISIONS/0014-crash-recorder-baseline.md for
// the full rationale, layout specification, and migration
// plan.
package crashrec
