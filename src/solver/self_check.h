#pragma once

// Phase 3 solver layer — link/sanity proof. The SolverFacade design
// (IR -> Z3) lands in ADR 0034; this slice only proves the bundled Z3
// links into a project target and reasons from our own code. SelfCheck
// builds two fixed-width bit-vector queries and verifies the solver's
// verdicts. It is not a public API and takes no input. Z3 is an
// implementation detail of this layer: z3++.h never appears in this
// header, so consumers (the unit test) link fuzzer::solver without any
// Z3 include path.

namespace mlfuzzz3::solver {

// SelfCheck returns true iff the bundled Z3 is linked and answers two
// bit-vector queries correctly: a satisfiable unsigned range
// (5 < x < 10) reports sat and an unsatisfiable one (x > 7 and x < 3)
// reports unsat. Any Z3 error (including a failure to construct the
// context) yields false. Unsigned bit-vector relations are used on
// purpose, so a true result proves Z3 reasons over fixed-width machine
// words rather than unbounded integers.
[[nodiscard]] bool SelfCheck();

}  // namespace mlfuzzz3::solver
