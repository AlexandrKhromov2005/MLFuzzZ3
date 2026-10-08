# BLOCKER, MEASURED ON THIS TREE -- READ BEFORE WRITING THE E2E ORACLE.
# This gate is UNSATISFIABLE under guard(). It is a faithful copy of the
# `a + b == MAGIC` -> `a ^ b == MAGIC`"), and that spec does not produce a
# runnable experiment:
#   MAGIC = 0xDEADBEEF has bit31 SET. guard() caps both operands at
#   HI = 0x7F000000 < 0x80000000, so bit31 of a and of b is always CLEAR.
#   xor is bitwise: bit31(a^b) = bit31(a) ^ bit31(b) = 0 ^ 0 = 0 != 1.
#   The sum escapes this because carries propagate INTO bit31; xor has no
#   carries. That asymmetry is the whole reason the two gates differ.
# Exhaustive check over every guard-admissible a in [0x01000000, 0x7F000000]
# (2113929217 values; b := a ^ MAGIC and b := MAGIC - a respectively):
#   xor solutions under guard = 0
#   sum solutions under guard = 513305822
# Consequence for the experiment: condition (ii) of the task entry (the
# crash) is unreachable for BOTH arm seeds, so `NOT-CRACKED@budget` would be
# guaranteed by the fixture arithmetic rather than by any limit of the
# solver -- the exact (i)/(ii) conflation the task entry warns against. The
# disjoint-bit ALIAS cell that task-034 exists to probe is unreachable for
# the same reason: a^b == a+b == MAGIC with a&b == 0 forces a|b == MAGIC,
# so bit31 must be set in one operand, which guard() rejects.
# Behavioural canaries on the built binary, consistent with the above:
#   sum-only  a=0x78514ad1 b=0x665c741e (overlapping bits, a+b == MAGIC)
#             -> xor_gate rc=0, add_gate rc=-6 (SIGABRT): the gates are
#             genuinely different, this copy is not an add_gate clone;
#   guard-rej a=0x11001101 b=0xcfadafee (a^b == MAGIC exactly, but a has a
#             zero byte and b is out of band) -> rc=0: the guard is live.
# Resolving this is a spec decision, not a code cleanup, so it is NOT taken
# here: lowering MAGIC below 2^31, widening HI, or xor-ing against a masked
# constant each change what the boundary cell measures and break
# comparability with the add_gate/sub_gate controls that share this guard
# byte-for-byte. Owner decision required before the e2e oracle is written.
#
# Cross-field xor gate fixture (ADR 0035, task-034): a ^ b == MAGIC over two
# verbatim u32 fields, nested inside the same guard() as add_gate and
# sub_gate. This is the BOUNDARY CELL of the pair's domain map. The map gives
# exactly this form a caveat instead of a clean answer --
# `xor=NO-BINDING(kConst; BOUND(kAddVars) only when the bits are disjoint, as
# an alias of the sum)` (docs/experiments/solver-domain-map/report.md:138,
# named in tests/unit/concolic/test_domain_map.cpp:188). Unlike the sum
# (positive control) and the difference (negative control), the outcome of
# this gate on a real target is NOT known in advance.
#
# The sources are copies of tests/fixtures/add_gate/{add_gate.c,
# gate_guard.h} (copy-based, as in task-011 and task-032): neither the
# positive control nor the canonical experiment files under
# docs/experiments/cmplog-integer-addition-recon/micro-test/ are modified.
#   - xor_gate.c differs from add_gate.c in exactly one expression,
#     `a + b == MAGIC` -> `(a ^ b) == MAGIC` (xor_gate.c:28), plus the
#     comment header naming the xor instead of the sum. Strip comments from
#     both and `diff` reports that single line. The parentheses are NOT
#     decoration and are the one place this copy could not stay literal:
#     `^` binds looser than `==` in C, so unparenthesised `a ^ b == MAGIC`
#     would compile as `a ^ (b == MAGIC)` -- a different gate entirely, and
#     one that is trivially satisfiable. The gate under test is the xor of
#     the two fields compared to MAGIC.
#   - gate_guard.h is a byte-identical copy of add_gate's, comment included
#     -- the comment is phrased for the addition case and is deliberately
#     left that way, exactly as in sub_gate. `cmp` over the three copies is
#     what keeps the guard from drifting. The guard matters more here than
#     in either control: condition (ii) of the task is that a Z3 solution
#     for `a + b == MAGIC` must ALSO survive band [0x01000000, 0x7F000000]
#     and the all-four-bytes-non-zero test (gate_guard.h:24-26) while having
#     disjoint bits, so a reworded or relaxed guard would silently change
#     what the experiment measures.
#
# Build shape, -O1 and pass order are copied from
# tests/fixtures/add_gate/CMakeLists.txt and are load-bearing there for
# reasons that carry over unchanged: clang explicitly (the project default
# C compiler may be gcc, which lacks -fpass-plugin), BranchTracePass FIRST
# so its PipelineStartEP callback only sees the fixture's own icmps,
# EdgeCoveragePass second, then linked against libmlfuzzz3_cov
# (DT_NEEDED); -O1 because the branch log is the solver's input and the
# positive control's calibrated numbers were measured at -O1
# (docs/experiments/kaddvars-solver-arm/run.sh:44). A boundary cell built
# differently from the controls it is compared against would measure the
# build, not the algebra. Self-skips when clang is absent, like add_gate
# and sub_gate.
#
# Measured on this tree rather than copied over: the object carries 13
# instrumented comparisons, the same count add_gate/CMakeLists.txt:31-37
# reports for the sum at -O1 and sub_gate/CMakeLists.txt:34-39 reports for
# the difference (`objdump -dr <fixture>.o | grep -c
# fuzzer_rt_log_branch_cmp` -> 13 for all three objects). Their
# per-function distribution was NOT re-measured here, so add_gate's
# "main 9 / nz32 4" is deliberately not restated for the xor.

find_program(MLFUZZZ3_XOR_GATE_CLANG NAMES clang)

if(NOT MLFUZZZ3_XOR_GATE_CLANG)
    message(STATUS
        "clang not found; xor_gate fixture will not be built "
        "(the xor_gate e2e oracle will self-skip)")
    return()
endif()

set(_xor_gate_src ${CMAKE_CURRENT_SOURCE_DIR}/xor_gate.c)
set(_xor_gate_bin ${CMAKE_CURRENT_BINARY_DIR}/xor_gate)
set(_xor_gate_obj ${CMAKE_CURRENT_BINARY_DIR}/xor_gate.o)

add_custom_command(
    OUTPUT ${_xor_gate_obj}
    COMMAND ${MLFUZZZ3_XOR_GATE_CLANG}
        -O1 -g
        -fpass-plugin=$<TARGET_FILE:BranchTracePass>
        -fpass-plugin=$<TARGET_FILE:EdgeCoveragePass>
        -Wall -Wextra
        -c
        ${_xor_gate_src}
        -o ${_xor_gate_obj}
    DEPENDS ${_xor_gate_src} ${CMAKE_CURRENT_SOURCE_DIR}/gate_guard.h
        BranchTracePass EdgeCoveragePass
    COMMENT "Compiling xor_gate.o with Branch+Edge passes"
    VERBATIM)

add_custom_command(
    OUTPUT ${_xor_gate_bin}
    COMMAND ${MLFUZZZ3_XOR_GATE_CLANG}
        ${_xor_gate_obj}
        $<TARGET_FILE:mlfuzzz3_cov>
        -Wl,-rpath,$<TARGET_FILE_DIR:mlfuzzz3_cov>
        -o ${_xor_gate_bin}
    DEPENDS ${_xor_gate_obj} mlfuzzz3_cov
    COMMENT "Linking xor_gate against libmlfuzzz3_cov"
    VERBATIM)

add_custom_target(xor_gate_build ALL
    DEPENDS ${_xor_gate_bin})
