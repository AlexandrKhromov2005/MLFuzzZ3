# Cross-field subtraction gate fixture (ADR 0036, task-032): a - b == MAGIC
# over two verbatim u32 fields, nested inside the same guard() as add_gate.
# This is the NEGATIVE control of the pair. The solver domain map calls the
# difference NO-BINDING (docs/experiments/solver-domain-map/report.md:138)
# where it calls the sum BOUND, and that verdict was obtained from direct
# BuildSystem calls, never on a target. This fixture is what lets the
# prediction be checked end-to-end against the positive control.
#
# The sources are copies of tests/fixtures/add_gate/{add_gate.c,
# gate_guard.h} (copy-based, as in task-011): the positive control is not
# modified by the negative one, and neither are the canonical experiment
# files under docs/experiments/cmplog-integer-addition-recon/micro-test/.
#   - sub_gate.c differs from add_gate.c in exactly one operator,
#     `a + b == MAGIC` -> `a - b == MAGIC` (sub_gate.c:25), plus the
#     comment header naming the difference instead of the sum. Strip
#     comments from both and `diff` reports that single line.
#   - gate_guard.h is a byte-identical copy, comment included -- the
#     comment is phrased for the addition case and is deliberately left
#     that way. `cmp` over the pair is what keeps the guard from drifting;
#     a reworded copy would compile the same but stop being checkable.
#
# Build shape, -O1 and pass order are copied from
# tests/fixtures/add_gate/CMakeLists.txt and are load-bearing there for
# reasons that carry over unchanged: clang explicitly (the project default
# C compiler may be gcc, which lacks -fpass-plugin), BranchTracePass FIRST
# so its PipelineStartEP callback only sees the fixture's own icmps,
# EdgeCoveragePass second, then linked against libmlfuzzz3_cov
# (DT_NEEDED); -O1 because the branch log is the solver's input and the
# positive control's calibrated numbers were measured at -O1
# (docs/experiments/kaddvars-solver-arm/run.sh:44). A negative control
# built differently from the positive one would measure the build, not the
# algebra. Self-skips when clang is absent, like add_gate.
#
# Measured on this tree rather than copied over: the object carries 13
# instrumented comparisons, the same count add_gate/CMakeLists.txt:31-37
# reports for the sum at -O1 (`objdump -dr <fixture>.o | grep -c
# fuzzer_rt_log_branch_cmp` -> 13 for both objects). Their per-function
# distribution was NOT re-measured here, so add_gate's "main 9 / nz32 4"
# is deliberately not restated for the difference.

find_program(MLFUZZZ3_SUB_GATE_CLANG NAMES clang)

if(NOT MLFUZZZ3_SUB_GATE_CLANG)
    message(STATUS
        "clang not found; sub_gate fixture will not be built "
        "(the sub_gate e2e oracle will self-skip)")
    return()
endif()

set(_sub_gate_src ${CMAKE_CURRENT_SOURCE_DIR}/sub_gate.c)
set(_sub_gate_bin ${CMAKE_CURRENT_BINARY_DIR}/sub_gate)
set(_sub_gate_obj ${CMAKE_CURRENT_BINARY_DIR}/sub_gate.o)

add_custom_command(
    OUTPUT ${_sub_gate_obj}
    COMMAND ${MLFUZZZ3_SUB_GATE_CLANG}
        -O1 -g
        -fpass-plugin=$<TARGET_FILE:BranchTracePass>
        -fpass-plugin=$<TARGET_FILE:EdgeCoveragePass>
        -Wall -Wextra
        -c
        ${_sub_gate_src}
        -o ${_sub_gate_obj}
    DEPENDS ${_sub_gate_src} ${CMAKE_CURRENT_SOURCE_DIR}/gate_guard.h
        BranchTracePass EdgeCoveragePass
    COMMENT "Compiling sub_gate.o with Branch+Edge passes"
    VERBATIM)

add_custom_command(
    OUTPUT ${_sub_gate_bin}
    COMMAND ${MLFUZZZ3_SUB_GATE_CLANG}
        ${_sub_gate_obj}
        $<TARGET_FILE:mlfuzzz3_cov>
        -Wl,-rpath,$<TARGET_FILE_DIR:mlfuzzz3_cov>
        -o ${_sub_gate_bin}
    DEPENDS ${_sub_gate_obj} mlfuzzz3_cov
    COMMENT "Linking sub_gate against libmlfuzzz3_cov"
    VERBATIM)

add_custom_target(sub_gate_build ALL
    DEPENDS ${_sub_gate_bin})
