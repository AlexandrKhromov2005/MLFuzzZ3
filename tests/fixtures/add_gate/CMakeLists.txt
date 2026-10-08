# Cross-field addition gate fixture (ADR 0036): a + b == MAGIC over two
# verbatim u32 fields, nested inside guard() so no degenerate solution
# counts. This is the second solver-requiring target in the tree next to
# cov_xfield -- AFL++ cmplog does not take this gate (task-012: 0/9.1M
# execs), our concolic arm does.
#
# The sources are copies of
#   docs/experiments/cmplog-integer-addition-recon/micro-test/add_gate.c
#   docs/experiments/cmplog-integer-addition-recon/micro-test/gate_guard.h
# (copy-based, as in task-011): the canonical experiment files are never
# modified by the test tree. add_gate.c is byte-identical to its original.
# gate_guard.h is NOT: scripts/format.sh globs tests/**/*.h (scripts/
# format.sh:18) and this is the first fixture to carry a header, so the
# copy is clang-formatted -- indentation and one rewrapped line, no token
# changed. Both copies compile to a byte-identical object file, which is
# what the oracle depends on; strip whitespace and the header still
# matches its original exactly.
#
# gate_guard.h needs no -I -- add_gate.c includes it as "gate_guard.h",
# resolved next to the copied source.
#
# Build shape follows cov_xfield/CMakeLists.txt: clang explicitly (the
# project default C compiler may be gcc, which lacks -fpass-plugin),
# BranchTracePass FIRST so its PipelineStartEP callback only sees the
# fixture's own icmps, EdgeCoveragePass second, then linked against
# libmlfuzzz3_cov (DT_NEEDED). Self-skips when clang is absent.
#
# -O1, NOT the -O0 of cov_xfield: the 500-600 execs to crash that this
# fixture's oracle is calibrated against were measured at -O1
# (docs/experiments/kaddvars-solver-arm/run.sh:44), and the two levels do
# not produce the same branch log. guard() and nz32() are `static inline`
# (gate_guard.h:20,24); measured on this source with both passes, the 13
# instrumented comparisons are distributed as main 3 / guard 6 / nz32 4 at
# -O0, versus main 9 / nz32 4 at -O1 (guard inlined, and no `guard` symbol
# is emitted at all). Since the branch log is the solver's input, building
# at -O0 would make this oracle's numbers incomparable to the arm they are
# calibrated against.

find_program(MLFUZZZ3_ADD_GATE_CLANG NAMES clang)

if(NOT MLFUZZZ3_ADD_GATE_CLANG)
    message(STATUS
        "clang not found; add_gate fixture will not be built "
        "(the add_gate e2e oracle will self-skip)")
    return()
endif()

set(_add_gate_src ${CMAKE_CURRENT_SOURCE_DIR}/add_gate.c)
set(_add_gate_bin ${CMAKE_CURRENT_BINARY_DIR}/add_gate)
set(_add_gate_obj ${CMAKE_CURRENT_BINARY_DIR}/add_gate.o)

add_custom_command(
    OUTPUT ${_add_gate_obj}
    COMMAND ${MLFUZZZ3_ADD_GATE_CLANG}
        -O1 -g
        -fpass-plugin=$<TARGET_FILE:BranchTracePass>
        -fpass-plugin=$<TARGET_FILE:EdgeCoveragePass>
        -Wall -Wextra
        -c
        ${_add_gate_src}
        -o ${_add_gate_obj}
    DEPENDS ${_add_gate_src} ${CMAKE_CURRENT_SOURCE_DIR}/gate_guard.h
        BranchTracePass EdgeCoveragePass
    COMMENT "Compiling add_gate.o with Branch+Edge passes"
    VERBATIM)

add_custom_command(
    OUTPUT ${_add_gate_bin}
    COMMAND ${MLFUZZZ3_ADD_GATE_CLANG}
        ${_add_gate_obj}
        $<TARGET_FILE:mlfuzzz3_cov>
        -Wl,-rpath,$<TARGET_FILE_DIR:mlfuzzz3_cov>
        -o ${_add_gate_bin}
    DEPENDS ${_add_gate_obj} mlfuzzz3_cov
    COMMENT "Linking add_gate against libmlfuzzz3_cov"
    VERBATIM)

add_custom_target(add_gate_build ALL
    DEPENDS ${_add_gate_bin})
