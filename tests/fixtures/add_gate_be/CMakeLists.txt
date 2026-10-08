# Big-endian variant of the cross-field addition gate fixture (task-080,
# ADR-0047): the same a + b == MAGIC over two verbatim u32 fields at the same
# offsets 0 and 4, nested inside the same guard(), with the fields decoded
# big-endian instead of host order. It exists to measure whether the CRASH
# BUDGET published for the little-endian donor carries across byte order; the
# domain map (docs/experiments/solver-domain-form-width-endian/) already says
# the BINDING does, which is a different claim.
#
# The source is a byte-order variant of tests/fixtures/add_gate/add_gate.c,
# not a copy: `diff -u` between the two files touches only the field-decoding
# lines, the load_be32() helper and the header comment.
#
# gate_guard.h is NOT copied here. This fixture includes the donor's file
# directly (-I ../add_gate), so "same guard" is a property of the build, not a
# claim about two copies staying in sync; a change to the donor header would
# change both fixtures at once. The donor resolves the header next to its own
# source and needs no -I (tests/fixtures/add_gate/CMakeLists.txt), which is why
# the flag appears here and not there.
#
# Build shape is the donor's, verbatim: clang explicitly (the project default C
# compiler may be gcc, which lacks -fpass-plugin), BranchTracePass FIRST so its
# PipelineStartEP callback only sees the fixture's own icmps, EdgeCoveragePass
# second, then linked against libmlfuzzz3_cov (DT_NEEDED). Self-skips when
# clang is absent.
#
# -O1, for the donor's reason: the crash-budget numbers this fixture is
# compared against were measured at -O1, and -O0 does not produce the same
# branch log (guard() and nz32() are `static inline`). load_be32() is likewise
# `static inline` and carries no comparison of its own, so it contributes no
# instrumented branch at either level.

find_program(MLFUZZZ3_ADD_GATE_BE_CLANG NAMES clang)

if(NOT MLFUZZZ3_ADD_GATE_BE_CLANG)
    message(STATUS
        "clang not found; add_gate_be fixture will not be built "
        "(the add_gate_be e2e oracle will self-skip)")
    return()
endif()

set(_add_gate_be_src ${CMAKE_CURRENT_SOURCE_DIR}/add_gate_be.c)
set(_add_gate_be_guard_dir ${CMAKE_CURRENT_SOURCE_DIR}/../add_gate)
set(_add_gate_be_bin ${CMAKE_CURRENT_BINARY_DIR}/add_gate_be)
set(_add_gate_be_obj ${CMAKE_CURRENT_BINARY_DIR}/add_gate_be.o)

add_custom_command(
    OUTPUT ${_add_gate_be_obj}
    COMMAND ${MLFUZZZ3_ADD_GATE_BE_CLANG}
        -O1 -g
        -fpass-plugin=$<TARGET_FILE:BranchTracePass>
        -fpass-plugin=$<TARGET_FILE:EdgeCoveragePass>
        -Wall -Wextra
        -I ${_add_gate_be_guard_dir}
        -c
        ${_add_gate_be_src}
        -o ${_add_gate_be_obj}
    DEPENDS ${_add_gate_be_src} ${_add_gate_be_guard_dir}/gate_guard.h
        BranchTracePass EdgeCoveragePass
    COMMENT "Compiling add_gate_be.o with Branch+Edge passes"
    VERBATIM)

add_custom_command(
    OUTPUT ${_add_gate_be_bin}
    COMMAND ${MLFUZZZ3_ADD_GATE_BE_CLANG}
        ${_add_gate_be_obj}
        $<TARGET_FILE:mlfuzzz3_cov>
        -Wl,-rpath,$<TARGET_FILE_DIR:mlfuzzz3_cov>
        -o ${_add_gate_be_bin}
    DEPENDS ${_add_gate_be_obj} mlfuzzz3_cov
    COMMENT "Linking add_gate_be against libmlfuzzz3_cov"
    VERBATIM)

add_custom_target(add_gate_be_build ALL
    DEPENDS ${_add_gate_be_bin})
