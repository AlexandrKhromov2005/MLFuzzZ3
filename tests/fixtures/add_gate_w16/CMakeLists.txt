# Field-WIDTH variant of the cross-field addition gate fixture (task-102,
# ADR-0047): the same a + b == MAGIC over two verbatim fields nested inside the
# same guard shape, with the fields 16 bits wide at offsets 0 and 2 instead of
# 32 bits wide at offsets 0 and 4. It exists to measure whether the CRASH
# BUDGET published for the 32-bit donor is a property of the gate or of the
# field width, and -- through the disarmed arm of its harness -- whether the
# gate is still solver-requiring once the pair space shrinks from 2^64 to 2^32.
# The domain map already says the BINDING for the `add` form does not depend on
# width (docs/experiments/solver-domain-form-width-endian/report.md:95,
# width_dependent_forms=xor), which is a different claim.
#
# The source is a width variant of tests/fixtures/add_gate/add_gate.c, not a
# copy: `diff -u` between the two files touches the field-decoding lines, MAGIC,
# the guard constants and the header comment.
#
# gate_guard.h is NOT included here and no -I is passed, unlike
# tests/fixtures/add_gate_be/CMakeLists.txt which shares the donor's header.
# The reason is arithmetic, not style: the donor's band starts at LO =
# 0x01000000, above the entire u16 range, so a 16-bit field can never satisfy
# it and the crash would be unreachable. The width-scaled guard therefore lives
# inside add_gate_w16.c and its scaling is documented there.
#
# Build shape is the donor's, verbatim: clang explicitly (the project default C
# compiler may be gcc, which lacks -fpass-plugin), BranchTracePass FIRST so its
# PipelineStartEP callback only sees the fixture's own icmps, EdgeCoveragePass
# second, then linked against libmlfuzzz3_cov (DT_NEEDED). Self-skips when
# clang is absent.
#
# -O1, for the donor's reason: the crash-budget numbers this fixture is
# compared against were measured at -O1, and -O0 does not produce the same
# branch log (guard() and nz16() are `static inline`, and at -O1 guard is
# inlined into main and emits no symbol of its own).

find_program(MLFUZZZ3_ADD_GATE_W16_CLANG NAMES clang)

if(NOT MLFUZZZ3_ADD_GATE_W16_CLANG)
    message(STATUS
        "clang not found; add_gate_w16 fixture will not be built "
        "(the add_gate_w16 crash-budget oracle will self-skip)")
    return()
endif()

set(_add_gate_w16_src ${CMAKE_CURRENT_SOURCE_DIR}/add_gate_w16.c)
set(_add_gate_w16_bin ${CMAKE_CURRENT_BINARY_DIR}/add_gate_w16)
set(_add_gate_w16_obj ${CMAKE_CURRENT_BINARY_DIR}/add_gate_w16.o)

add_custom_command(
    OUTPUT ${_add_gate_w16_obj}
    COMMAND ${MLFUZZZ3_ADD_GATE_W16_CLANG}
        -O1 -g
        -fpass-plugin=$<TARGET_FILE:BranchTracePass>
        -fpass-plugin=$<TARGET_FILE:EdgeCoveragePass>
        -Wall -Wextra
        -c
        ${_add_gate_w16_src}
        -o ${_add_gate_w16_obj}
    DEPENDS ${_add_gate_w16_src}
        BranchTracePass EdgeCoveragePass
    COMMENT "Compiling add_gate_w16.o with Branch+Edge passes"
    VERBATIM)

add_custom_command(
    OUTPUT ${_add_gate_w16_bin}
    COMMAND ${MLFUZZZ3_ADD_GATE_W16_CLANG}
        ${_add_gate_w16_obj}
        $<TARGET_FILE:mlfuzzz3_cov>
        -Wl,-rpath,$<TARGET_FILE_DIR:mlfuzzz3_cov>
        -o ${_add_gate_w16_bin}
    DEPENDS ${_add_gate_w16_obj} mlfuzzz3_cov
    COMMENT "Linking add_gate_w16 against libmlfuzzz3_cov"
    VERBATIM)

add_custom_target(add_gate_w16_build ALL
    DEPENDS ${_add_gate_w16_bin})
