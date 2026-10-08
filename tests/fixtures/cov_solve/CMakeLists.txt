# Solver-necessary fixture (ADR 0034 prep — PROVISIONAL). Same build
# shape as branch_icmp: built with clang explicitly (the project default
# C compiler may be gcc, which lacks -fpass-plugin), instrumented with the
# branch pass FIRST and the edge pass second, then linked against
# libmlfuzzz3_cov (DT_NEEDED). Self-skips when clang is absent (the
# solver-prep smoke test self-skips too).
#
# The branch plugin is loaded first so its PipelineStartEP callback runs
# before the edge pass and only sees the fixture's own icmps, never the
# edge pass's inserted saturating-compare. So the branch log holds exactly
# the four user comparisons while edge coverage is collected on the same
# run.

find_program(MLFUZZZ3_COV_SOLVE_CLANG NAMES clang)

if(NOT MLFUZZZ3_COV_SOLVE_CLANG)
    message(STATUS
        "clang not found; cov_solve fixture will not be built "
        "(solver-prep smoke test will self-skip)")
    return()
endif()

set(_cov_solve_src ${CMAKE_CURRENT_SOURCE_DIR}/cov_solve_target.c)
set(_cov_solve_bin ${CMAKE_CURRENT_BINARY_DIR}/cov_solve_target)
set(_cov_solve_obj ${CMAKE_CURRENT_BINARY_DIR}/cov_solve_target.o)

add_custom_command(
    OUTPUT ${_cov_solve_obj}
    COMMAND ${MLFUZZZ3_COV_SOLVE_CLANG}
        -O0 -g
        -fpass-plugin=$<TARGET_FILE:BranchTracePass>
        -fpass-plugin=$<TARGET_FILE:EdgeCoveragePass>
        -Wall -Wextra
        -c
        ${_cov_solve_src}
        -o ${_cov_solve_obj}
    DEPENDS ${_cov_solve_src} BranchTracePass EdgeCoveragePass
    COMMENT "Compiling cov_solve_target.o with Branch+Edge passes"
    VERBATIM)

add_custom_command(
    OUTPUT ${_cov_solve_bin}
    COMMAND ${MLFUZZZ3_COV_SOLVE_CLANG}
        ${_cov_solve_obj}
        $<TARGET_FILE:mlfuzzz3_cov>
        -Wl,-rpath,$<TARGET_FILE_DIR:mlfuzzz3_cov>
        -o ${_cov_solve_bin}
    DEPENDS ${_cov_solve_obj} mlfuzzz3_cov
    COMMENT "Linking cov_solve_target against libmlfuzzz3_cov"
    VERBATIM)

add_custom_target(cov_solve_build ALL
    DEPENDS ${_cov_solve_bin})
