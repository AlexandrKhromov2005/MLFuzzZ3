# Cross-field Z3-necessary fixture (ADR 0035). Same build shape as
# branch_icmp/cov_solve: built with clang explicitly (the project default
# C compiler may be gcc, which lacks -fpass-plugin), instrumented with the
# branch pass FIRST and the edge pass second, then linked against
# libmlfuzzz3_cov (DT_NEEDED). Self-skips when clang is absent (the
# cross-field smoke test self-skips too).
#
# The branch plugin is loaded first so its PipelineStartEP callback runs
# before the edge pass and only sees the fixture's own icmps, never the
# edge pass's inserted saturating-compare. So the branch log holds exactly
# the four user comparisons while edge coverage is collected on the same
# run.

find_program(MLFUZZZ3_COV_XFIELD_CLANG NAMES clang)

if(NOT MLFUZZZ3_COV_XFIELD_CLANG)
    message(STATUS
        "clang not found; cov_xfield fixture will not be built "
        "(cross-field smoke test will self-skip)")
    return()
endif()

set(_cov_xfield_src ${CMAKE_CURRENT_SOURCE_DIR}/cov_xfield_target.c)
set(_cov_xfield_bin ${CMAKE_CURRENT_BINARY_DIR}/cov_xfield_target)
set(_cov_xfield_obj ${CMAKE_CURRENT_BINARY_DIR}/cov_xfield_target.o)

add_custom_command(
    OUTPUT ${_cov_xfield_obj}
    COMMAND ${MLFUZZZ3_COV_XFIELD_CLANG}
        -O0 -g
        -fpass-plugin=$<TARGET_FILE:BranchTracePass>
        -fpass-plugin=$<TARGET_FILE:EdgeCoveragePass>
        -Wall -Wextra
        -c
        ${_cov_xfield_src}
        -o ${_cov_xfield_obj}
    DEPENDS ${_cov_xfield_src} BranchTracePass EdgeCoveragePass
    COMMENT "Compiling cov_xfield_target.o with Branch+Edge passes"
    VERBATIM)

add_custom_command(
    OUTPUT ${_cov_xfield_bin}
    COMMAND ${MLFUZZZ3_COV_XFIELD_CLANG}
        ${_cov_xfield_obj}
        $<TARGET_FILE:mlfuzzz3_cov>
        -Wl,-rpath,$<TARGET_FILE_DIR:mlfuzzz3_cov>
        -o ${_cov_xfield_bin}
    DEPENDS ${_cov_xfield_obj} mlfuzzz3_cov
    COMMENT "Linking cov_xfield_target against libmlfuzzz3_cov"
    VERBATIM)

add_custom_target(cov_xfield_build ALL
    DEPENDS ${_cov_xfield_bin})
