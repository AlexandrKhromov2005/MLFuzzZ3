# Crashing test target for end-to-end crash-path validation
# (ADR 0029). Same build shape as cov_stdin (clang +
# EdgeCoveragePass + libmlfuzzz3_cov via DT_NEEDED), but the
# program aborts on any high-bit-set first byte so a byte-flip
# campaign deterministically reaches EXEC_STATUS_CRASH.
#
# Built via add_custom_command rather than add_executable +
# mlfuzzz3_instrument_target() because the project's default C
# compiler may be gcc (no -fpass-plugin support); the existing
# fixture pattern invokes clang explicitly.

find_program(MLFUZZZ3_COV_CRASH_CLANG NAMES clang)

if(NOT MLFUZZZ3_COV_CRASH_CLANG)
    message(STATUS
        "clang not found; cov_crash_target will not be "
        "built (crash-path e2e test will self-skip)")
    return()
endif()

set(_cov_crash_bin
    ${CMAKE_CURRENT_BINARY_DIR}/cov_crash_target)
set(_cov_crash_obj
    ${CMAKE_CURRENT_BINARY_DIR}/cov_crash_target.o)
set(_cov_crash_src
    ${CMAKE_CURRENT_SOURCE_DIR}/cov_crash_target.c)

add_custom_command(
    OUTPUT ${_cov_crash_obj}
    COMMAND ${MLFUZZZ3_COV_CRASH_CLANG}
        -O0 -g
        -fpass-plugin=$<TARGET_FILE:EdgeCoveragePass>
        -Wall -Wextra
        -c
        ${_cov_crash_src}
        -o ${_cov_crash_obj}
    DEPENDS ${_cov_crash_src} EdgeCoveragePass
    COMMENT "Compiling cov_crash_target.o with EdgeCoveragePass"
    VERBATIM)

add_custom_command(
    OUTPUT ${_cov_crash_bin}
    COMMAND ${MLFUZZZ3_COV_CRASH_CLANG}
        ${_cov_crash_obj}
        $<TARGET_FILE:mlfuzzz3_cov>
        -Wl,-rpath,$<TARGET_FILE_DIR:mlfuzzz3_cov>
        -o ${_cov_crash_bin}
    DEPENDS ${_cov_crash_obj} mlfuzzz3_cov
    COMMENT "Linking cov_crash_target against libmlfuzzz3_cov"
    VERBATIM)

add_custom_target(cov_crash_build ALL
    DEPENDS ${_cov_crash_bin})
