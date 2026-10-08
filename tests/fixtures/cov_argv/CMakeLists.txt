# argv-driven crash fixture for the --target-args E2E (ADR 0040).
# Same build shape as cov_crash (clang + EdgeCoveragePass +
# libmlfuzzz3_cov via DT_NEEDED): the program crashes only when the
# "crash" argument is delivered, otherwise it exits 0 for any input.
#
# Built via add_custom_command rather than add_executable +
# mlfuzzz3_instrument_target() because the project's default C
# compiler may be gcc (no -fpass-plugin support); the existing
# fixture pattern invokes clang explicitly.

find_program(MLFUZZZ3_COV_ARGV_CLANG NAMES clang)

if(NOT MLFUZZZ3_COV_ARGV_CLANG)
    message(STATUS
        "clang not found; cov_argv_target will not be "
        "built (--target-args e2e test will self-skip)")
    return()
endif()

set(_cov_argv_bin
    ${CMAKE_CURRENT_BINARY_DIR}/cov_argv_target)
set(_cov_argv_obj
    ${CMAKE_CURRENT_BINARY_DIR}/cov_argv_target.o)
set(_cov_argv_src
    ${CMAKE_CURRENT_SOURCE_DIR}/cov_argv_target.c)

add_custom_command(
    OUTPUT ${_cov_argv_obj}
    COMMAND ${MLFUZZZ3_COV_ARGV_CLANG}
        -O0 -g
        -fpass-plugin=$<TARGET_FILE:EdgeCoveragePass>
        -Wall -Wextra
        -c
        ${_cov_argv_src}
        -o ${_cov_argv_obj}
    DEPENDS ${_cov_argv_src} EdgeCoveragePass
    COMMENT "Compiling cov_argv_target.o with EdgeCoveragePass"
    VERBATIM)

add_custom_command(
    OUTPUT ${_cov_argv_bin}
    COMMAND ${MLFUZZZ3_COV_ARGV_CLANG}
        ${_cov_argv_obj}
        $<TARGET_FILE:mlfuzzz3_cov>
        -Wl,-rpath,$<TARGET_FILE_DIR:mlfuzzz3_cov>
        -o ${_cov_argv_bin}
    DEPENDS ${_cov_argv_obj} mlfuzzz3_cov
    COMMENT "Linking cov_argv_target against libmlfuzzz3_cov"
    VERBATIM)

add_custom_target(cov_argv_build ALL
    DEPENDS ${_cov_argv_bin})
