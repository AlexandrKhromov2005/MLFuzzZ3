# Test target for coverage validation. Reads stdin,
# branches on first byte, mirrors the cov_simple shape
# but matches worker.Pool's runOnce contract (cmd.Stdin
# = input).
#
# Compiled with -fpass-plugin=$<TARGET_FILE:
# EdgeCoveragePass> (ADR 0024); the project's own
# ModulePass inlines AFL-style XOR + saturating 8-bit
# increment directly. Bitmap pointer resolved through
# the exported __mlfuzzz3_cov_map symbol in
# libmlfuzzz3_cov (DT_NEEDED linkage; env activation
# via MLFUZZZ3_COV_FD).
#
# Built via add_custom_command rather than add_executable
# + mlfuzzz3_instrument_target() because the project's
# default C compiler may be gcc (no -fpass-plugin
# support); the existing fixture pattern bypasses
# CMAKE_C_COMPILER by invoking clang explicitly. The
# mlfuzzz3_instrument_target() function (cmake/
# MLFuzzZ3Instrument.cmake) remains the canonical
# integration hook for callers whose toolchain is clang
# at the CMake level.

find_program(MLFUZZZ3_COV_STDIN_CLANG NAMES clang)

if(NOT MLFUZZZ3_COV_STDIN_CLANG)
    message(STATUS
        "clang not found; cov_stdin_target will not be "
        "built (Go pool coverage test will t.Skip)")
    return()
endif()

set(_cov_stdin_bin
    ${CMAKE_CURRENT_BINARY_DIR}/cov_stdin_target)
set(_cov_stdin_obj
    ${CMAKE_CURRENT_BINARY_DIR}/cov_stdin_target.o)
set(_cov_stdin_src
    ${CMAKE_CURRENT_SOURCE_DIR}/cov_stdin_target.c)

add_custom_command(
    OUTPUT ${_cov_stdin_obj}
    COMMAND ${MLFUZZZ3_COV_STDIN_CLANG}
        -O0 -g
        -fpass-plugin=$<TARGET_FILE:EdgeCoveragePass>
        -Wall -Wextra
        -c
        ${_cov_stdin_src}
        -o ${_cov_stdin_obj}
    DEPENDS ${_cov_stdin_src} EdgeCoveragePass
    COMMENT "Compiling cov_stdin_target.o with EdgeCoveragePass"
    VERBATIM)

add_custom_command(
    OUTPUT ${_cov_stdin_bin}
    COMMAND ${MLFUZZZ3_COV_STDIN_CLANG}
        ${_cov_stdin_obj}
        $<TARGET_FILE:mlfuzzz3_cov>
        -Wl,-rpath,$<TARGET_FILE_DIR:mlfuzzz3_cov>
        -o ${_cov_stdin_bin}
    DEPENDS ${_cov_stdin_obj} mlfuzzz3_cov
    COMMENT "Linking cov_stdin_target against libmlfuzzz3_cov"
    VERBATIM)

add_custom_target(cov_stdin_build ALL
    DEPENDS ${_cov_stdin_bin})
