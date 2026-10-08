# Test fixture for Stage 2 coverage instrumentation
# validation (ADR 0024). Compiled with
# -fpass-plugin=$<TARGET_FILE:EdgeCoveragePass> so the
# project's own ModulePass inlines AFL-style XOR +
# saturating 8-bit increment directly. Bitmap pointer
# resolved through the exported __mlfuzzz3_cov_map
# symbol in libmlfuzzz3_cov (DT_NEEDED linkage; env
# activation via MLFUZZZ3_COV_FD).
#
# The project's default C compiler may be gcc, which
# does not support -fpass-plugin. We require clang for
# this fixture and invoke it via a custom command so the
# rest of the build is unaffected. If clang is
# unavailable, the target is skipped; Go E2E test will
# t.Skip.

find_program(MLFUZZZ3_COV_CLANG NAMES clang)

if(NOT MLFUZZZ3_COV_CLANG)
    message(STATUS
        "clang not found; cov_simple_target will not be "
        "built (Go E2E coverage test will t.Skip)")
    return()
endif()

set(_cov_target_bin
    ${CMAKE_CURRENT_BINARY_DIR}/cov_simple_target)
set(_cov_target_obj
    ${CMAKE_CURRENT_BINARY_DIR}/cov_simple_target.o)
set(_cov_target_src
    ${CMAKE_CURRENT_SOURCE_DIR}/cov_simple_target.c)

# Compile with the project's EdgeCoveragePass; link
# against libmlfuzzz3_cov so the inline IR's external
# reference to __mlfuzzz3_cov_map resolves through the
# library's exported symbol (DT_NEEDED + rpath). No
# LD_PRELOAD is required for symbol resolution; the
# runtime's constructor activates the bitmap when
# MLFUZZZ3_COV_FD is set in the environment.
add_custom_command(
    OUTPUT ${_cov_target_obj}
    COMMAND ${MLFUZZZ3_COV_CLANG}
        -O0 -g
        -fpass-plugin=$<TARGET_FILE:EdgeCoveragePass>
        -Wall -Wextra
        -c
        ${_cov_target_src}
        -o ${_cov_target_obj}
    DEPENDS ${_cov_target_src} EdgeCoveragePass
    COMMENT "Compiling cov_simple_target.o with EdgeCoveragePass"
    VERBATIM)

add_custom_command(
    OUTPUT ${_cov_target_bin}
    COMMAND ${MLFUZZZ3_COV_CLANG}
        ${_cov_target_obj}
        $<TARGET_FILE:mlfuzzz3_cov>
        -Wl,-rpath,$<TARGET_FILE_DIR:mlfuzzz3_cov>
        -o ${_cov_target_bin}
    DEPENDS ${_cov_target_obj} mlfuzzz3_cov
    COMMENT "Linking cov_simple_target against libmlfuzzz3_cov"
    VERBATIM)

# Logical target name differs from output binary name to
# avoid ninja's "phony target named the same as a file"
# conflict. The binary on disk is `cov_simple_target`
# (consumed by the Go E2E test); the build target is
# `cov_simple_build`.
add_custom_target(cov_simple_build ALL
    DEPENDS ${_cov_target_bin})
