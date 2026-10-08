# mlfuzzz3 Stage 2 instrumentation integration (ADR 0024).
#
# Defines mlfuzzz3_instrument_target(<target>) — the minimal
# CMake-side hook that wires the project's own LLVM edge-coverage
# pass into a target's build. Stage 3 (ADR 0017 §Subdivision) will
# absorb this into a full add_fuzz_target macro.
#
# What it does:
#   1. Adds -fpass-plugin=$<TARGET_FILE:EdgeCoveragePass> to the
#      target's compile options. The plugin .so is built by
#      src/instrumentation/edge_coverage_pass/CMakeLists.txt.
#   2. Links the target against libmlfuzzz3_cov so the inline IR
#      emitted by the pass (load ptr @__mlfuzzz3_cov_map, ...)
#      resolves at link time and the bitmap pointer is set by
#      the runtime's constructor at process start.
#   3. Adds explicit build-order dependencies on EdgeCoveragePass
#      (the .so must exist before the target's TU is compiled) and
#      on mlfuzzz3_cov.
#
# Toolchain requirement (caller's responsibility): -fpass-plugin
# is a clang flag (LLVM 20 per ADR 0024 §Toolchain pinning). The
# target's C/CXX compiler must be clang 20.

function(mlfuzzz3_instrument_target target)
    if(NOT TARGET EdgeCoveragePass)
        message(FATAL_ERROR
            "mlfuzzz3_instrument_target(${target}): EdgeCoveragePass "
            "target not defined. Ensure src/instrumentation has been "
            "added before calling this function.")
    endif()
    if(NOT TARGET mlfuzzz3_cov)
        message(FATAL_ERROR
            "mlfuzzz3_instrument_target(${target}): mlfuzzz3_cov "
            "runtime target not defined. Ensure src/runtime has "
            "been added before calling this function.")
    endif()

    target_compile_options(${target} PRIVATE
        -fpass-plugin=$<TARGET_FILE:EdgeCoveragePass>)
    target_link_libraries(${target} PRIVATE mlfuzzz3_cov)
    add_dependencies(${target} EdgeCoveragePass mlfuzzz3_cov)
endfunction()
