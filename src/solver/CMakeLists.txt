# Phase 3 solver layer. self_check is the original link/sanity proof
# (links the bundled Z3 static library and exercises the bit-vector
# theory via SelfCheck); solver_facade is the SolverFacade from ADR 0034
# — the thin Z3 boundary that solves inverted branch-constraint systems.

add_library(fuzzer_solver STATIC
  self_check.cpp
  solver_facade.cpp
)
add_library(fuzzer::solver ALIAS fuzzer_solver)

target_include_directories(fuzzer_solver
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# libz3 is the static SMT library built from third_party/z3 via
# add_subdirectory in the root CMakeLists. It exports its C API include
# dir (src/api) transitively, but the C++ wrapper z3++.h lives in
# src/api/c++, which libz3 does not export — both are added here. They
# are marked SYSTEM so the Z3 headers stay out of -Werror/-Wpedantic and
# out of clang-tidy's scope (HeaderFilterRegex would otherwise match
# their .../src/... paths). Marking src/api SYSTEM here also overrides
# libz3's non-system INTERFACE include for the same path, so no Z3
# header is ever analysed as project code.
target_include_directories(fuzzer_solver SYSTEM PRIVATE
  ${CMAKE_SOURCE_DIR}/third_party/z3/src/api
  ${CMAKE_SOURCE_DIR}/third_party/z3/src/api/c++
)

target_link_libraries(fuzzer_solver
  PRIVATE
    # Z3 stays an implementation detail of the solver layer: PRIVATE
    # keeps z3++.h off fuzzer::solver's public API surface.
    libz3
    fuzzer::warnings
)
