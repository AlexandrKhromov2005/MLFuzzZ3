# SPDX-License-Identifier: MIT
# Value matching uses solver domain types but no solver implementation.
add_library(fuzzer_binding STATIC EXCLUDE_FROM_ALL binding_provider.cpp)
add_library(fuzzer::binding ALIAS fuzzer_binding)
target_include_directories(fuzzer_binding PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_SOURCE_DIR}/src/solver)
target_link_libraries(fuzzer_binding PUBLIC fuzzer::coverage fuzzer::mutation PRIVATE fuzzer::warnings)
if(FUZZER_BUILD_Z3)
# Phase 3 concolic orchestrator (ADR 0035 §2). Sits above the solver:
# reconstructs a cross-field constraint system from branch records, solves
# the inverted system via fuzzer::solver, and places the result back into
# the input. The three layer libraries are linked PUBLIC because the
# public header (concolic.h) includes their headers (solver_facade.h,
# branch_reader.h, fuzz_input.h) — Z3 stays PRIVATE inside fuzzer::solver,
# so none of it is re-exported here.

add_library(fuzzer_concolic STATIC
  concolic.cpp
  throttle.cpp
)
add_library(fuzzer::concolic ALIAS fuzzer_concolic)

target_include_directories(fuzzer_concolic
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(fuzzer_concolic
  PUBLIC
    fuzzer::binding
    fuzzer::solver
    fuzzer::coverage
    fuzzer::mutation
  PRIVATE
    fuzzer::warnings
)

endif()
