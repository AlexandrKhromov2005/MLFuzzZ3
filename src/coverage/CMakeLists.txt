# Phase 2 coverage bridge core (ADR 0028 part B).
#
# CoverageReader maps the edge-coverage memfd announced by the
# execution server (via SCM_RIGHTS) and returns snapshot copies
# of the 64 KiB bitmap. The reader borrows the fd from
# fuzzer::session; ownership stays with ClientSession.

add_library(fuzzer_coverage STATIC
  coverage_reader.cpp
  branch_reader.cpp
)
add_library(fuzzer::coverage ALIAS fuzzer_coverage)

target_include_directories(fuzzer_coverage
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(fuzzer_coverage
  PUBLIC
    tl::expected
  PRIVATE
    fuzzer::warnings
)
