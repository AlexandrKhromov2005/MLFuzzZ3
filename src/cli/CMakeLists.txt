# CLI argument parser, factored out of main.cpp so ParseArgs/Args are
# unit-testable in isolation (ADR 0040). The Args struct surfaces
# core::kDefaultMaxDetSteps, so the include path to fuzzer::core
# propagates publicly to consumers (fuzzer, the unit test).
add_library(fuzzer_cli_args STATIC
  args.cpp
)
add_library(fuzzer::cli_args ALIAS fuzzer_cli_args)

target_include_directories(fuzzer_cli_args
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(fuzzer_cli_args
  PUBLIC
    # args.h includes campaign.h for core::kDefaultMaxDetSteps.
    fuzzer::core
  PRIVATE
    fuzzer::warnings
)

add_executable(fuzzer
  main.cpp
  exec_server_process.cpp
)

target_link_libraries(fuzzer
  PRIVATE
    fuzzer::cli_args
    fuzzer::core
    fuzzer::common
    fuzzer::session
    fuzzer::mutation
    fuzzer::warnings
)

# Short git revision for the metrics run id (ADR 0029). Captured at
# configure time; falls back to "unknown" outside a git checkout so the
# build never depends on git being present.
execute_process(
  COMMAND git -C ${CMAKE_SOURCE_DIR} rev-parse --short HEAD
  OUTPUT_VARIABLE _git_sha
  OUTPUT_STRIP_TRAILING_WHITESPACE
  ERROR_QUIET
  RESULT_VARIABLE _git_sha_result)
if(NOT _git_sha_result EQUAL 0 OR _git_sha STREQUAL "")
  set(_git_sha "unknown")
endif()

target_compile_definitions(fuzzer
  PRIVATE
    MLFUZZZ3_GIT_SHA="${_git_sha}")
