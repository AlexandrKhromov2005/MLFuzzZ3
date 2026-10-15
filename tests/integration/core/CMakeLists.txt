# End-to-end MVP campaign integration test (ADR 0029).
#
# Drives the real `fuzzer` CLI binary against the pass-instrumented
# cov_stdin fixture. The CLI brings up a real exec-server subprocess and
# runs a bounded mutation campaign; the test asserts the corpus grows
# and metrics.jsonl is written.
#
# Reuses the shared exec_server_bin target (built by the coverage
# integration subdirectory, processed first) and the cov_stdin_build /
# mlfuzzz3_cov fixtures. Self-skips when any artifact is unavailable.

if(NOT TARGET mlfuzzz3_cov)
    message(STATUS
        "mlfuzzz3_cov target absent; "
        "test_campaign_e2e will not be built")
    return()
endif()

if(NOT TARGET cov_stdin_build)
    message(STATUS
        "cov_stdin_build target absent; "
        "test_campaign_e2e will not be built")
    return()
endif()

if(NOT TARGET exec_server_bin)
    message(STATUS
        "exec_server_bin target absent (go unavailable); "
        "test_campaign_e2e will not be built")
    return()
endif()

add_executable(test_campaign_e2e
    test_campaign_e2e.cpp)

add_dependencies(test_campaign_e2e
    fuzzer
    exec_server_bin
    cov_stdin_build
    cov_crash_build
    cov_parser_build
    cov_argv_build)

target_link_libraries(test_campaign_e2e
    PRIVATE
        fuzzer::warnings
        GTest::gtest_main)

target_compile_definitions(test_campaign_e2e
    PRIVATE
        FUZZER_BIN="$<TARGET_FILE:fuzzer>"
        EXEC_SERVER_BIN="${CMAKE_BINARY_DIR}/exec-server-bin"
        COV_STDIN_BIN="${CMAKE_BINARY_DIR}/tests/fixtures/cov_stdin/cov_stdin_target"
        COV_CRASH_BIN="${CMAKE_BINARY_DIR}/tests/fixtures/cov_crash/cov_crash_target"
        COV_PARSER_BIN="${CMAKE_BINARY_DIR}/tests/fixtures/cov_parser/cov_parser_target"
        COV_PARSER_SEEDS="${CMAKE_SOURCE_DIR}/tests/fixtures/cov_parser/seeds"
        COV_ARGV_BIN="${CMAKE_BINARY_DIR}/tests/fixtures/cov_argv/cov_argv_target"
        COV_LIBRARY_PATH="$<TARGET_FILE:mlfuzzz3_cov>")

gtest_discover_tests(test_campaign_e2e
    PROPERTIES TIMEOUT 90)

target_link_libraries(test_campaign_e2e PRIVATE yaml-cpp::yaml-cpp)
target_compile_definitions(test_campaign_e2e PRIVATE
  COMPOSITION_HAS_I2S=$<BOOL:${FUZZER_ENABLE_I2S}>
  COMPOSITION_HAS_SMT=$<BOOL:${FUZZER_ENABLE_SMT}>)
