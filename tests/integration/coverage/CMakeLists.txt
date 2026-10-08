# End-to-end coverage bridge integration test (ADR 0028 Phase 2).
#
# Spawns a real exec-server subprocess against the
# pass-instrumented cov_stdin fixture and verifies that the
# C++ Core receives the edge-coverage memfd via SCM_RIGHTS
# (ClientSession::coverage_fd) and observes per-run coverage
# through CoverageReader. This is the cross-language gate
# for ADR 0028 part A + part B.
#
# The test self-skips when any of the three required
# artifacts is unavailable:
#   - exec-server Go binary (requires `go` on PATH);
#   - cov_stdin_target (requires clang + EdgeCoveragePass);
#   - libmlfuzzz3_cov.so (always built when src/runtime is
#     present, but guarded for completeness).

if(NOT TARGET mlfuzzz3_cov)
    message(STATUS
        "mlfuzzz3_cov target absent; "
        "test_coverage_bridge_e2e will not be built")
    return()
endif()

if(NOT TARGET cov_stdin_build)
    message(STATUS
        "cov_stdin_build target absent (clang or "
        "EdgeCoveragePass unavailable); "
        "test_coverage_bridge_e2e will not be built")
    return()
endif()

find_program(MLFUZZZ3_GO_BIN NAMES go)
if(NOT MLFUZZZ3_GO_BIN)
    message(STATUS
        "go not found on PATH; "
        "test_coverage_bridge_e2e will not be built")
    return()
endif()

# Build the exec-server Go binary into the CMake build
# tree. The integration test fork+exec's this artifact with
# the IPC socketpair installed at fd 3, matching the
# subprocess contract documented in cmd/exec-server/main.go.
# CGO_ENABLED=0 keeps the binary self-contained and avoids
# accidental dependence on the build host's libc soname.
set(_exec_server_bin ${CMAKE_BINARY_DIR}/exec-server-bin)
file(GLOB_RECURSE _exec_server_sources CONFIGURE_DEPENDS
    ${CMAKE_SOURCE_DIR}/exec-server/go.mod
    ${CMAKE_SOURCE_DIR}/exec-server/go.sum
    ${CMAKE_SOURCE_DIR}/exec-server/cmd/exec-server/*.go
    ${CMAKE_SOURCE_DIR}/exec-server/internal/*.go)

add_custom_command(
    OUTPUT ${_exec_server_bin}
    COMMAND ${CMAKE_COMMAND} -E env
        CGO_ENABLED=0
        ${MLFUZZZ3_GO_BIN} build
            -o ${_exec_server_bin}
            ./cmd/exec-server
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/exec-server
    DEPENDS ${_exec_server_sources}
    COMMENT "Building exec-server (Go) for integration tests"
    VERBATIM)

add_custom_target(exec_server_bin
    DEPENDS ${_exec_server_bin})

add_executable(test_coverage_bridge_e2e
    test_coverage_bridge_e2e.cpp)

add_dependencies(test_coverage_bridge_e2e
    exec_server_bin
    cov_stdin_build)

target_link_libraries(test_coverage_bridge_e2e
    PRIVATE
        fuzzer::session
        fuzzer::coverage
        fuzzer::warnings
        GTest::gtest_main)

target_compile_definitions(test_coverage_bridge_e2e
    PRIVATE
        EXEC_SERVER_BIN="${_exec_server_bin}"
        COV_STDIN_BIN="${CMAKE_BINARY_DIR}/tests/fixtures/cov_stdin/cov_stdin_target"
        COV_LIBRARY_PATH="$<TARGET_FILE:mlfuzzz3_cov>")

gtest_discover_tests(test_coverage_bridge_e2e
    PROPERTIES TIMEOUT 60)

# Branch-value channel format smoke e2e (ADR 0033 Шаг 6). Reuses the
# exec_server_bin target above; runs against the branch_icmp fixture
# (branch + edge passes). Self-skips when the fixture is unavailable
# (clang or the passes were not built).
if(TARGET branch_icmp_build)
    add_executable(test_branch_channel_e2e
        test_branch_channel_e2e.cpp)

    add_dependencies(test_branch_channel_e2e
        exec_server_bin
        branch_icmp_build)

    target_link_libraries(test_branch_channel_e2e
        PRIVATE
            fuzzer::session
            fuzzer::coverage
            fuzzer::warnings
            GTest::gtest_main)

    target_compile_definitions(test_branch_channel_e2e
        PRIVATE
            EXEC_SERVER_BIN="${_exec_server_bin}"
            BRANCH_FIXTURE_BIN="${CMAKE_BINARY_DIR}/tests/fixtures/branch_icmp/branch_icmp_target"
            COV_LIBRARY_PATH="$<TARGET_FILE:mlfuzzz3_cov>")

    gtest_discover_tests(test_branch_channel_e2e
        PROPERTIES TIMEOUT 60)
else()
    message(STATUS
        "branch_icmp_build target absent; "
        "test_branch_channel_e2e will not be built")
endif()
