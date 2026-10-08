# C unit test для libmlfuzzz3_cov.so loadability and
# symbol presence.

add_executable(test_mlfuzzz3_cov
    test_mlfuzzz3_cov.cpp
)

target_link_libraries(test_mlfuzzz3_cov
    PRIVATE
        GTest::gtest_main
        ${CMAKE_DL_LIBS}
)

# Pass absolute path to library .so as compile-time
# constant. CMake target generator creates lib at
# known location. COV_STDIN_BIN points at the instrumented
# cov_stdin fixture for the ADR 0042 no-fd regression test (a
# plain path string, not a generator expression on the target,
# so configure succeeds even when clang is absent and the
# fixture is not built; the test self-skips when it is missing).
target_compile_definitions(test_mlfuzzz3_cov PRIVATE
    MLFUZZZ3_COV_LIB_PATH="$<TARGET_FILE:mlfuzzz3_cov>"
    COV_STDIN_BIN="${CMAKE_BINARY_DIR}/tests/fixtures/cov_stdin/cov_stdin_target"
)

add_dependencies(test_mlfuzzz3_cov mlfuzzz3_cov)
if(TARGET cov_stdin_build)
    add_dependencies(test_mlfuzzz3_cov cov_stdin_build)
endif()

gtest_discover_tests(test_mlfuzzz3_cov)

# Branch-value channel unit test (ADR 0033 Шаг 2). Forks and
# dlopens the library in the child so the branch constructor
# runs fresh per scenario; includes the shared branch ABI
# header to inspect the segment with the canonical layout.
add_executable(test_mlfuzzz3_branch
    test_mlfuzzz3_branch.cpp
)

target_link_libraries(test_mlfuzzz3_branch
    PRIVATE
        GTest::gtest_main
        ${CMAKE_DL_LIBS}
)

target_include_directories(test_mlfuzzz3_branch PRIVATE
    ${CMAKE_SOURCE_DIR}/src/runtime/coverage
)

target_compile_definitions(test_mlfuzzz3_branch PRIVATE
    MLFUZZZ3_COV_LIB_PATH="$<TARGET_FILE:mlfuzzz3_cov>"
)

add_dependencies(test_mlfuzzz3_branch mlfuzzz3_cov)

gtest_discover_tests(test_mlfuzzz3_branch)
