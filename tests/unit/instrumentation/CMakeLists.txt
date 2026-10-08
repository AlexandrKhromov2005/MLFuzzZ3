# IR-level unit test for the branch-tracing pass (ADR 0033 Шаг 3).
# Reads the instrumented IR emitted by the branch_icmp fixture; the
# test self-skips when that artifact is absent (clang unavailable).

add_executable(test_branch_trace_pass
    test_branch_trace_pass.cpp
)

target_link_libraries(test_branch_trace_pass
    PRIVATE
        fuzzer::warnings
        GTest::gtest_main
)

target_compile_definitions(test_branch_trace_pass PRIVATE
    BRANCH_ICMP_IR_PATH="${CMAKE_BINARY_DIR}/tests/fixtures/branch_icmp/branch_icmp_instrumented.ll"
)

gtest_discover_tests(test_branch_trace_pass)

# Таблица сайтов (ADR 0047 §Решение-5): читает артефакт, испускаемый
# фикстурой branch_icmp отдельной сборкой с -g.
add_executable(test_site_map
    test_site_map.cpp
)

target_link_libraries(test_site_map
    PRIVATE
        fuzzer::warnings
        GTest::gtest_main
)

target_compile_definitions(test_site_map PRIVATE
    BRANCH_ICMP_SITEMAP_DIR="${CMAKE_BINARY_DIR}/tests/fixtures/branch_icmp/sitemap"
)

gtest_discover_tests(test_site_map)
