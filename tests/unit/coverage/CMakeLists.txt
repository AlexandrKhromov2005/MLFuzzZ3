add_executable(test_coverage_reader
  test_coverage_reader.cpp
)

target_link_libraries(test_coverage_reader
  PRIVATE
    fuzzer::coverage
    fuzzer::warnings
    GTest::gtest_main
)

gtest_discover_tests(test_coverage_reader)

add_executable(test_branch_reader
  test_branch_reader.cpp
)

target_link_libraries(test_branch_reader
  PRIVATE
    fuzzer::coverage
    fuzzer::warnings
    GTest::gtest_main
)

gtest_discover_tests(test_branch_reader)

add_executable(test_count_scheme
  test_count_scheme.cpp
)

target_link_libraries(test_count_scheme
  PRIVATE
    fuzzer::coverage
    fuzzer::warnings
    GTest::gtest_main
)

gtest_discover_tests(test_count_scheme)
