add_executable(mutation_test
  test_mutation.cpp
)

target_link_libraries(mutation_test
  PRIVATE
    fuzzer::mutation
    fuzzer::warnings
    GTest::gtest_main
)

gtest_discover_tests(mutation_test)

add_executable(test_havoc
  test_havoc.cpp
)

target_link_libraries(test_havoc
  PRIVATE
    fuzzer::mutation
    fuzzer::warnings
    GTest::gtest_main
)

gtest_discover_tests(test_havoc)

add_executable(test_ops
  test_ops.cpp
)

target_link_libraries(test_ops
  PRIVATE
    fuzzer::mutation
    fuzzer::warnings
    GTest::gtest_main
)

gtest_discover_tests(test_ops)

add_executable(test_deterministic_stage
  test_deterministic_stage.cpp
)

target_link_libraries(test_deterministic_stage
  PRIVATE
    fuzzer::mutation
    fuzzer::warnings
    GTest::gtest_main
)

gtest_discover_tests(test_deterministic_stage)
target_sources(test_havoc PRIVATE ../../regression/test_havoc_legacy_trace.cpp)
