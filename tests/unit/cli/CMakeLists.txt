add_executable(test_cli_args
  test_args.cpp
)

target_link_libraries(test_cli_args
  PRIVATE
    fuzzer::cli_args
    fuzzer::warnings
    GTest::gtest_main
)

gtest_discover_tests(test_cli_args)
