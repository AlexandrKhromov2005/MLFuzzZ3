add_executable(test_self_check
  test_self_check.cpp
)

target_link_libraries(test_self_check
  PRIVATE
    fuzzer::solver
    fuzzer::warnings
    GTest::gtest_main
)

gtest_discover_tests(test_self_check)

add_executable(test_solver_facade
  test_solver_facade.cpp
)

target_link_libraries(test_solver_facade
  PRIVATE
    fuzzer::solver
    fuzzer::warnings
    GTest::gtest_main
)

gtest_discover_tests(test_solver_facade)
