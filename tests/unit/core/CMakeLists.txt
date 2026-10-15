add_executable(test_core_smoke
  test_smoke.cpp
)

target_link_libraries(test_core_smoke
  PRIVATE
    fuzzer::core
    fuzzer::warnings
    GTest::gtest_main
)

gtest_discover_tests(test_core_smoke)

add_executable(test_seed_scheduler
  test_seed_scheduler.cpp
)

target_link_libraries(test_seed_scheduler
  PRIVATE
    fuzzer::core
    fuzzer::warnings
    GTest::gtest_main
)

gtest_discover_tests(test_seed_scheduler)

add_executable(test_corpus
  test_corpus.cpp
)

target_link_libraries(test_corpus
  PRIVATE
    fuzzer::core
    fuzzer::warnings
    GTest::gtest_main
)

gtest_discover_tests(test_corpus)

add_executable(test_metrics
  test_metrics.cpp
)

target_link_libraries(test_metrics
  PRIVATE
    fuzzer::core
    fuzzer::warnings
    GTest::gtest_main
)

gtest_discover_tests(test_metrics)

add_executable(test_campaign
  test_campaign.cpp
  ${CMAKE_SOURCE_DIR}/tests/regression/test_campaign_without_solver.cpp
)

target_link_libraries(test_campaign
  PRIVATE
    fuzzer::composition
    fuzzer::session
    fuzzer::mutation
    fuzzer::warnings
    GTest::gtest_main
)

gtest_discover_tests(test_campaign)

# ADR 0036: Runner::LastBranchRecords accessor coverage via FakeRunner.
add_executable(test_runner
  test_runner.cpp
)

target_link_libraries(test_runner
  PRIVATE
    fuzzer::composition
    fuzzer::session
    fuzzer::warnings
    GTest::gtest_main
)

# The concolic-compatibility case links fuzzer::concolic (which pulls in
# Z3), so it is gated on FUZZER_BUILD_Z3 like the concolic tests
# (ADR 0035/0036); the accessor-semantics cases build unconditionally.
if(TARGET fuzzer::concolic)
  target_link_libraries(test_runner PRIVATE fuzzer::concolic)
  target_compile_definitions(test_runner PRIVATE MLFUZZZ3_WITH_CONCOLIC)
endif()

gtest_discover_tests(test_runner)

# ADR 0036: campaign-loop concolic-trigger coverage without a server. Only
# meaningful with the registered SMT campaign stage; direct solver tests
# remain available when the library is built without stage registration.
if(TARGET fuzzer::concolic AND FUZZER_ENABLE_SMT)
  add_executable(test_campaign_concolic
    test_campaign_concolic.cpp
  )

  # fuzzer::concolic is already pulled in transitively by fuzzer::composition here,
  # but it is linked explicitly so concolic.h is on the include path: the
  # attribution pin (AttributionFor) switches over concolic::SolveOutcome.
  target_link_libraries(test_campaign_concolic
    PRIVATE
      fuzzer::composition
      fuzzer::concolic
      fuzzer::session
      fuzzer::mutation
      fuzzer::warnings
      GTest::gtest_main
  )

  gtest_discover_tests(test_campaign_concolic)
endif()

# task-030 / ADR 0036 §4: characterization of WHERE a concolic candidate's
# edges are attributed for OK and CRASH. Same optional stage registration
# and link set as test_campaign_concolic.
if(TARGET fuzzer::concolic AND FUZZER_ENABLE_SMT)
  add_executable(test_concolic_edge_attribution
    test_concolic_edge_attribution.cpp
  )

  target_link_libraries(test_concolic_edge_attribution
    PRIVATE
      fuzzer::composition
      fuzzer::concolic
      fuzzer::session
      fuzzer::mutation
      fuzzer::warnings
      GTest::gtest_main
  )

  gtest_discover_tests(test_concolic_edge_attribution)
endif()
if(TARGET fuzzer::concolic AND FUZZER_ENABLE_SMT)
  add_executable(test_campaign_execution_budget ../../regression/test_campaign_execution_budget.cpp)
  target_include_directories(test_campaign_execution_budget PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
  target_link_libraries(test_campaign_execution_budget PRIVATE fuzzer::composition fuzzer::warnings GTest::gtest_main)
  gtest_discover_tests(test_campaign_execution_budget)
endif()
# This executable intentionally links only core, proving transport/solver independence.
add_executable(test_domain_campaign test_domain_campaign.cpp)
target_link_libraries(test_domain_campaign PRIVATE fuzzer::core fuzzer::warnings GTest::gtest_main)
gtest_discover_tests(test_domain_campaign)
