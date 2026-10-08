add_executable(test_ipc_proto_smoke
  test_proto_smoke.cpp
)

target_link_libraries(test_ipc_proto_smoke
  PRIVATE
    fuzzer::proto
    GTest::gtest_main
)

gtest_discover_tests(test_ipc_proto_smoke)

add_executable(test_ipc_framing
  test_ipc_framing.cpp
)

target_link_libraries(test_ipc_framing
  PRIVATE
    fuzzer::framing
    fuzzer::warnings
    GTest::gtest_main
)

gtest_discover_tests(test_ipc_framing)

add_executable(test_ipc_session
  test_ipc_session.cpp
)

target_link_libraries(test_ipc_session
  PRIVATE
    fuzzer::session
    fuzzer::warnings
    GTest::gtest_main
)

gtest_discover_tests(test_ipc_session)

add_executable(test_scm_rights
  test_scm_rights.cpp
)

target_link_libraries(test_scm_rights
  PRIVATE
    fuzzer::session
    fuzzer::warnings
    GTest::gtest_main
)

gtest_discover_tests(test_scm_rights)
