# Solver-necessary fixture smoke test (ADR 0034 prep — PROVISIONAL). Runs
# the cov_solve fixture directly (no exec-server): a brute-forced
# satisfying input must abort, a neutral input must exit cleanly. Self-
# skips when the fixture was not built (clang or the passes absent).
if(TARGET cov_solve_build)
    add_executable(test_cov_solve_smoke
        test_cov_solve_smoke.cpp)

    add_dependencies(test_cov_solve_smoke cov_solve_build)

    target_link_libraries(test_cov_solve_smoke
        PRIVATE
            fuzzer::warnings
            GTest::gtest_main)

    target_compile_definitions(test_cov_solve_smoke
        PRIVATE
            COV_SOLVE_BIN="${CMAKE_BINARY_DIR}/tests/fixtures/cov_solve/cov_solve_target")

    gtest_discover_tests(test_cov_solve_smoke
        PROPERTIES TIMEOUT 30)
else()
    message(STATUS
        "cov_solve_build target absent; "
        "test_cov_solve_smoke will not be built")
endif()

# Cross-field Z3-necessary fixture smoke test (ADR 0035). Runs the
# cov_xfield fixture directly (no exec-server): a hand-solved satisfying
# pair must abort, a neutral input must exit cleanly, and single-operand
# substitutions must not crash (Z3-necessity). Self-skips when the fixture
# was not built (clang or the passes absent).
if(TARGET cov_xfield_build)
    add_executable(test_cov_xfield_smoke
        test_cov_xfield_smoke.cpp)

    add_dependencies(test_cov_xfield_smoke cov_xfield_build)

    target_link_libraries(test_cov_xfield_smoke
        PRIVATE
            fuzzer::warnings
            GTest::gtest_main)

    target_compile_definitions(test_cov_xfield_smoke
        PRIVATE
            COV_XFIELD_BIN="${CMAKE_BINARY_DIR}/tests/fixtures/cov_xfield/cov_xfield_target")

    gtest_discover_tests(test_cov_xfield_smoke
        PROPERTIES TIMEOUT 30)
else()
    message(STATUS
        "cov_xfield_build target absent; "
        "test_cov_xfield_smoke will not be built")
endif()

# Cross-field addition gate fixture smoke test (ADR 0036). Runs the
# add_gate fixture directly (no exec-server): a hand-solved satisfying
# pair must abort, the solver arm's seed and a short input must exit
# cleanly, and every degenerate pair that also sums to MAGIC must be
# rejected by guard() -- that last one is what keeps the fixture
# solver-requiring. Self-skips when the fixture was not built (clang or
# the passes absent).
if(TARGET add_gate_build)
    add_executable(test_add_gate_smoke
        test_add_gate_smoke.cpp)

    add_dependencies(test_add_gate_smoke add_gate_build)

    target_link_libraries(test_add_gate_smoke
        PRIVATE
            fuzzer::warnings
            GTest::gtest_main)

    target_compile_definitions(test_add_gate_smoke
        PRIVATE
            ADD_GATE_BIN="${CMAKE_BINARY_DIR}/tests/fixtures/add_gate/add_gate")

    gtest_discover_tests(test_add_gate_smoke
        PROPERTIES TIMEOUT 30)
else()
    message(STATUS
        "add_gate_build target absent; "
        "test_add_gate_smoke will not be built")
endif()
