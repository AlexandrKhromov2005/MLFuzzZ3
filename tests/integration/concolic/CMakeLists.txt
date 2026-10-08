# End-to-end cross-field concolic test (ADR 0035). Reuses the
# exec_server_bin target defined in tests/integration/coverage; runs the
# orchestrator (fuzzer::concolic) against the cov_xfield fixture through a
# real exec-server: a seed that misses C4 runs clean, the solved candidate
# crashes. Self-skips when any artifact is unavailable (clang/passes for
# the fixture, Z3 for the orchestrator, or go for the exec-server).
if(TARGET cov_xfield_build AND TARGET fuzzer::concolic AND TARGET exec_server_bin)
    add_executable(test_concolic_xfield_e2e
        test_concolic_xfield_e2e.cpp)

    add_dependencies(test_concolic_xfield_e2e
        exec_server_bin
        cov_xfield_build)

    target_link_libraries(test_concolic_xfield_e2e
        PRIVATE
            fuzzer::concolic
            fuzzer::session
            fuzzer::coverage
            fuzzer::warnings
            GTest::gtest_main)

    target_compile_definitions(test_concolic_xfield_e2e
        PRIVATE
            EXEC_SERVER_BIN="${CMAKE_BINARY_DIR}/exec-server-bin"
            COV_XFIELD_BIN="${CMAKE_BINARY_DIR}/tests/fixtures/cov_xfield/cov_xfield_target"
            COV_LIBRARY_PATH="$<TARGET_FILE:mlfuzzz3_cov>")

    gtest_discover_tests(test_concolic_xfield_e2e
        PROPERTIES TIMEOUT 60)

    # ADR 0036: campaign-loop concolic integration e2e. The loop itself
    # (fuzzer::core, built with concolic) triggers concolic on stagnation
    # and reaches the crash. Links fuzzer::core; concolic is pulled in
    # transitively (PRIVATE dep of fuzzer::core under FUZZER_BUILD_Z3).
    add_executable(test_campaign_concolic_e2e
        test_campaign_concolic_e2e.cpp)

    add_dependencies(test_campaign_concolic_e2e
        exec_server_bin
        cov_xfield_build)

    target_link_libraries(test_campaign_concolic_e2e
        PRIVATE
            fuzzer::core
            fuzzer::session
            fuzzer::mutation
            fuzzer::warnings
            GTest::gtest_main)

    target_compile_definitions(test_campaign_concolic_e2e
        PRIVATE
            EXEC_SERVER_BIN="${CMAKE_BINARY_DIR}/exec-server-bin"
            COV_XFIELD_BIN="${CMAKE_BINARY_DIR}/tests/fixtures/cov_xfield/cov_xfield_target"
            COV_LIBRARY_PATH="$<TARGET_FILE:mlfuzzz3_cov>")

    gtest_discover_tests(test_campaign_concolic_e2e
        PROPERTIES TIMEOUT 120)
else()
    message(STATUS
        "cov_xfield_build / fuzzer::concolic / exec_server_bin absent; "
        "test_concolic_xfield_e2e / test_campaign_concolic_e2e will not be built")
endif()

# ADR 0036: the SECOND solver-requiring e2e oracle, on the add_gate
# fixture (a + b == MAGIC over two verbatim fields, inside guard()). Same
# shape as test_campaign_concolic_e2e above, different gate — so a
# regression that only kills the solver on one gate form (e.g. an
# adaptive-budget throttle, ADR 0038) cannot pass unnoticed. Guarded on
# add_gate_build, not cov_xfield_build: the two fixtures skip
# independently.
if(TARGET add_gate_build AND TARGET fuzzer::concolic AND TARGET exec_server_bin)
    add_executable(test_campaign_add_gate_e2e
        test_campaign_add_gate_e2e.cpp)

    add_dependencies(test_campaign_add_gate_e2e
        exec_server_bin
        add_gate_build)

    target_link_libraries(test_campaign_add_gate_e2e
        PRIVATE
            fuzzer::core
            fuzzer::session
            fuzzer::mutation
            fuzzer::warnings
            GTest::gtest_main)

    target_compile_definitions(test_campaign_add_gate_e2e
        PRIVATE
            EXEC_SERVER_BIN="${CMAKE_BINARY_DIR}/exec-server-bin"
            ADD_GATE_BIN="${CMAKE_BINARY_DIR}/tests/fixtures/add_gate/add_gate"
            COV_LIBRARY_PATH="$<TARGET_FILE:mlfuzzz3_cov>")

    # Two campaigns of 200 execs each plus their concolic solves; the
    # measured arm reaches the crash in 500-600 execs / under 0.5 s
    # (docs/experiments/kaddvars-solver-arm/report.md), so this is a wide
    # margin, matched to the cov_xfield campaign oracle above.
    gtest_discover_tests(test_campaign_add_gate_e2e
        PROPERTIES TIMEOUT 120)
else()
    message(STATUS
        "add_gate_build / fuzzer::concolic / exec_server_bin absent; "
        "test_campaign_add_gate_e2e will not be built")
endif()

# task-032, ADR 0036: the NEGATIVE control of the add_gate oracle above —
# the same campaign on a gate that differs by one operator (a - b == MAGIC,
# the form the domain map calls NO-BINDING). Same seed, budget, RNG seed
# and threshold; only the fixture binary differs, so the pair measures the
# boundary of the solver's domain on a target instead of inferring it from
# BuildSystem calls. Guarded on sub_gate_build so it skips independently of
# add_gate and cov_xfield.
if(TARGET sub_gate_build AND TARGET fuzzer::concolic AND TARGET exec_server_bin)
    add_executable(test_campaign_sub_gate_e2e
        test_campaign_sub_gate_e2e.cpp)

    add_dependencies(test_campaign_sub_gate_e2e
        exec_server_bin
        sub_gate_build)

    target_link_libraries(test_campaign_sub_gate_e2e
        PRIVATE
            fuzzer::core
            fuzzer::session
            fuzzer::mutation
            fuzzer::warnings
            GTest::gtest_main)

    target_compile_definitions(test_campaign_sub_gate_e2e
        PRIVATE
            EXEC_SERVER_BIN="${CMAKE_BINARY_DIR}/exec-server-bin"
            SUB_GATE_BIN="${CMAKE_BINARY_DIR}/tests/fixtures/sub_gate/sub_gate"
            COV_LIBRARY_PATH="$<TARGET_FILE:mlfuzzz3_cov>")

    # One campaign of 200 execs plus its concolic solves — half the work of
    # the add_gate oracle, which runs two; the timeout is kept at the same
    # 120 s so a slow solve shows up as a red test, not as a flaky timeout.
    gtest_discover_tests(test_campaign_sub_gate_e2e
        PROPERTIES TIMEOUT 120)
else()
    message(STATUS
        "sub_gate_build / fuzzer::concolic / exec_server_bin absent; "
        "test_campaign_sub_gate_e2e will not be built")
endif()

# task-067, ADR 0036: the budget sweep that gives the add_gate oracle its
# DENOMINATOR — the minimal `max_iterations` at which the campaign still
# reaches the crash, found from outside by re-running with a truncated
# budget. Needs BOTH fixtures: add_gate for the measurement and sub_gate for
# the mandatory negative control, so the guard names both.
#
# The *_REL definitions are the same paths as the *_BIN ones, expressed
# relative to the repository root: the harness prints only those, so the raw
# log of the sweep carries no absolute path and stays byte-comparable
# between machines.
if(TARGET add_gate_build AND TARGET sub_gate_build AND TARGET fuzzer::concolic
        AND TARGET exec_server_bin)
    add_executable(test_add_gate_crash_budget
        test_add_gate_crash_budget.cpp)

    add_dependencies(test_add_gate_crash_budget
        exec_server_bin
        add_gate_build
        sub_gate_build)

    target_link_libraries(test_add_gate_crash_budget
        PRIVATE
            fuzzer::core
            fuzzer::session
            fuzzer::mutation
            fuzzer::warnings
            GTest::gtest_main)

    file(RELATIVE_PATH _crash_budget_exec_server_rel
        "${CMAKE_SOURCE_DIR}" "${CMAKE_BINARY_DIR}/exec-server-bin")
    file(RELATIVE_PATH _crash_budget_add_gate_rel
        "${CMAKE_SOURCE_DIR}" "${CMAKE_BINARY_DIR}/tests/fixtures/add_gate/add_gate")
    file(RELATIVE_PATH _crash_budget_sub_gate_rel
        "${CMAKE_SOURCE_DIR}" "${CMAKE_BINARY_DIR}/tests/fixtures/sub_gate/sub_gate")

    target_compile_definitions(test_add_gate_crash_budget
        PRIVATE
            EXEC_SERVER_BIN="${CMAKE_BINARY_DIR}/exec-server-bin"
            ADD_GATE_BIN="${CMAKE_BINARY_DIR}/tests/fixtures/add_gate/add_gate"
            SUB_GATE_BIN="${CMAKE_BINARY_DIR}/tests/fixtures/sub_gate/sub_gate"
            COV_LIBRARY_PATH="$<TARGET_FILE:mlfuzzz3_cov>"
            EXEC_SERVER_REL="${_crash_budget_exec_server_rel}"
            ADD_GATE_REL="${_crash_budget_add_gate_rel}"
            SUB_GATE_REL="${_crash_budget_sub_gate_rel}"
            COV_LIBRARY_REL="$<PATH:RELATIVE_PATH,$<TARGET_FILE:mlfuzzz3_cov>,${CMAKE_SOURCE_DIR}>")

    # ~25 bounded campaigns in one test: the binary search over [1, 200], the
    # four probes around the transition point, five repeats of the point and
    # of the point below it, and the two controls. The 200-exec campaigns
    # cost about 3.3 s each (docs/experiments/solver-oracle-repeatability/
    # raw-ctest.txt:33) and the truncated ones far less, so 900 s is a wide
    # margin over the measured minute-scale total rather than a guess.
    gtest_discover_tests(test_add_gate_crash_budget
        PROPERTIES TIMEOUT 900)
else()
    message(STATUS
        "add_gate_build / sub_gate_build / fuzzer::concolic / exec_server_bin absent; "
        "test_add_gate_crash_budget will not be built")
endif()

# task-070, ADR 0036: the CEILING of the control arm — the budget sweep that
# asks whether `add_gate` falls at all with the solver disarmed. task-067
# pinned that control at exactly one point (budget 18), which bounds nothing
# from above; this target walks the doubling ladder 1..200 with the stagnation
# threshold pushed past each budget, extends to 1600 under a condition fixed
# before the run, and reproduces task-067's armed pin (18 crashes, 17 does
# not) on the same tree.
#
# Guarded on add_gate_build alone — unlike test_add_gate_crash_budget it needs
# no sub_gate: the negative control here is the disarmed arm itself, not a
# second fixture.
#
# The *_REL definitions are the same paths as the *_BIN ones, expressed
# relative to the repository root: the harness prints only those, so the raw
# log of the sweep carries no absolute path and stays byte-comparable between
# machines.
if(TARGET add_gate_build AND TARGET fuzzer::concolic AND TARGET exec_server_bin)
    add_executable(test_add_gate_noconcolic_ceiling
        test_add_gate_noconcolic_ceiling.cpp)

    add_dependencies(test_add_gate_noconcolic_ceiling
        exec_server_bin
        add_gate_build)

    target_link_libraries(test_add_gate_noconcolic_ceiling
        PRIVATE
            fuzzer::core
            fuzzer::session
            fuzzer::mutation
            fuzzer::warnings
            GTest::gtest_main)

    file(RELATIVE_PATH _noconc_ceiling_exec_server_rel
        "${CMAKE_SOURCE_DIR}" "${CMAKE_BINARY_DIR}/exec-server-bin")
    file(RELATIVE_PATH _noconc_ceiling_add_gate_rel
        "${CMAKE_SOURCE_DIR}" "${CMAKE_BINARY_DIR}/tests/fixtures/add_gate/add_gate")

    target_compile_definitions(test_add_gate_noconcolic_ceiling
        PRIVATE
            EXEC_SERVER_BIN="${CMAKE_BINARY_DIR}/exec-server-bin"
            ADD_GATE_BIN="${CMAKE_BINARY_DIR}/tests/fixtures/add_gate/add_gate"
            COV_LIBRARY_PATH="$<TARGET_FILE:mlfuzzz3_cov>"
            EXEC_SERVER_REL="${_noconc_ceiling_exec_server_rel}"
            ADD_GATE_REL="${_noconc_ceiling_add_gate_rel}"
            COV_LIBRARY_REL="$<PATH:RELATIVE_PATH,$<TARGET_FILE:mlfuzzz3_cov>,${CMAKE_SOURCE_DIR}>")

    # The disarmed arm costs no solver time: task-067 measured 18 disarmed
    # execs at 13 ms (docs/experiments/solver-add-gate-crash-budget/
    # raw-crash-budget.txt, phase=control-noconcolic), so the whole sweep —
    # ladder, extension to 1600, refinement, ten repeats and the two armed
    # control probes — is seconds, not minutes. 300 s is a wide margin, and
    # the 60 s wall-time cap on the extension is enforced inside the harness.
    gtest_discover_tests(test_add_gate_noconcolic_ceiling
        PROPERTIES TIMEOUT 300)
else()
    message(STATUS
        "add_gate_build / fuzzer::concolic / exec_server_bin absent; "
        "test_add_gate_noconcolic_ceiling will not be built")
endif()

# task-076, ADR 0036: HOW DEEP that ceiling is. task-070 stopped the disarmed
# ladder at 1600 because the ladder ran out (`stop_reason=hi`), so its
# `ratio_vs_solver=>=88.8889` is a property of the number 1600 rather than of
# `add_gate`. This target continues the same ladder by doubling — 3200 .. 409600,
# the series fixed inside the harness before the run — on the donor's seed, RNG
# seed 7 and stagnation threshold, under a HARD 1200 s wall-time budget enforced
# by admission control inside the harness itself.
#
# Same guard and same *_REL construction as the target above: only relative paths
# reach the raw log, so it stays free of absolute paths and byte-comparable
# between machines.
if(TARGET add_gate_build AND TARGET fuzzer::concolic AND TARGET exec_server_bin)
    add_executable(test_add_gate_ceiling_depth
        test_add_gate_ceiling_depth.cpp)

    add_dependencies(test_add_gate_ceiling_depth
        exec_server_bin
        add_gate_build)

    target_link_libraries(test_add_gate_ceiling_depth
        PRIVATE
            fuzzer::core
            fuzzer::session
            fuzzer::mutation
            fuzzer::warnings
            GTest::gtest_main)

    file(RELATIVE_PATH _ceiling_depth_exec_server_rel
        "${CMAKE_SOURCE_DIR}" "${CMAKE_BINARY_DIR}/exec-server-bin")
    file(RELATIVE_PATH _ceiling_depth_add_gate_rel
        "${CMAKE_SOURCE_DIR}" "${CMAKE_BINARY_DIR}/tests/fixtures/add_gate/add_gate")

    target_compile_definitions(test_add_gate_ceiling_depth
        PRIVATE
            EXEC_SERVER_BIN="${CMAKE_BINARY_DIR}/exec-server-bin"
            ADD_GATE_BIN="${CMAKE_BINARY_DIR}/tests/fixtures/add_gate/add_gate"
            COV_LIBRARY_PATH="$<TARGET_FILE:mlfuzzz3_cov>"
            EXEC_SERVER_REL="${_ceiling_depth_exec_server_rel}"
            ADD_GATE_REL="${_ceiling_depth_add_gate_rel}"
            COV_LIBRARY_REL="$<PATH:RELATIVE_PATH,$<TARGET_FILE:mlfuzzz3_cov>,${CMAKE_SOURCE_DIR}>")

    # This target is minutes, not seconds, and that is by design: task-070
    # measured 0.8 s for one probe at 1600 (docs/experiments/
    # solver-add-gate-noconcolic-ceiling/report.md:14), so the ladder to 409600
    # is of the order of 400 s under linearity. The harness stops itself at its
    # own 1200 s budget (kWalltimeBudgetS), so the ctest timeout must sit ABOVE
    # that budget or ctest — not the stopping rule — would decide where the
    # ceiling is. 1500 s leaves the harness room to report `stop_reason=walltime`
    # and still exit cleanly.
    gtest_discover_tests(test_add_gate_ceiling_depth
        PROPERTIES TIMEOUT 1500)
else()
    message(STATUS
        "add_gate_build / fuzzer::concolic / exec_server_bin absent; "
        "test_add_gate_ceiling_depth will not be built")
endif()


# task-071, ADR 0036: the ENSEMBLE behind the denominator — is
# `min_budget_crash=18` a property of the engine or of one RNG seed? The
# donor sweep pinned the mutation RNG at 7; this target repeats its binary
# search over [1, 200] for ten pre-registered seeds (7, 1, 2, 3, 11, 13, 17,
# 23, 29, 31), verifies monotonicity by probes per seed, and reproduces
# task-067's 18 on the control seed.
#
# Guarded on add_gate_build alone — unlike test_add_gate_crash_budget it
# needs no sub_gate: the whole ensemble lives on add_gate, and the series'
# negative control already stands in task-067.
#
# The *_REL definitions are the same paths as the *_BIN ones, expressed
# relative to the repository root: the harness prints only those, so the raw
# log of the sweep carries no absolute path and stays byte-comparable between
# machines.
if(TARGET add_gate_build AND TARGET fuzzer::concolic AND TARGET exec_server_bin)
    add_executable(test_add_gate_budget_seed_spread
        test_add_gate_budget_seed_spread.cpp)

    add_dependencies(test_add_gate_budget_seed_spread
        exec_server_bin
        add_gate_build)

    target_link_libraries(test_add_gate_budget_seed_spread
        PRIVATE
            fuzzer::core
            fuzzer::session
            fuzzer::mutation
            fuzzer::warnings
            GTest::gtest_main)

    file(RELATIVE_PATH _seed_spread_exec_server_rel
        "${CMAKE_SOURCE_DIR}" "${CMAKE_BINARY_DIR}/exec-server-bin")
    file(RELATIVE_PATH _seed_spread_add_gate_rel
        "${CMAKE_SOURCE_DIR}" "${CMAKE_BINARY_DIR}/tests/fixtures/add_gate/add_gate")

    target_compile_definitions(test_add_gate_budget_seed_spread
        PRIVATE
            EXEC_SERVER_BIN="${CMAKE_BINARY_DIR}/exec-server-bin"
            ADD_GATE_BIN="${CMAKE_BINARY_DIR}/tests/fixtures/add_gate/add_gate"
            COV_LIBRARY_PATH="$<TARGET_FILE:mlfuzzz3_cov>"
            EXEC_SERVER_REL="${_seed_spread_exec_server_rel}"
            ADD_GATE_REL="${_seed_spread_add_gate_rel}"
            COV_LIBRARY_REL="$<PATH:RELATIVE_PATH,$<TARGET_FILE:mlfuzzz3_cov>,${CMAKE_SOURCE_DIR}>")

    # Ten seeds x about eleven bounded campaigns each: one 200-exec ticket
    # (~3.3 s, docs/experiments/solver-oracle-repeatability/raw-ctest.txt:33),
    # eight truncated search steps and three probes around the transition.
    # That is minutes, not tens of minutes; 1800 s is a wide margin over the
    # measured total rather than a guess.
    gtest_discover_tests(test_add_gate_budget_seed_spread
        PROPERTIES TIMEOUT 1800)
else()
    message(STATUS
        "add_gate_build / fuzzer::concolic / exec_server_bin absent; "
        "test_add_gate_budget_seed_spread will not be built")
endif()

# task-072, ADR 0036: the AXIS behind the unexplained eight — are the extra
# iterations of the first concolic interval the stagnation threshold itself?
# The donor sweeps held that threshold at 8 while measuring min_budget=18;
# this target repeats the binary search over [1, 200] for six pre-registered
# thresholds (1, 2, 4, 8, 16, 32), finds the iteration of the first concolic
# call by the same search on `concolic_calls > 0`, and checks the model out of
# sample on a seventh threshold (24). RNG seed and input seed are the donor's.
#
# Two tests, deliberately separate: `ControlThreshold8ReproducesTask067MinBudget`
# is the cheap control that must land back on 18 and can be run alone with
# --gtest_filter, `MinimalBudgetAcrossStagnationThresholds` is the full sweep.
#
# Guarded on add_gate_build alone — like its seed-spread sibling it needs no
# sub_gate: the whole axis lives on add_gate, and the series' negative
# controls already stand in task-067.
#
# The *_REL definitions are the same paths as the *_BIN ones, expressed
# relative to the repository root: the harness prints only those, so the raw
# log of the sweep carries no absolute path and stays byte-comparable between
# machines.
if(TARGET add_gate_build AND TARGET fuzzer::concolic AND TARGET exec_server_bin)
    add_executable(test_add_gate_budget_stagnation_axis
        test_add_gate_budget_stagnation_axis.cpp)

    add_dependencies(test_add_gate_budget_stagnation_axis
        exec_server_bin
        add_gate_build)

    target_link_libraries(test_add_gate_budget_stagnation_axis
        PRIVATE
            fuzzer::core
            fuzzer::session
            fuzzer::mutation
            fuzzer::warnings
            GTest::gtest_main)

    file(RELATIVE_PATH _stagnation_axis_exec_server_rel
        "${CMAKE_SOURCE_DIR}" "${CMAKE_BINARY_DIR}/exec-server-bin")
    file(RELATIVE_PATH _stagnation_axis_add_gate_rel
        "${CMAKE_SOURCE_DIR}" "${CMAKE_BINARY_DIR}/tests/fixtures/add_gate/add_gate")

    target_compile_definitions(test_add_gate_budget_stagnation_axis
        PRIVATE
            EXEC_SERVER_BIN="${CMAKE_BINARY_DIR}/exec-server-bin"
            ADD_GATE_BIN="${CMAKE_BINARY_DIR}/tests/fixtures/add_gate/add_gate"
            COV_LIBRARY_PATH="$<TARGET_FILE:mlfuzzz3_cov>"
            EXEC_SERVER_REL="${_stagnation_axis_exec_server_rel}"
            ADD_GATE_REL="${_stagnation_axis_add_gate_rel}"
            COV_LIBRARY_REL="$<PATH:RELATIVE_PATH,$<TARGET_FILE:mlfuzzz3_cov>,${CMAKE_SOURCE_DIR}>")

    # Seven thresholds x about twenty-eight bounded campaigns each: one
    # 200-exec ticket (~3.3 s,
    # docs/experiments/solver-oracle-repeatability/raw-ctest.txt:33), eight
    # steps of the first-call search, eight of the second-call search, eight
    # of the crash search and three probes around the transition. MEASURED on
    # this machine when the target was introduced: 237 s for the sweep test,
    # 24 s for the control test. 900 s is a near-fourfold margin over the
    # measured sweep rather than a guess.
    gtest_discover_tests(test_add_gate_budget_stagnation_axis
        PROPERTIES TIMEOUT 900)
else()
    message(STATUS
        "add_gate_build / fuzzer::concolic / exec_server_bin absent; "
        "test_add_gate_budget_stagnation_axis will not be built")
endif()

# task-073, ADR 0036: the NUMERATOR across the same ensemble — task-070 took
# the ceiling of the disarmed arm (budget_hi=1600, gate not taken) on RNG seed
# 7 alone, while task-071 showed the denominator is a distribution over ten
# pre-registered seeds. This target repeats the disarmed ceiling probe for all
# ten seeds (7, 1, 2, 3, 11, 13, 17, 23, 29, 31), builds task-067's binary
# search over [1, 1600] only for a seed that actually cracked the gate without
# the solver, and divides PAIRWISE by task-071's `min_budget` of THE SAME
# seed. Seed 7 is the control: it must reproduce task-070's outcome.
#
# Guarded on add_gate_build alone — like test_add_gate_budget_seed_spread it
# needs no sub_gate: the whole ensemble lives on add_gate.
#
# The *_REL definitions are the same paths as the *_BIN ones, expressed
# relative to the repository root: the harness prints only those, so the raw
# log of the sweep carries no absolute path and stays byte-comparable between
# machines.
if(TARGET add_gate_build AND TARGET fuzzer::concolic AND TARGET exec_server_bin)
    add_executable(test_add_gate_ceiling_seed_spread
        test_add_gate_ceiling_seed_spread.cpp)

    add_dependencies(test_add_gate_ceiling_seed_spread
        exec_server_bin
        add_gate_build)

    target_link_libraries(test_add_gate_ceiling_seed_spread
        PRIVATE
            fuzzer::core
            fuzzer::session
            fuzzer::mutation
            fuzzer::warnings
            GTest::gtest_main)

    file(RELATIVE_PATH _ceiling_spread_exec_server_rel
        "${CMAKE_SOURCE_DIR}" "${CMAKE_BINARY_DIR}/exec-server-bin")
    file(RELATIVE_PATH _ceiling_spread_add_gate_rel
        "${CMAKE_SOURCE_DIR}" "${CMAKE_BINARY_DIR}/tests/fixtures/add_gate/add_gate")

    target_compile_definitions(test_add_gate_ceiling_seed_spread
        PRIVATE
            EXEC_SERVER_BIN="${CMAKE_BINARY_DIR}/exec-server-bin"
            ADD_GATE_BIN="${CMAKE_BINARY_DIR}/tests/fixtures/add_gate/add_gate"
            COV_LIBRARY_PATH="$<TARGET_FILE:mlfuzzz3_cov>"
            EXEC_SERVER_REL="${_ceiling_spread_exec_server_rel}"
            ADD_GATE_REL="${_ceiling_spread_add_gate_rel}"
            COV_LIBRARY_REL="$<PATH:RELATIVE_PATH,$<TARGET_FILE:mlfuzzz3_cov>,${CMAKE_SOURCE_DIR}>")

    # Ten disarmed probes at budget 1600 when no seed cracks the gate. The
    # cost of one such probe is MEASURED in task-070: max_probe_walltime_s=0.8
    # (docs/experiments/solver-add-gate-noconcolic-ceiling/report.md:15), so
    # the expected total is seconds. The budget below covers the opposite
    # branch too: a seed that cracks adds about eleven truncated search steps
    # plus two probes around the transition, and even ten such ladders stay
    # far inside 1800 s.
    gtest_discover_tests(test_add_gate_ceiling_seed_spread
        PROPERTIES TIMEOUT 1800)
else()
    message(STATUS
        "add_gate_build / fuzzer::concolic / exec_server_bin absent; "
        "test_add_gate_ceiling_seed_spread will not be built")
endif()

# task-081, ADR 0036: the price of the niche at the PRODUCTION stagnation
# threshold. The whole price series ran with the threshold pinned at the
# donor's 8, and the measured axis of task-072 stops at 32 — while
# src/core/campaign.h:58 makes 64 the campaign's own default. This target
# adds exactly ONE point to that axis, 64, taken from the header rather than
# retyped, with the RNG seed, the input seed, the gate and the fixture held
# at the donor's values.
#
# Interval 1..400 and not the series' 1..200: at threshold 32 the minimum is
# already 51 and the axis is monotone, so a ceiling of 200 could be reached
# without settling anything. The two controls (8 -> 18, 32 -> 51) are re-run
# by the same binary in the same process, so the production point is never
# published beside controls from a different run.
#
# One test and not two: the wall-clock budget of the unit (900 s, a constant
# in the harness) covers the controls and the point together, and the
# controls are what licenses the point to be read at all.
#
# Guarded on add_gate_build alone, like its stagnation-axis donor: the whole
# axis lives on add_gate and needs no sub_gate.
if(TARGET add_gate_build AND TARGET fuzzer::concolic AND TARGET exec_server_bin)
    add_executable(test_add_gate_budget_threshold64
        test_add_gate_budget_threshold64.cpp)

    add_dependencies(test_add_gate_budget_threshold64
        exec_server_bin
        add_gate_build)

    target_link_libraries(test_add_gate_budget_threshold64
        PRIVATE
            fuzzer::core
            fuzzer::session
            fuzzer::mutation
            fuzzer::warnings
            GTest::gtest_main)

    file(RELATIVE_PATH _threshold64_exec_server_rel
        "${CMAKE_SOURCE_DIR}" "${CMAKE_BINARY_DIR}/exec-server-bin")
    file(RELATIVE_PATH _threshold64_add_gate_rel
        "${CMAKE_SOURCE_DIR}" "${CMAKE_BINARY_DIR}/tests/fixtures/add_gate/add_gate")

    target_compile_definitions(test_add_gate_budget_threshold64
        PRIVATE
            EXEC_SERVER_BIN="${CMAKE_BINARY_DIR}/exec-server-bin"
            ADD_GATE_BIN="${CMAKE_BINARY_DIR}/tests/fixtures/add_gate/add_gate"
            COV_LIBRARY_PATH="$<TARGET_FILE:mlfuzzz3_cov>"
            EXEC_SERVER_REL="${_threshold64_exec_server_rel}"
            ADD_GATE_REL="${_threshold64_add_gate_rel}"
            COV_LIBRARY_REL="$<PATH:RELATIVE_PATH,$<TARGET_FILE:mlfuzzz3_cov>,${CMAKE_SOURCE_DIR}>")

    # Three thresholds x about twenty bounded campaigns each: one 400-exec
    # ticket, nine steps of the first-call search over [1, 400], nine of the
    # crash search and two probes around the transition. The neighbouring
    # six-point axis over [1, 200] measured 270 s for 220 probes
    # (docs/experiments/solver-add-gate-stagnation-axis/raw-stagnation-axis.txt),
    # so ~60 probes at twice the budget sit well inside 900 s. The harness
    # enforces the same 900 s itself (kWalltimeBudgetS) and stops on it rather
    # than being killed by ctest.
    gtest_discover_tests(test_add_gate_budget_threshold64
        PROPERTIES TIMEOUT 900)
else()
    message(STATUS
        "add_gate_build / fuzzer::concolic / exec_server_bin absent; "
        "test_add_gate_budget_threshold64 will not be built")
endif()

# task-080, ADR 0047: the price of the verbatim niche under a BIG-ENDIAN field
# encoding. The domain map already settles that the BINDING survives the byte
# order (docs/experiments/solver-domain-form-width-endian/report.md:95,
# endian_dependent_forms=none); the price, min_budget_crash=18 on seed 7, was
# measured on exactly one encoding. This target measures the same number on the
# byte-order twin fixture and, in the same process, re-measures the donor's 18
# by the same rule so the two are never taken from different runs.
#
# Guarded on both fixtures: add_gate_be_build carries the target under test and
# add_gate_build carries the little-endian control, which is what licenses the
# BE number to be read at all. No sub_gate — the negative control here is the
# out-of-budget stagnation threshold on the BE fixture itself.
if(TARGET add_gate_be_build AND TARGET add_gate_build AND TARGET fuzzer::concolic
        AND TARGET exec_server_bin)
    add_executable(test_add_gate_be_crash_budget
        test_add_gate_be_crash_budget.cpp)

    add_dependencies(test_add_gate_be_crash_budget
        exec_server_bin
        add_gate_be_build
        add_gate_build)

    target_link_libraries(test_add_gate_be_crash_budget
        PRIVATE
            fuzzer::core
            fuzzer::session
            fuzzer::mutation
            fuzzer::warnings
            GTest::gtest_main)

    file(RELATIVE_PATH _be_crash_budget_exec_server_rel
        "${CMAKE_SOURCE_DIR}" "${CMAKE_BINARY_DIR}/exec-server-bin")
    file(RELATIVE_PATH _be_crash_budget_add_gate_be_rel
        "${CMAKE_SOURCE_DIR}" "${CMAKE_BINARY_DIR}/tests/fixtures/add_gate_be/add_gate_be")
    file(RELATIVE_PATH _be_crash_budget_add_gate_rel
        "${CMAKE_SOURCE_DIR}" "${CMAKE_BINARY_DIR}/tests/fixtures/add_gate/add_gate")

    target_compile_definitions(test_add_gate_be_crash_budget
        PRIVATE
            EXEC_SERVER_BIN="${CMAKE_BINARY_DIR}/exec-server-bin"
            ADD_GATE_BE_BIN="${CMAKE_BINARY_DIR}/tests/fixtures/add_gate_be/add_gate_be"
            ADD_GATE_BIN="${CMAKE_BINARY_DIR}/tests/fixtures/add_gate/add_gate"
            COV_LIBRARY_PATH="$<TARGET_FILE:mlfuzzz3_cov>"
            EXEC_SERVER_REL="${_be_crash_budget_exec_server_rel}"
            ADD_GATE_BE_REL="${_be_crash_budget_add_gate_be_rel}"
            ADD_GATE_REL="${_be_crash_budget_add_gate_rel}"
            COV_LIBRARY_REL="$<PATH:RELATIVE_PATH,$<TARGET_FILE:mlfuzzz3_cov>,${CMAKE_SOURCE_DIR}>")

    # Two binary searches over [1, 200] plus three probes and one control, i.e.
    # roughly twice the donor sweep minus its five repeats. The harness stops
    # itself at kWalltimeBudgetS = 900 s and prints its verdict afterwards, so
    # the ctest ceiling is set above that budget: it is a backstop for a hung
    # process, not the mechanism that ends the sweep.
    gtest_discover_tests(test_add_gate_be_crash_budget
        PROPERTIES TIMEOUT 1200)
else()
    message(STATUS
        "add_gate_be_build / add_gate_build / fuzzer::concolic / exec_server_bin absent; "
        "test_add_gate_be_crash_budget will not be built")
endif()

# task-102, ADR 0047: where the verbatim niche ENDS along the field-WIDTH axis.
# The whole price series was measured at one width, u32; the domain map already
# settles that the BINDING for the `add` form does not depend on width
# (docs/experiments/solver-domain-form-width-endian/report.md:95,
# width_dependent_forms=xor), so what is open is the PRICE and, more sharply,
# whether the gate is still solver-requiring at 16 bits, where the pair space
# is 2^32 instead of 2^64. This target measures the crash budget on the 16-bit
# twin, re-measures the donor's 18 by the same rule in the same process, and
# runs a disarmed ladder up to 1600 iterations on the twin.
#
# Guarded on both fixtures: add_gate_w16_build carries the target under test and
# add_gate_build carries the 32-bit control, which is what licenses the 16-bit
# number to be read at all. No sub_gate — the negative control here is the
# disarmed ladder on the add_gate_w16 fixture itself.
if(TARGET add_gate_w16_build AND TARGET add_gate_build AND TARGET fuzzer::concolic
        AND TARGET exec_server_bin)
    add_executable(test_add_gate_w16_crash_budget
        test_add_gate_w16_crash_budget.cpp)

    add_dependencies(test_add_gate_w16_crash_budget
        exec_server_bin
        add_gate_w16_build
        add_gate_build)

    target_link_libraries(test_add_gate_w16_crash_budget
        PRIVATE
            fuzzer::core
            fuzzer::session
            fuzzer::mutation
            fuzzer::warnings
            GTest::gtest_main)

    file(RELATIVE_PATH _w16_crash_budget_exec_server_rel
        "${CMAKE_SOURCE_DIR}" "${CMAKE_BINARY_DIR}/exec-server-bin")
    file(RELATIVE_PATH _w16_crash_budget_add_gate_w16_rel
        "${CMAKE_SOURCE_DIR}" "${CMAKE_BINARY_DIR}/tests/fixtures/add_gate_w16/add_gate_w16")
    file(RELATIVE_PATH _w16_crash_budget_add_gate_rel
        "${CMAKE_SOURCE_DIR}" "${CMAKE_BINARY_DIR}/tests/fixtures/add_gate/add_gate")

    target_compile_definitions(test_add_gate_w16_crash_budget
        PRIVATE
            EXEC_SERVER_BIN="${CMAKE_BINARY_DIR}/exec-server-bin"
            ADD_GATE_W16_BIN="${CMAKE_BINARY_DIR}/tests/fixtures/add_gate_w16/add_gate_w16"
            ADD_GATE_BIN="${CMAKE_BINARY_DIR}/tests/fixtures/add_gate/add_gate"
            COV_LIBRARY_PATH="$<TARGET_FILE:mlfuzzz3_cov>"
            EXEC_SERVER_REL="${_w16_crash_budget_exec_server_rel}"
            ADD_GATE_W16_REL="${_w16_crash_budget_add_gate_w16_rel}"
            ADD_GATE_REL="${_w16_crash_budget_add_gate_rel}"
            COV_LIBRARY_REL="$<PATH:RELATIVE_PATH,$<TARGET_FILE:mlfuzzz3_cov>,${CMAKE_SOURCE_DIR}>")

    # Two binary searches over [1, 200], three probes, one control ticket and a
    # four-rung disarmed ladder up to 1600 iterations. The harness stops itself
    # at kWalltimeBudgetS = 900 s and prints its verdict afterwards, so the
    # ctest ceiling is set above that budget: it is a backstop for a hung
    # process, not the mechanism that ends the sweep.
    gtest_discover_tests(test_add_gate_w16_crash_budget
        PROPERTIES TIMEOUT 1200)
else()
    message(STATUS
        "add_gate_w16_build / add_gate_build / fuzzer::concolic / exec_server_bin absent; "
        "test_add_gate_w16_crash_budget will not be built")
endif()

# task-104 (ADR-0047): why the width-16 arm never binds while the u32 control
# does. Needs BOTH fixtures in one process, plus fuzzer::concolic for the
# public BuildSystem/SolveForCandidate the harness calls directly.
if(TARGET add_gate_w16_build AND TARGET add_gate_build AND TARGET fuzzer::concolic
        AND TARGET exec_server_bin)
    add_executable(test_w16_binding_gap
        test_w16_binding_gap.cpp)

    add_dependencies(test_w16_binding_gap
        exec_server_bin
        add_gate_w16_build
        add_gate_build)

    target_link_libraries(test_w16_binding_gap
        PRIVATE
            fuzzer::core
            fuzzer::concolic
            fuzzer::session
            fuzzer::mutation
            fuzzer::warnings
            GTest::gtest_main)

    file(RELATIVE_PATH _w16_binding_gap_exec_server_rel
        "${CMAKE_SOURCE_DIR}" "${CMAKE_BINARY_DIR}/exec-server-bin")
    file(RELATIVE_PATH _w16_binding_gap_add_gate_w16_rel
        "${CMAKE_SOURCE_DIR}" "${CMAKE_BINARY_DIR}/tests/fixtures/add_gate_w16/add_gate_w16")
    file(RELATIVE_PATH _w16_binding_gap_add_gate_rel
        "${CMAKE_SOURCE_DIR}" "${CMAKE_BINARY_DIR}/tests/fixtures/add_gate/add_gate")

    target_compile_definitions(test_w16_binding_gap
        PRIVATE
            EXEC_SERVER_BIN="${CMAKE_BINARY_DIR}/exec-server-bin"
            ADD_GATE_W16_BIN="${CMAKE_BINARY_DIR}/tests/fixtures/add_gate_w16/add_gate_w16"
            ADD_GATE_BIN="${CMAKE_BINARY_DIR}/tests/fixtures/add_gate/add_gate"
            COV_LIBRARY_PATH="$<TARGET_FILE:mlfuzzz3_cov>"
            EXEC_SERVER_REL="${_w16_binding_gap_exec_server_rel}"
            ADD_GATE_W16_REL="${_w16_binding_gap_add_gate_w16_rel}"
            ADD_GATE_REL="${_w16_binding_gap_add_gate_rel}"
            COV_LIBRARY_REL="$<PATH:RELATIVE_PATH,$<TARGET_FILE:mlfuzzz3_cov>,${CMAKE_SOURCE_DIR}>")

    gtest_discover_tests(test_w16_binding_gap
        PROPERTIES TIMEOUT 1200)
else()
    message(STATUS
        "add_gate_w16_build / add_gate_build / fuzzer::concolic / exec_server_bin absent; "
        "test_w16_binding_gap will not be built")
endif()

# task-106 (ADR-0047): what breaks the binding at 16 bits — the width marking
# in the branch record or the offset search. One arm (add_gate_w16), live
# records taken the campaign's way, three probes over the same records.
if(TARGET add_gate_w16_build AND TARGET fuzzer::concolic AND TARGET exec_server_bin)
    add_executable(test_w16_binding_hypothesis_split
        test_w16_binding_hypothesis_split.cpp)

    add_dependencies(test_w16_binding_hypothesis_split
        exec_server_bin
        add_gate_w16_build)

    target_link_libraries(test_w16_binding_hypothesis_split
        PRIVATE
            fuzzer::core
            fuzzer::concolic
            fuzzer::session
            fuzzer::mutation
            fuzzer::warnings
            GTest::gtest_main)

    file(RELATIVE_PATH _w16_split_exec_server_rel
        "${CMAKE_SOURCE_DIR}" "${CMAKE_BINARY_DIR}/exec-server-bin")
    file(RELATIVE_PATH _w16_split_add_gate_w16_rel
        "${CMAKE_SOURCE_DIR}" "${CMAKE_BINARY_DIR}/tests/fixtures/add_gate_w16/add_gate_w16")

    target_compile_definitions(test_w16_binding_hypothesis_split
        PRIVATE
            EXEC_SERVER_BIN="${CMAKE_BINARY_DIR}/exec-server-bin"
            ADD_GATE_W16_BIN="${CMAKE_BINARY_DIR}/tests/fixtures/add_gate_w16/add_gate_w16"
            COV_LIBRARY_PATH="$<TARGET_FILE:mlfuzzz3_cov>"
            EXEC_SERVER_REL="${_w16_split_exec_server_rel}"
            ADD_GATE_W16_REL="${_w16_split_add_gate_w16_rel}"
            COV_LIBRARY_REL="$<PATH:RELATIVE_PATH,$<TARGET_FILE:mlfuzzz3_cov>,${CMAKE_SOURCE_DIR}>")

    # One campaign at the fixed budget 200 plus three in-process probes; the
    # harness stops itself at kWalltimeBudgetS = 900 s, so the ctest ceiling is
    # a backstop for a hung process, not the mechanism that ends the run.
    gtest_discover_tests(test_w16_binding_hypothesis_split
        PROPERTIES TIMEOUT 1200)
else()
    message(STATUS
        "add_gate_w16_build / fuzzer::concolic / exec_server_bin absent; "
        "test_w16_binding_hypothesis_split will not be built")
endif()

# task-108, ADR 0047: does the DONOR's rank survive the stagnation threshold?
# The x1.5 correction that task-103 put on point publications was measured at
# the donor's threshold 8 only, and task-100 left the matching cell at the
# production threshold empty (ratios_uncomputable=1). This target measures
# THREE pre-registered seeds — the minimal and the median of task-071's
# ensemble plus the donor itself — at the production threshold 64, so the
# question "is the order at 64 the order at 8" is answered by numbers.
#
# Seeds 1 (t8=10), 17 (t8=12) and 7 (t8=18), chosen from the committed
# raw-seed-spread.txt by value and not by eye; both extremes are shared by
# several seeds, so the tie is broken by task-071's own pre-registration order
# (raw-seed-spread.txt:16). Three points are NOT a median of ten and the
# harness says so in its own verdict line.
#
# The donor runs FIRST as the control of the stand: it must reproduce
# task-081's min_budget=83. Method and interval (1..400) are task-081's,
# unchanged, or the located minima would not be comparable with the number the
# control has to hit.
#
# Guarded on add_gate_build alone, like its threshold64 donor: the whole
# comparison lives on add_gate and needs no sub_gate.
if(TARGET add_gate_build AND TARGET fuzzer::concolic AND TARGET exec_server_bin)
    add_executable(test_add_gate_rank_across_threshold
        test_add_gate_rank_across_threshold.cpp)

    add_dependencies(test_add_gate_rank_across_threshold
        exec_server_bin
        add_gate_build)

    target_link_libraries(test_add_gate_rank_across_threshold
        PRIVATE
            fuzzer::core
            fuzzer::session
            fuzzer::mutation
            fuzzer::warnings
            GTest::gtest_main)

    file(RELATIVE_PATH _rank_across_exec_server_rel
        "${CMAKE_SOURCE_DIR}" "${CMAKE_BINARY_DIR}/exec-server-bin")
    file(RELATIVE_PATH _rank_across_add_gate_rel
        "${CMAKE_SOURCE_DIR}" "${CMAKE_BINARY_DIR}/tests/fixtures/add_gate/add_gate")

    target_compile_definitions(test_add_gate_rank_across_threshold
        PRIVATE
            EXEC_SERVER_BIN="${CMAKE_BINARY_DIR}/exec-server-bin"
            ADD_GATE_BIN="${CMAKE_BINARY_DIR}/tests/fixtures/add_gate/add_gate"
            COV_LIBRARY_PATH="$<TARGET_FILE:mlfuzzz3_cov>"
            EXEC_SERVER_REL="${_rank_across_exec_server_rel}"
            ADD_GATE_REL="${_rank_across_add_gate_rel}"
            COV_LIBRARY_REL="$<PATH:RELATIVE_PATH,$<TARGET_FILE:mlfuzzz3_cov>,${CMAKE_SOURCE_DIR}>")

    # Three seeds x about twenty bounded campaigns each, all at threshold 64:
    # one 400-exec ticket, nine steps of the first-call search over [1, 400],
    # nine of the crash search and two probes around the transition. task-081
    # measured its own three thresholds over the same interval inside 900 s,
    # and 64 is the expensive point of those three, so this unit is registered
    # with 2700 s. The harness enforces that same 2700 s itself
    # (kWalltimeBudgetS) and stops on it rather than being killed by ctest;
    # the ctest ceiling above it is a backstop for a hung process.
    gtest_discover_tests(test_add_gate_rank_across_threshold
        PROPERTIES TIMEOUT 3000)
else()
    message(STATUS
        "add_gate_build / fuzzer::concolic / exec_server_bin absent; "
        "test_add_gate_rank_across_threshold will not be built")
endif()

# task-110 (ADR-0047): where does the seed order break? task-108 measured the
# SAME three seeds at threshold 8 and at the production threshold 64 and found
# a full inversion — 10,12,18 against 107,87,83. This target adds exactly one
# intermediate rung, threshold 32, on task-081's unchanged ladder, so the flip
# is placed in the interval 8–32 or in 32–64 by numbers rather than by
# reading. src/ is not touched: the threshold is a config field the campaign
# already accepts.
#
# The donor seed 7 runs FIRST as the control of the stand: at threshold 32 it
# must reproduce task-081's min_budget=51
# (docs/experiments/solver-add-gate-threshold64/report.md:14). Method and
# interval (1..400) are task-081's, unchanged, or the located minima would not
# be comparable with the number the control has to hit.
#
# Guarded on add_gate_build alone, like its task-108 donor: the whole
# comparison lives on add_gate and needs no sub_gate.
if(TARGET add_gate_build AND TARGET fuzzer::concolic AND TARGET exec_server_bin)
    add_executable(test_add_gate_rank_threshold32
        test_add_gate_rank_threshold32.cpp)

    add_dependencies(test_add_gate_rank_threshold32
        exec_server_bin
        add_gate_build)

    target_link_libraries(test_add_gate_rank_threshold32
        PRIVATE
            fuzzer::core
            fuzzer::session
            fuzzer::mutation
            fuzzer::warnings
            GTest::gtest_main)

    file(RELATIVE_PATH _rank_t32_exec_server_rel
        "${CMAKE_SOURCE_DIR}" "${CMAKE_BINARY_DIR}/exec-server-bin")
    file(RELATIVE_PATH _rank_t32_add_gate_rel
        "${CMAKE_SOURCE_DIR}" "${CMAKE_BINARY_DIR}/tests/fixtures/add_gate/add_gate")

    target_compile_definitions(test_add_gate_rank_threshold32
        PRIVATE
            EXEC_SERVER_BIN="${CMAKE_BINARY_DIR}/exec-server-bin"
            ADD_GATE_BIN="${CMAKE_BINARY_DIR}/tests/fixtures/add_gate/add_gate"
            COV_LIBRARY_PATH="$<TARGET_FILE:mlfuzzz3_cov>"
            EXEC_SERVER_REL="${_rank_t32_exec_server_rel}"
            ADD_GATE_REL="${_rank_t32_add_gate_rel}"
            COV_LIBRARY_REL="$<PATH:RELATIVE_PATH,$<TARGET_FILE:mlfuzzz3_cov>,${CMAKE_SOURCE_DIR}>")

    # Three seeds x about twenty bounded campaigns each, all at threshold 32:
    # one 400-exec ticket, nine steps of the first-call search over [1, 400],
    # nine of the crash search and two probes around the transition. task-108
    # ran the same ladder for the same three seeds at the DEARER threshold 64
    # in 25 s (raw-rank-across-threshold.txt:228, walltime_used_s=25), so the
    # 1800 s the queue registered for this unit is slack and not a target. The
    # harness enforces that same 1800 s itself (kWalltimeBudgetS) and stops on
    # it rather than being killed by ctest; the ctest ceiling above it is a
    # backstop for a hung process.
    gtest_discover_tests(test_add_gate_rank_threshold32
        PROPERTIES TIMEOUT 2100)
else()
    message(STATUS
        "add_gate_build / fuzzer::concolic / exec_server_bin absent; "
        "test_add_gate_rank_threshold32 will not be built")
endif()

# task-107 (ADR-0039): clean Z3 time split by outcome class. Needs BOTH
# fixtures in one process — add_gate (arm b, the "reached Z3" class) and
# add_gate_w16 (arm c, the "died on binding" class) — and reads
# CampaignStats::concolic_time_ms_total, the timer already standing at
# src/core/campaign.cpp:192-196. src/ is not touched.
if(TARGET add_gate_build AND TARGET add_gate_w16_build AND TARGET fuzzer::concolic
        AND TARGET exec_server_bin)
    add_executable(test_solver_time_by_outcome
        test_solver_time_by_outcome.cpp)

    add_dependencies(test_solver_time_by_outcome
        exec_server_bin
        add_gate_build
        add_gate_w16_build)

    target_link_libraries(test_solver_time_by_outcome
        PRIVATE
            fuzzer::core
            fuzzer::session
            fuzzer::mutation
            fuzzer::warnings
            GTest::gtest_main)

    file(RELATIVE_PATH _time_by_outcome_exec_server_rel
        "${CMAKE_SOURCE_DIR}" "${CMAKE_BINARY_DIR}/exec-server-bin")
    file(RELATIVE_PATH _time_by_outcome_add_gate_rel
        "${CMAKE_SOURCE_DIR}" "${CMAKE_BINARY_DIR}/tests/fixtures/add_gate/add_gate")
    file(RELATIVE_PATH _time_by_outcome_add_gate_w16_rel
        "${CMAKE_SOURCE_DIR}" "${CMAKE_BINARY_DIR}/tests/fixtures/add_gate_w16/add_gate_w16")

    target_compile_definitions(test_solver_time_by_outcome
        PRIVATE
            EXEC_SERVER_BIN="${CMAKE_BINARY_DIR}/exec-server-bin"
            ADD_GATE_BIN="${CMAKE_BINARY_DIR}/tests/fixtures/add_gate/add_gate"
            ADD_GATE_W16_BIN="${CMAKE_BINARY_DIR}/tests/fixtures/add_gate_w16/add_gate_w16"
            COV_LIBRARY_PATH="$<TARGET_FILE:mlfuzzz3_cov>"
            EXEC_SERVER_REL="${_time_by_outcome_exec_server_rel}"
            ADD_GATE_REL="${_time_by_outcome_add_gate_rel}"
            ADD_GATE_W16_REL="${_time_by_outcome_add_gate_w16_rel}"
            COV_LIBRARY_REL="$<PATH:RELATIVE_PATH,$<TARGET_FILE:mlfuzzz3_cov>,${CMAKE_SOURCE_DIR}>")

    # Two bounded campaigns at budget 200, no search around it. The harness
    # stops itself at kWalltimeBudgetS = 900 s and prints its summary
    # afterwards, so the ctest ceiling above that budget is a backstop for a
    # hung process, not the mechanism that ends the run.
    gtest_discover_tests(test_solver_time_by_outcome
        PROPERTIES TIMEOUT 1200)
else()
    message(STATUS
        "add_gate_build / add_gate_w16_build / fuzzer::concolic / exec_server_bin absent; "
        "test_solver_time_by_outcome will not be built")
endif()

# task-109, ADR 0047: the empty cell of task-100 — the ensemble of ten seeds at
# the PRODUCTION stagnation threshold 64.
#
# task-100 left exactly one denominator unmeasured
# (docs/experiments/solver-niche-ratio-denominators/report.md:96,
# ratios_uncomputable=1) and task-108 then proved the T=8 correction does not
# travel across the threshold (order_preserved=no,
# correction_transferable=no). This harness measures the denominator directly:
# all ten of task-071's pre-registered seeds at threshold 64, by task-081's
# unchanged bisection over 1..400, with task-108's three already-published
# seeds re-run first as the control of the stand.
#
# Same guard shape as test_add_gate_rank_across_threshold above: one fixture
# (add_gate), no sub_gate.
if(TARGET add_gate_build AND TARGET fuzzer::concolic AND TARGET exec_server_bin)
    add_executable(test_add_gate_ensemble_threshold64
        test_add_gate_ensemble_threshold64.cpp)

    add_dependencies(test_add_gate_ensemble_threshold64
        exec_server_bin
        add_gate_build)

    target_link_libraries(test_add_gate_ensemble_threshold64
        PRIVATE
            fuzzer::core
            fuzzer::session
            fuzzer::mutation
            fuzzer::warnings
            GTest::gtest_main)

    file(RELATIVE_PATH _ensemble_t64_exec_server_rel
        "${CMAKE_SOURCE_DIR}" "${CMAKE_BINARY_DIR}/exec-server-bin")
    file(RELATIVE_PATH _ensemble_t64_add_gate_rel
        "${CMAKE_SOURCE_DIR}" "${CMAKE_BINARY_DIR}/tests/fixtures/add_gate/add_gate")

    target_compile_definitions(test_add_gate_ensemble_threshold64
        PRIVATE
            EXEC_SERVER_BIN="${CMAKE_BINARY_DIR}/exec-server-bin"
            ADD_GATE_BIN="${CMAKE_BINARY_DIR}/tests/fixtures/add_gate/add_gate"
            COV_LIBRARY_PATH="$<TARGET_FILE:mlfuzzz3_cov>"
            EXEC_SERVER_REL="${_ensemble_t64_exec_server_rel}"
            ADD_GATE_REL="${_ensemble_t64_add_gate_rel}"
            COV_LIBRARY_REL="$<PATH:RELATIVE_PATH,$<TARGET_FILE:mlfuzzz3_cov>,${CMAKE_SOURCE_DIR}>")

    # Ten seeds x about twenty bounded campaigns each, all at threshold 64.
    # task-108 spent walltime_used_s=25 on three of these seeds over the same
    # interval at the same threshold
    # (docs/experiments/solver-rank-across-threshold/raw-rank-across-threshold.txt:228),
    # so ten are of the order of a minute and a half. The harness enforces its
    # OWN hard budget of 1800 s and stops cleanly on it, naming every probe it
    # did not run; this TIMEOUT is only the outer fence and is set above that
    # budget so the harness's own stop, not ctest's kill, is what a reader sees.
    gtest_discover_tests(test_add_gate_ensemble_threshold64
        PROPERTIES TIMEOUT 2400)
else()
    message(STATUS
        "add_gate_build / fuzzer::concolic / exec_server_bin absent; "
        "test_add_gate_ensemble_threshold64 will not be built")
endif()

# task-111, ADR 0047: the eighth cell of the task-082 cost matrix — the price of
# the verbatim niche on the BIG-endian gate at the PRODUCTION stagnation
# threshold 64.
#
# task-080 measured the byte-order axis at the donor threshold T = 8 only
# (docs/experiments/solver-add-gate-be-crash-budget/report.md:13,
# min_budget_be=11 against the little-endian 18), while task-081 lifted the
# little-endian arm to 83 at T = 64
# (docs/experiments/solver-add-gate-threshold64/report.md:12). The matrix
# therefore compares a T = 64 cell against a T = 8 cell — the class of mismatch
# task-101 already found in it once. This harness takes both arms at T = 64 in
# ONE process: the big-endian gate under test and the little-endian donor as
# the control of the stand, which must reproduce 83.
#
# Same guard shape as test_add_gate_be_crash_budget above: both fixtures, no
# sub_gate. The negative control is the out-of-budget stagnation threshold on
# the big-endian fixture itself.
if(TARGET add_gate_be_build AND TARGET add_gate_build AND TARGET fuzzer::concolic
        AND TARGET exec_server_bin)
    add_executable(test_add_gate_be_threshold64
        test_add_gate_be_threshold64.cpp)

    add_dependencies(test_add_gate_be_threshold64
        exec_server_bin
        add_gate_be_build
        add_gate_build)

    target_link_libraries(test_add_gate_be_threshold64
        PRIVATE
            fuzzer::core
            fuzzer::session
            fuzzer::mutation
            fuzzer::warnings
            GTest::gtest_main)

    file(RELATIVE_PATH _be_threshold64_exec_server_rel
        "${CMAKE_SOURCE_DIR}" "${CMAKE_BINARY_DIR}/exec-server-bin")
    file(RELATIVE_PATH _be_threshold64_add_gate_be_rel
        "${CMAKE_SOURCE_DIR}" "${CMAKE_BINARY_DIR}/tests/fixtures/add_gate_be/add_gate_be")
    file(RELATIVE_PATH _be_threshold64_add_gate_rel
        "${CMAKE_SOURCE_DIR}" "${CMAKE_BINARY_DIR}/tests/fixtures/add_gate/add_gate")

    target_compile_definitions(test_add_gate_be_threshold64
        PRIVATE
            EXEC_SERVER_BIN="${CMAKE_BINARY_DIR}/exec-server-bin"
            ADD_GATE_BE_BIN="${CMAKE_BINARY_DIR}/tests/fixtures/add_gate_be/add_gate_be"
            ADD_GATE_BIN="${CMAKE_BINARY_DIR}/tests/fixtures/add_gate/add_gate"
            COV_LIBRARY_PATH="$<TARGET_FILE:mlfuzzz3_cov>"
            EXEC_SERVER_REL="${_be_threshold64_exec_server_rel}"
            ADD_GATE_BE_REL="${_be_threshold64_add_gate_be_rel}"
            ADD_GATE_REL="${_be_threshold64_add_gate_rel}"
            COV_LIBRARY_REL="$<PATH:RELATIVE_PATH,$<TARGET_FILE:mlfuzzz3_cov>,${CMAKE_SOURCE_DIR}>")

    # Two bisections over [1, 400] plus three transition probes and one
    # disarmed control, i.e. of the order of two dozen bounded campaigns at
    # threshold 64. task-109 spent walltime_used_s=86 on ten such ladders
    # (docs/experiments/solver-niche-ensemble-threshold64/report.md:226), so two
    # are a matter of seconds. The harness enforces its OWN hard budget of
    # 1800 s and prints timeout_hit=yes if it is spent; this TIMEOUT is only the
    # outer fence and sits above that budget, so what a reader sees is the
    # harness's own stop rather than ctest's kill.
    gtest_discover_tests(test_add_gate_be_threshold64
        PROPERTIES TIMEOUT 2400)
else()
    message(STATUS
        "add_gate_be_build / add_gate_build / fuzzer::concolic / exec_server_bin absent; "
        "test_add_gate_be_threshold64 will not be built")
endif()

# task-113 (ADR-0047): the big-endian arm at T = 64 over TEN seeds, not one.
# task-111 published be_min_budget_t64=92 on the donor seed alone and said so
# in its own verdict (seeds=1, seeds_are_a_median=no), while the little-endian
# arm at the same threshold has a MEDIAN over ten seeds, 83
# (docs/experiments/solver-niche-ensemble-threshold64/report.md:226). The
# published ratio 1.11 therefore divides a point by a median. This harness
# takes the missing median: the same ten pre-registered seeds of task-103, the
# same ladder, one process. Only the big-endian fixture is needed — the
# little-endian side is quoted, not re-measured.
if(TARGET add_gate_be_build AND TARGET fuzzer::concolic AND TARGET exec_server_bin)
    add_executable(test_add_gate_be_ensemble_threshold64
        test_add_gate_be_ensemble_threshold64.cpp)

    add_dependencies(test_add_gate_be_ensemble_threshold64
        exec_server_bin
        add_gate_be_build)

    target_link_libraries(test_add_gate_be_ensemble_threshold64
        PRIVATE
            fuzzer::core
            fuzzer::session
            fuzzer::mutation
            fuzzer::warnings
            GTest::gtest_main)

    file(RELATIVE_PATH _be_ens64_exec_server_rel
        "${CMAKE_SOURCE_DIR}" "${CMAKE_BINARY_DIR}/exec-server-bin")
    file(RELATIVE_PATH _be_ens64_add_gate_be_rel
        "${CMAKE_SOURCE_DIR}" "${CMAKE_BINARY_DIR}/tests/fixtures/add_gate_be/add_gate_be")

    target_compile_definitions(test_add_gate_be_ensemble_threshold64
        PRIVATE
            EXEC_SERVER_BIN="${CMAKE_BINARY_DIR}/exec-server-bin"
            ADD_GATE_BE_BIN="${CMAKE_BINARY_DIR}/tests/fixtures/add_gate_be/add_gate_be"
            COV_LIBRARY_PATH="$<TARGET_FILE:mlfuzzz3_cov>"
            EXEC_SERVER_REL="${_be_ens64_exec_server_rel}"
            ADD_GATE_BE_REL="${_be_ens64_add_gate_be_rel}"
            COV_LIBRARY_REL="$<PATH:RELATIVE_PATH,$<TARGET_FILE:mlfuzzz3_cov>,${CMAKE_SOURCE_DIR}>")

    # Ten bisections over [1, 400] plus two transition probes each, i.e. of the
    # order of 120 bounded campaigns at threshold 64. task-109 spent
    # walltime_used_s=86 on ten such ladders on the little-endian fixture
    # (docs/experiments/solver-niche-ensemble-threshold64/report.md:226); the
    # big-endian one costs the same order. The harness enforces its OWN hard
    # budget of 1800 s and prints timeout_hit=yes if it is spent; this TIMEOUT
    # is only the outer fence and sits above that budget, so what a reader sees
    # is the harness's own stop rather than ctest's kill.
    gtest_discover_tests(test_add_gate_be_ensemble_threshold64
        PROPERTIES TIMEOUT 2400)
else()
    message(STATUS
        "add_gate_be_build / fuzzer::concolic / exec_server_bin absent; "
        "test_add_gate_be_ensemble_threshold64 will not be built")
endif()

# task-112 (ADR-0047): where EXACTLY does the seed order break? task-110 put
# the break inside 8–32 by measuring the rung 32; the interval itself was
# never split. This target adds exactly one rung, threshold 16, on task-081's
# unchanged ladder for the same three seeds, so the interval halves by numbers
# rather than by reading. src/ is not touched: the threshold is a config field
# the campaign already accepts.
#
# The control is a WHOLE LADDER, not a quoted number: the donor seed 7 runs
# FIRST at threshold 32 and must reproduce task-110's min_budget=51
# (docs/experiments/solver-rank-threshold32/report.md:14). It shares the
# process with the three new ladders, so the comparison can never be published
# beside a control from a different run. Method and interval (1..400) are
# task-081's, unchanged, or the located minima would not be comparable with the
# number the control has to hit.
#
# Guarded on add_gate_build alone, like its task-110 donor: the whole
# comparison lives on add_gate and needs no sub_gate.
if(TARGET add_gate_build AND TARGET fuzzer::concolic AND TARGET exec_server_bin)
    add_executable(test_add_gate_rank_threshold16
        test_add_gate_rank_threshold16.cpp)

    add_dependencies(test_add_gate_rank_threshold16
        exec_server_bin
        add_gate_build)

    target_link_libraries(test_add_gate_rank_threshold16
        PRIVATE
            fuzzer::core
            fuzzer::session
            fuzzer::mutation
            fuzzer::warnings
            GTest::gtest_main)

    file(RELATIVE_PATH _rank_t16_exec_server_rel
        "${CMAKE_SOURCE_DIR}" "${CMAKE_BINARY_DIR}/exec-server-bin")
    file(RELATIVE_PATH _rank_t16_add_gate_rel
        "${CMAKE_SOURCE_DIR}" "${CMAKE_BINARY_DIR}/tests/fixtures/add_gate/add_gate")

    target_compile_definitions(test_add_gate_rank_threshold16
        PRIVATE
            EXEC_SERVER_BIN="${CMAKE_BINARY_DIR}/exec-server-bin"
            ADD_GATE_BIN="${CMAKE_BINARY_DIR}/tests/fixtures/add_gate/add_gate"
            COV_LIBRARY_PATH="$<TARGET_FILE:mlfuzzz3_cov>"
            EXEC_SERVER_REL="${_rank_t16_exec_server_rel}"
            ADD_GATE_REL="${_rank_t16_add_gate_rel}"
            COV_LIBRARY_REL="$<PATH:RELATIVE_PATH,$<TARGET_FILE:mlfuzzz3_cov>,${CMAKE_SOURCE_DIR}>")

    # FOUR ladders in one process, not three: the control at threshold 32 plus
    # the three new ones at 16. Each is about twenty bounded campaigns — one
    # 400-exec ticket, nine steps of the first-call search over [1, 400], nine
    # of the crash search and two probes around the transition. task-110 ran
    # three such ladders at the DEARER threshold 32 in tens of seconds and 16
    # is cheaper by construction, so the 1800 s the queue registered for this
    # unit is slack and not a target. The harness enforces that same 1800 s
    # itself (kWalltimeBudgetS) and stops on it rather than being killed by
    # ctest; the ctest ceiling above it is a backstop for a hung process.
    gtest_discover_tests(test_add_gate_rank_threshold16
        PROPERTIES TIMEOUT 2100)
else()
    message(STATUS
        "add_gate_build / fuzzer::concolic / exec_server_bin absent; "
        "test_add_gate_rank_threshold16 will not be built")
endif()

# E0 (recon, ADR-0047): развёртка по target_index на реальной цели. Продукт
# инвертирует только последнюю запись пути (src/concolic/concolic.cpp:255),
# и этот выбор никогда не измерялся отдельно от свойств самого пути. Харнесс
# снимает путь каждого из 21 сида libtiff кампанийной связкой и крутит по
# нему тот же solver::SolveInverted с каждым target_index.
#
# Почему цель и корпус приходят путями, а не целями CMake: и бинарь, и сиды
# лежат в benchmarks/magma/vendor/ — это не часть сборки, каталог не под
# git и собирается отдельными скриптами benchmarks/magma/build_tiff*.sh.
# Поэтому их отсутствие — не ошибка конфигурации, а повод пропустить тест;
# проверка лежит в MissingArtifact() и печатает ОТНОСИТЕЛЬНЫЕ пути.
#
# add_gate нужен здесь как отрицательный контроль стенда: на нём кандидат,
# собранный обратной записью харнесса, обязан уронить цель.
if(TARGET add_gate_build AND TARGET fuzzer::concolic AND TARGET exec_server_bin)
    add_executable(test_solver_target_index_sweep
        test_solver_target_index_sweep.cpp)

    add_dependencies(test_solver_target_index_sweep
        exec_server_bin
        add_gate_build)

    target_link_libraries(test_solver_target_index_sweep
        PRIVATE
            fuzzer::core
            fuzzer::concolic
            fuzzer::session
            fuzzer::coverage
            fuzzer::warnings
            GTest::gtest_main)

    file(RELATIVE_PATH _tis_exec_server_rel
        "${CMAKE_SOURCE_DIR}" "${CMAKE_BINARY_DIR}/exec-server-bin")
    file(RELATIVE_PATH _tis_add_gate_rel
        "${CMAKE_SOURCE_DIR}" "${CMAKE_BINARY_DIR}/tests/fixtures/add_gate/add_gate")

    target_compile_definitions(test_solver_target_index_sweep
        PRIVATE
            EXEC_SERVER_BIN="${CMAKE_BINARY_DIR}/exec-server-bin"
            ADD_GATE_BIN="${CMAKE_BINARY_DIR}/tests/fixtures/add_gate/add_gate"
            COV_LIBRARY_PATH="$<TARGET_FILE:mlfuzzz3_cov>"
            EXEC_SERVER_REL="${_tis_exec_server_rel}"
            ADD_GATE_REL="${_tis_add_gate_rel}"
            COV_LIBRARY_REL="$<PATH:RELATIVE_PATH,$<TARGET_FILE:mlfuzzz3_cov>,${CMAKE_SOURCE_DIR}>"
            TIFF_TARGET_BIN="${CMAKE_SOURCE_DIR}/benchmarks/magma/vendor/out-tiff/tiff_read_rgba_fuzzer"
            TIFF_TARGET_REL="benchmarks/magma/vendor/out-tiff/tiff_read_rgba_fuzzer"
            TIFF_CORPUS_DIR="${CMAKE_SOURCE_DIR}/benchmarks/magma/vendor/magma-src/targets/libtiff/corpus/tiff_read_rgba_fuzzer"
            TIFF_CORPUS_REL="benchmarks/magma/vendor/magma-src/targets/libtiff/corpus/tiff_read_rgba_fuzzer")

    # Харнесс держит собственный бюджет стены 5400 с (kWalltimeBudgetS) и
    # останавливается по нему сам, печатая stop_reason=walltime. Потолок
    # ctest выше него — страховка от зависшего процесса, а не цель.
    gtest_discover_tests(test_solver_target_index_sweep
        PROPERTIES TIMEOUT 6600)

    # E2/E3 (ADR-0047): перепись привязок и цена построения системы на
    # реальной цели. Солвер не вызывается; бинарь цели и корпус — те же, что
    # у развёртки E0. Регистрация повторяет test_solver_target_index_sweep.
    add_executable(test_binding_census
        test_binding_census.cpp)

    add_dependencies(test_binding_census
        exec_server_bin
        add_gate_build)

    target_link_libraries(test_binding_census
        PRIVATE
            fuzzer::core
            fuzzer::concolic
            fuzzer::session
            fuzzer::coverage
            fuzzer::warnings
            GTest::gtest_main)

    file(RELATIVE_PATH _bc_exec_server_rel
        "${CMAKE_SOURCE_DIR}" "${CMAKE_BINARY_DIR}/exec-server-bin")
    file(RELATIVE_PATH _bc_add_gate_rel
        "${CMAKE_SOURCE_DIR}" "${CMAKE_BINARY_DIR}/tests/fixtures/add_gate/add_gate")

    target_compile_definitions(test_binding_census
        PRIVATE
            EXEC_SERVER_BIN="${CMAKE_BINARY_DIR}/exec-server-bin"
            ADD_GATE_BIN="${CMAKE_BINARY_DIR}/tests/fixtures/add_gate/add_gate"
            COV_LIBRARY_PATH="$<TARGET_FILE:mlfuzzz3_cov>"
            EXEC_SERVER_REL="${_bc_exec_server_rel}"
            ADD_GATE_REL="${_bc_add_gate_rel}"
            COV_LIBRARY_REL="$<PATH:RELATIVE_PATH,$<TARGET_FILE:mlfuzzz3_cov>,${CMAKE_SOURCE_DIR}>"
            TIFF_TARGET_BIN="${CMAKE_SOURCE_DIR}/benchmarks/magma/vendor/out-tiff/tiff_read_rgba_fuzzer"
            TIFF_TARGET_REL="benchmarks/magma/vendor/out-tiff/tiff_read_rgba_fuzzer"
            TIFF_CORPUS_DIR="${CMAKE_SOURCE_DIR}/benchmarks/magma/vendor/magma-src/targets/libtiff/corpus/tiff_read_rgba_fuzzer"
            TIFF_CORPUS_REL="benchmarks/magma/vendor/magma-src/targets/libtiff/corpus/tiff_read_rgba_fuzzer")

    # Лимиты стены харнесса: перепись 1500 с, цена построения 2700 с. Потолок
    # ctest выше них — страховка от зависшего процесса, а не цель.
    gtest_discover_tests(test_binding_census
        PROPERTIES TIMEOUT 3300)

    add_executable(test_solver_prefix_sweep
        test_solver_prefix_sweep.cpp)

    add_dependencies(test_solver_prefix_sweep
        exec_server_bin
        add_gate_build)

    target_link_libraries(test_solver_prefix_sweep
        PRIVATE
            fuzzer::core
            fuzzer::concolic
            fuzzer::session
            fuzzer::coverage
            fuzzer::warnings
            GTest::gtest_main)

    file(RELATIVE_PATH _pfx_exec_server_rel
        "${CMAKE_SOURCE_DIR}" "${CMAKE_BINARY_DIR}/exec-server-bin")
    file(RELATIVE_PATH _pfx_add_gate_rel
        "${CMAKE_SOURCE_DIR}" "${CMAKE_BINARY_DIR}/tests/fixtures/add_gate/add_gate")

    target_compile_definitions(test_solver_prefix_sweep
        PRIVATE
            EXEC_SERVER_BIN="${CMAKE_BINARY_DIR}/exec-server-bin"
            ADD_GATE_BIN="${CMAKE_BINARY_DIR}/tests/fixtures/add_gate/add_gate"
            COV_LIBRARY_PATH="$<TARGET_FILE:mlfuzzz3_cov>"
            EXEC_SERVER_REL="${_pfx_exec_server_rel}"
            ADD_GATE_REL="${_pfx_add_gate_rel}"
            COV_LIBRARY_REL="$<PATH:RELATIVE_PATH,$<TARGET_FILE:mlfuzzz3_cov>,${CMAKE_SOURCE_DIR}>"
            TIFF_TARGET_BIN="${CMAKE_SOURCE_DIR}/benchmarks/magma/vendor/out-tiff/tiff_read_rgba_fuzzer"
            TIFF_TARGET_REL="benchmarks/magma/vendor/out-tiff/tiff_read_rgba_fuzzer"
            TIFF_CORPUS_DIR="${CMAKE_SOURCE_DIR}/benchmarks/magma/vendor/magma-src/targets/libtiff/corpus/tiff_read_rgba_fuzzer"
            TIFF_CORPUS_REL="benchmarks/magma/vendor/magma-src/targets/libtiff/corpus/tiff_read_rgba_fuzzer")

    # Лестница починок ADR-0049 на том же стенде. Цель — та же цель E1, плюс
    # два синтетических гейта для контролей К1 и К2.
    add_executable(test_solver_fix_ladder
        test_solver_fix_ladder.cpp)

    add_dependencies(test_solver_fix_ladder
        exec_server_bin
        add_gate_build
        add_gate_w16_build)

    target_link_libraries(test_solver_fix_ladder
        PRIVATE
            fuzzer::core
            fuzzer::concolic
            fuzzer::session
            fuzzer::coverage
            fuzzer::warnings
            GTest::gtest_main)

    target_compile_definitions(test_solver_fix_ladder
        PRIVATE
            EXEC_SERVER_BIN="${CMAKE_BINARY_DIR}/exec-server-bin"
            ADD_GATE_BIN="${CMAKE_BINARY_DIR}/tests/fixtures/add_gate/add_gate"
            ADD_GATE_W16_BIN="${CMAKE_BINARY_DIR}/tests/fixtures/add_gate_w16/add_gate_w16"
            COV_LIBRARY_PATH="$<TARGET_FILE:mlfuzzz3_cov>"
            EXEC_SERVER_REL="${_pfx_exec_server_rel}"
            ADD_GATE_REL="${_pfx_add_gate_rel}"
            COV_LIBRARY_REL="$<PATH:RELATIVE_PATH,$<TARGET_FILE:mlfuzzz3_cov>,${CMAKE_SOURCE_DIR}>"
            TIFF_TARGET_BIN="${CMAKE_SOURCE_DIR}/benchmarks/magma/vendor/out-tiff/tiff_read_rgba_fuzzer"
            TIFF_TARGET_REL="benchmarks/magma/vendor/out-tiff/tiff_read_rgba_fuzzer"
            TIFF_CORPUS_DIR="${CMAKE_SOURCE_DIR}/benchmarks/magma/vendor/magma-src/targets/libtiff/corpus/tiff_read_rgba_fuzzer"
            TIFF_CORPUS_REL="benchmarks/magma/vendor/magma-src/targets/libtiff/corpus/tiff_read_rgba_fuzzer")

    # В ctest НЕ регистрируется намеренно. Восемь плеч по бюджету стены
    # 5400 с — это до двенадцати часов, и гейт стал бы непроходимым: три уже
    # зарегистрированные развёртки (target-index, binding-census, prefix)
    # стоят ему около четырёх с половиной часов. Развёртка запускается своим
    # run.sh, как и остальные длинные замеры.

    # Побайтовый дамп систем на стенде E1 — эталон для рефакторинга привязки
    # операндов (ADR-0050). Пишет по файлу на (плечо, сид) в SYSDUMP_OUT_DIR;
    # в ctest не регистрируется: около десяти минут стены и вывод в каталог,
    # который задаёт docs/experiments/binding-provider-regress/run.sh.
    add_executable(test_system_dump
        test_system_dump.cpp)

    add_dependencies(test_system_dump
        exec_server_bin)

    target_link_libraries(test_system_dump
        PRIVATE
            fuzzer::core
            fuzzer::concolic
            fuzzer::session
            fuzzer::coverage
            fuzzer::warnings
            GTest::gtest_main)

    target_compile_definitions(test_system_dump
        PRIVATE
            EXEC_SERVER_BIN="${CMAKE_BINARY_DIR}/exec-server-bin"
            COV_LIBRARY_PATH="$<TARGET_FILE:mlfuzzz3_cov>"
            EXEC_SERVER_REL="${_pfx_exec_server_rel}"
            COV_LIBRARY_REL="$<PATH:RELATIVE_PATH,$<TARGET_FILE:mlfuzzz3_cov>,${CMAKE_SOURCE_DIR}>"
            TIFF_TARGET_BIN="${CMAKE_SOURCE_DIR}/benchmarks/magma/vendor/out-tiff/tiff_read_rgba_fuzzer"
            TIFF_TARGET_REL="benchmarks/magma/vendor/out-tiff/tiff_read_rgba_fuzzer"
            TIFF_CORPUS_DIR="${CMAKE_SOURCE_DIR}/benchmarks/magma/vendor/magma-src/targets/libtiff/corpus/tiff_read_rgba_fuzzer"
            TIFF_CORPUS_REL="benchmarks/magma/vendor/magma-src/targets/libtiff/corpus/tiff_read_rgba_fuzzer")

    # Трассы записей сравнения на стенде E1: сид, повтор сида и сид с одним
    # возмущённым байтом, с номером повтора сайта (task-270). Пишет в
    # OCCALIGN_OUT_DIR; в ctest не регистрируется — запускается
    # docs/experiments/branch-occurrence-alignment/run.sh.
    add_executable(test_occurrence_alignment
        test_occurrence_alignment.cpp)

    add_dependencies(test_occurrence_alignment
        exec_server_bin)

    target_link_libraries(test_occurrence_alignment
        PRIVATE
            fuzzer::core
            fuzzer::session
            fuzzer::coverage
            fuzzer::warnings
            GTest::gtest_main)

    target_compile_definitions(test_occurrence_alignment
        PRIVATE
            EXEC_SERVER_BIN="${CMAKE_BINARY_DIR}/exec-server-bin"
            COV_LIBRARY_PATH="$<TARGET_FILE:mlfuzzz3_cov>"
            EXEC_SERVER_REL="${_pfx_exec_server_rel}"
            COV_LIBRARY_REL="$<PATH:RELATIVE_PATH,$<TARGET_FILE:mlfuzzz3_cov>,${CMAKE_SOURCE_DIR}>"
            TIFF_TARGET_BIN="${CMAKE_SOURCE_DIR}/benchmarks/magma/vendor/out-tiff/tiff_read_rgba_fuzzer"
            TIFF_TARGET_REL="benchmarks/magma/vendor/out-tiff/tiff_read_rgba_fuzzer"
            TIFF_CORPUS_DIR="${CMAKE_SOURCE_DIR}/benchmarks/magma/vendor/magma-src/targets/libtiff/corpus/tiff_read_rgba_fuzzer"
            TIFF_CORPUS_REL="benchmarks/magma/vendor/magma-src/targets/libtiff/corpus/tiff_read_rgba_fuzzer")

    # E1 (ADR-0047): префиксная форма инверсии на стенде E0. Харнесс держит
    # собственный бюджет стены 5400 с (kWalltimeBudgetS) и
    # останавливается по нему сам, печатая stop_reason=walltime. Потолок
    # ctest выше него — страховка от зависшего процесса, а не цель.
    gtest_discover_tests(test_solver_prefix_sweep
        PROPERTIES TIMEOUT 6600)
else()
    message(STATUS
        "add_gate_build / fuzzer::concolic / exec_server_bin absent; "
        "test_solver_target_index_sweep will not be built")
endif()

# task-191 (ADR-0049): цена вызова концолики В КАМПАНИИ, разложенная на
# построение системы и решение, с F1 и без. Кампания на add_gate, 21 сид,
# сырьё по каждому вызову. Нужна только фикстура add_gate.
if(TARGET add_gate_build AND TARGET fuzzer::concolic AND TARGET exec_server_bin)
    add_executable(campaign_call_cost_split_harness
        campaign_call_cost_split_harness.cpp)

    add_dependencies(campaign_call_cost_split_harness
        exec_server_bin
        add_gate_build)

    target_link_libraries(campaign_call_cost_split_harness
        PRIVATE
            fuzzer::core
            fuzzer::session
            fuzzer::mutation
            fuzzer::warnings
            GTest::gtest_main)

    file(RELATIVE_PATH _ccs_exec_server_rel
        "${CMAKE_SOURCE_DIR}" "${CMAKE_BINARY_DIR}/exec-server-bin")
    file(RELATIVE_PATH _ccs_add_gate_rel
        "${CMAKE_SOURCE_DIR}" "${CMAKE_BINARY_DIR}/tests/fixtures/add_gate/add_gate")

    target_compile_definitions(campaign_call_cost_split_harness
        PRIVATE
            EXEC_SERVER_BIN="${CMAKE_BINARY_DIR}/exec-server-bin"
            ADD_GATE_BIN="${CMAKE_BINARY_DIR}/tests/fixtures/add_gate/add_gate"
            COV_LIBRARY_PATH="$<TARGET_FILE:mlfuzzz3_cov>"
            EXEC_SERVER_REL="${_ccs_exec_server_rel}"
            ADD_GATE_REL="${_ccs_add_gate_rel}"
            COV_LIBRARY_REL="$<PATH:RELATIVE_PATH,$<TARGET_FILE:mlfuzzz3_cov>,${CMAKE_SOURCE_DIR}>")

    # В ctest НЕ регистрируется намеренно: 21 сид на два плеча, каждая
    # кампания дважды (чанками и целиком) — 84 кампании по 200 прогонов, это
    # минуты стены, а бюджет самого харнесса 1200 с (kWalltimeBudgetS).
    # Длинные развёртки в ctest уже стоят гейту часов. Запуск — своим run.sh.
else()
    message(STATUS
        "add_gate_build / fuzzer::concolic / exec_server_bin absent; "
        "campaign_call_cost_split_harness will not be built")
endif()
