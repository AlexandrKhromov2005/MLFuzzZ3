// End-to-end MVP campaign integration test (ADR 0029). Drives the real
// `fuzzer` CLI binary against the pass-instrumented cov_stdin fixture
// (Milestone 1.5). The CLI itself brings up a real exec-server
// subprocess (not a mock), runs a bounded mutation campaign, and writes
// corpus/ + metrics.jsonl. The test verifies that:
//
//   1. the campaign runs N iterations and the CLI exits 0 — the loop
//      does not crash itself while driving the target;
//   2. the corpus grows beyond the single bootstrap input as byteflip
//      mutations discover the cov_stdin branches (A / B / other);
//   3. metrics.jsonl is written and non-empty.
//
// The crash/hang/ipc-error branches of the loop are exercised
// deterministically by the unit test (tests/unit/core/test_campaign.cpp)
// with a scripted runner, because cov_stdin is non-crashing by design.

#include <fcntl.h>
#include <gtest/gtest.h>
#include <sys/wait.h>
#include <unistd.h>
#include <yaml-cpp/yaml.h>

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <system_error>
#include <vector>

namespace {

bool PathExecutable(const std::string& path) {
    return ::access(path.c_str(), R_OK | X_OK) == 0;
}

bool PathReadable(const std::string& path) {
    return ::access(path.c_str(), R_OK) == 0;
}

std::size_t CountRegularFiles(const std::filesystem::path& dir) {
    std::error_code ec;
    std::size_t count = 0;
    for (const auto& entry : std::filesystem::directory_iterator(dir, ec)) {
        if (entry.is_regular_file()) {
            ++count;
        }
    }
    return count;
}

// Largest regular file under dir, or 0 if there are none. Used to tell the
// cov_parser crash conditions apart: a crash input longer than the base
// length L is crash B, otherwise crash A (ADR 0032).
std::uintmax_t MaxRegularFileSize(const std::filesystem::path& dir) {
    std::error_code ec;
    std::uintmax_t largest = 0;
    for (const auto& entry : std::filesystem::directory_iterator(dir, ec)) {
        if (entry.is_regular_file()) {
            largest = std::max(largest, entry.file_size(ec));
        }
    }
    return largest;
}

// RunBinary fork+exec's argv[0] with stdio redirected to /dev/null and
// returns the child's exit code, or -1 if it did not exit normally.
int RunBinary(const std::vector<std::string>& args) {
    const pid_t pid = ::fork();
    if (pid < 0) {
        return -1;
    }
    if (pid == 0) {
        const int devnull = ::open("/dev/null", O_RDWR);
        if (devnull >= 0) {
            (void)::dup2(devnull, 1);
            (void)::dup2(devnull, 2);
            if (devnull > 2) {
                ::close(devnull);
            }
        }
        std::vector<char*> argv;
        argv.reserve(args.size() + 1);
        for (const std::string& arg : args) {
            argv.push_back(const_cast<char*>(arg.c_str()));
        }
        argv.push_back(nullptr);
        ::execv(argv[0], argv.data());
        ::_exit(127);
    }
    int status = 0;
    ::waitpid(pid, &status, 0);
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    return -1;
}

TEST(CampaignE2E, RealExecServerCampaignGrowsCorpusAndWritesMetrics) {
    const std::string fuzzer_bin = FUZZER_BIN;
    const std::string exec_server = EXEC_SERVER_BIN;
    const std::string cov_stdin = COV_STDIN_BIN;
    const std::string cov_lib = COV_LIBRARY_PATH;

    if (!PathExecutable(fuzzer_bin)) {
        GTEST_SKIP() << "fuzzer binary missing: " << fuzzer_bin;
    }
    if (!PathExecutable(exec_server)) {
        GTEST_SKIP() << "exec-server binary missing: " << exec_server;
    }
    if (!PathExecutable(cov_stdin)) {
        GTEST_SKIP() << "cov_stdin_target missing: " << cov_stdin;
    }
    if (!PathReadable(cov_lib)) {
        GTEST_SKIP() << "libmlfuzzz3_cov missing: " << cov_lib;
    }

    const std::filesystem::path out =
        std::filesystem::path(::testing::TempDir()) / "mlfuzzz3_campaign_e2e";
    std::error_code ec;
    std::filesystem::remove_all(out, ec);
    std::filesystem::create_directories(out, ec);

    const int rc =
        RunBinary({fuzzer_bin, "--exec-server", exec_server, "--target", cov_stdin, "--cov-library",
                   cov_lib, "--out-dir", out.string(), "--max-iterations", "300",
                   "--metrics-interval", "50", "--seed", "1234"});
    EXPECT_EQ(rc, 0) << "fuzzer exited with code " << rc;

    // The first run always observes new coverage (empty seen-map), and
    // cov_stdin's A/B/other branches yield further new edges, so the
    // corpus must grow beyond the single bootstrap input.
    EXPECT_GT(CountRegularFiles(out / "corpus"), 1U);

    const std::filesystem::path metrics = out / "metrics.jsonl";
    ASSERT_TRUE(std::filesystem::exists(metrics));
    EXPECT_GT(std::filesystem::file_size(metrics, ec), 0U);

    std::filesystem::remove_all(out, ec);
}

// Crash-path coverage: a real campaign against the cov_crash fixture
// (aborts on ~50% of byte values) must persist crashes under crashes/
// while the loop itself keeps running and the CLI exits cleanly. The
// fixed seed + iteration cap make the byteflip sequence deterministically
// reach the crash (non-flaky).
TEST(CampaignE2E, RealExecServerCampaignPersistsCrashesAndKeepsRunning) {
    const std::string fuzzer_bin = FUZZER_BIN;
    const std::string exec_server = EXEC_SERVER_BIN;
    const std::string cov_crash = COV_CRASH_BIN;
    const std::string cov_lib = COV_LIBRARY_PATH;

    if (!PathExecutable(fuzzer_bin)) {
        GTEST_SKIP() << "fuzzer binary missing: " << fuzzer_bin;
    }
    if (!PathExecutable(exec_server)) {
        GTEST_SKIP() << "exec-server binary missing: " << exec_server;
    }
    if (!PathExecutable(cov_crash)) {
        GTEST_SKIP() << "cov_crash_target missing: " << cov_crash;
    }
    if (!PathReadable(cov_lib)) {
        GTEST_SKIP() << "libmlfuzzz3_cov missing: " << cov_lib;
    }

    const std::filesystem::path out =
        std::filesystem::path(::testing::TempDir()) / "mlfuzzz3_campaign_crash_e2e";
    std::error_code ec;
    std::filesystem::remove_all(out, ec);
    std::filesystem::create_directories(out, ec);

    const int rc =
        RunBinary({fuzzer_bin, "--exec-server", exec_server, "--target", cov_crash, "--cov-library",
                   cov_lib, "--out-dir", out.string(), "--max-iterations", "200",
                   "--metrics-interval", "50", "--seed", "1234"});
    // Crashes are findings, not infrastructure errors: the loop keeps
    // running and the CLI exits 0.
    EXPECT_EQ(rc, 0) << "fuzzer exited with code " << rc;

    EXPECT_GT(CountRegularFiles(out / "crashes"), 0U);

    std::filesystem::remove_all(out, ec);
}

// --target-args delivery (ADR 0040). The cov_argv fixture crashes if and
// only if the literal "crash" argument reaches it. Running the same
// campaign with and without --target-args proves the argument is carried
// end-to-end through the fuzzer CLI -> exec-server CLI -> worker chain:
// without the flag the target never crashes, with it every run does.
TEST(CampaignE2E, TargetArgsAbsentNeverCrashes) {
    const std::string fuzzer_bin = FUZZER_BIN;
    const std::string exec_server = EXEC_SERVER_BIN;
    const std::string cov_argv = COV_ARGV_BIN;
    const std::string cov_lib = COV_LIBRARY_PATH;

    if (!PathExecutable(fuzzer_bin)) {
        GTEST_SKIP() << "fuzzer binary missing: " << fuzzer_bin;
    }
    if (!PathExecutable(exec_server)) {
        GTEST_SKIP() << "exec-server binary missing: " << exec_server;
    }
    if (!PathExecutable(cov_argv)) {
        GTEST_SKIP() << "cov_argv_target missing: " << cov_argv;
    }
    if (!PathReadable(cov_lib)) {
        GTEST_SKIP() << "libmlfuzzz3_cov missing: " << cov_lib;
    }

    const std::filesystem::path out =
        std::filesystem::path(::testing::TempDir()) / "mlfuzzz3_targetargs_absent_e2e";
    std::error_code ec;
    std::filesystem::remove_all(out, ec);
    std::filesystem::create_directories(out, ec);

    const int rc =
        RunBinary({fuzzer_bin, "--exec-server", exec_server, "--target", cov_argv, "--cov-library",
                   cov_lib, "--out-dir", out.string(), "--max-iterations", "50",
                   "--metrics-interval", "25", "--seed", "1234"});
    EXPECT_EQ(rc, 0) << "fuzzer exited with code " << rc;

    // No "crash" argument was delivered, so the target exits 0 for every
    // input and nothing is recorded under crashes/.
    EXPECT_EQ(CountRegularFiles(out / "crashes"), 0U);

    std::filesystem::remove_all(out, ec);
}

TEST(CampaignE2E, TargetArgsPresentReachesTargetAndCrashes) {
    const std::string fuzzer_bin = FUZZER_BIN;
    const std::string exec_server = EXEC_SERVER_BIN;
    const std::string cov_argv = COV_ARGV_BIN;
    const std::string cov_lib = COV_LIBRARY_PATH;

    if (!PathExecutable(fuzzer_bin)) {
        GTEST_SKIP() << "fuzzer binary missing: " << fuzzer_bin;
    }
    if (!PathExecutable(exec_server)) {
        GTEST_SKIP() << "exec-server binary missing: " << exec_server;
    }
    if (!PathExecutable(cov_argv)) {
        GTEST_SKIP() << "cov_argv_target missing: " << cov_argv;
    }
    if (!PathReadable(cov_lib)) {
        GTEST_SKIP() << "libmlfuzzz3_cov missing: " << cov_lib;
    }

    const std::filesystem::path out =
        std::filesystem::path(::testing::TempDir()) / "mlfuzzz3_targetargs_present_e2e";
    std::error_code ec;
    std::filesystem::remove_all(out, ec);
    std::filesystem::create_directories(out, ec);

    const int rc =
        RunBinary({fuzzer_bin, "--exec-server", exec_server, "--target", cov_argv, "--cov-library",
                   cov_lib, "--out-dir", out.string(), "--max-iterations", "50",
                   "--metrics-interval", "25", "--seed", "1234", "--target-args", "crash"});
    // Crashes are findings, not infrastructure errors: the CLI exits 0.
    EXPECT_EQ(rc, 0) << "fuzzer exited with code " << rc;

    // The "crash" argument reached the target, so every run SIGSEGVs and
    // crashes/ is populated — the only difference from the case above is
    // --target-args, proving end-to-end delivery.
    EXPECT_GT(CountRegularFiles(out / "crashes"), 0U);

    std::filesystem::remove_all(out, ec);
}

// --- Discriminating parser fixture smoke (ADR 0032) -----------------------
//
// These do not benchmark; they only assert the fixture is wired correctly
// and its two crash conditions behave as designed, so the benchmark harness
// can rely on them. The base length L = 8 (cov_parser_target.c kBaseLen);
// a crash input <= L bytes is crash A (length-preserving), > L is crash B
// (length-growing). Fixed --seed keeps every run deterministic (non-flaky).

constexpr std::uintmax_t kCovParserBaseLen = 8;

// Returns a skip reason if any cov_parser artifact is missing, or an empty
// string when everything is present. GTEST_SKIP() expands to a return, so
// it must be invoked from the test body (void context), not here.
std::string CovParserSkipReason() {
    if (!PathExecutable(FUZZER_BIN)) {
        return std::string("fuzzer binary missing: ") + FUZZER_BIN;
    }
    if (!PathExecutable(EXEC_SERVER_BIN)) {
        return std::string("exec-server binary missing: ") + EXEC_SERVER_BIN;
    }
    if (!PathExecutable(COV_PARSER_BIN)) {
        return std::string("cov_parser_target missing: ") + COV_PARSER_BIN;
    }
    if (!PathReadable(COV_LIBRARY_PATH)) {
        return std::string("libmlfuzzz3_cov missing: ") + COV_LIBRARY_PATH;
    }
    if (!PathReadable(COV_PARSER_SEEDS)) {
        return std::string("cov_parser seeds missing: ") + COV_PARSER_SEEDS;
    }
    return std::string();
}

std::filesystem::path FreshOutDir(const std::string& name) {
    const std::filesystem::path out = std::filesystem::path(::testing::TempDir()) / name;
    std::error_code ec;
    std::filesystem::remove_all(out, ec);
    std::filesystem::create_directories(out, ec);
    return out;
}

TEST(ParserFixtureE2E, HavocReachesACrash) {
    if (const std::string reason = CovParserSkipReason(); !reason.empty()) {
        GTEST_SKIP() << reason;
    }
    const std::filesystem::path out = FreshOutDir("mlfuzzz3_parser_havoc");

    // Havoc can both grow the input (crash B) and set bytes (crash A); a
    // short campaign reaches some crash quickly.
    const int rc = RunBinary({FUZZER_BIN,
                              "--exec-server",
                              EXEC_SERVER_BIN,
                              "--target",
                              COV_PARSER_BIN,
                              "--cov-library",
                              COV_LIBRARY_PATH,
                              "--seed-dir",
                              COV_PARSER_SEEDS,
                              "--out-dir",
                              out.string(),
                              "--mutator",
                              "havoc",
                              "--max-det-steps",
                              "0",
                              "--max-iterations",
                              "500",
                              "--metrics-interval",
                              "500",
                              "--seed",
                              "1234"});
    EXPECT_EQ(rc, 0) << "fuzzer exited with code " << rc;
    EXPECT_GT(CountRegularFiles(out / "crashes"), 0U);

    std::error_code ec;
    std::filesystem::remove_all(out, ec);
}

TEST(ParserFixtureE2E, ByteflipReachesCrashAButNeverCrashB) {
    if (const std::string reason = CovParserSkipReason(); !reason.empty()) {
        GTEST_SKIP() << reason;
    }
    const std::filesystem::path out = FreshOutDir("mlfuzzz3_parser_byteflip");

    // Byteflip is length-preserving: from the L-byte neutral seeds it can
    // set buf[5] into the crashing range (crash A) but can never grow the
    // input past L (crash B). So crashes appear and all are <= L bytes.
    const int rc = RunBinary({FUZZER_BIN,
                              "--exec-server",
                              EXEC_SERVER_BIN,
                              "--target",
                              COV_PARSER_BIN,
                              "--cov-library",
                              COV_LIBRARY_PATH,
                              "--seed-dir",
                              COV_PARSER_SEEDS,
                              "--out-dir",
                              out.string(),
                              "--mutator",
                              "byteflip",
                              "--max-det-steps",
                              "0",
                              "--max-iterations",
                              "2000",
                              "--metrics-interval",
                              "2000",
                              "--seed",
                              "1234"});
    EXPECT_EQ(rc, 0) << "fuzzer exited with code " << rc;

    // Crash A is reached (length-preserving)...
    EXPECT_GT(CountRegularFiles(out / "crashes"), 0U);
    // ...and crash B (length > L) is never reached by a length-preserving
    // mutator: no saved crash input exceeds the base length.
    EXPECT_LE(MaxRegularFileSize(out / "crashes"), kCovParserBaseLen);

    std::error_code ec;
    std::filesystem::remove_all(out, ec);
}

}  // namespace

namespace {
TEST(CompositionE2E, ProfilesRespectYamlAndExplicitCliOverrides) {
    ASSERT_TRUE(PathExecutable(FUZZER_BIN));
    const auto base = std::filesystem::path(::testing::TempDir()) /
                      ("composition_profiles_" + std::to_string(::getpid()));
    std::filesystem::create_directories(base);
    std::vector<std::string> profiles{"legacy", "mutation-only"};
#if COMPOSITION_HAS_I2S
    profiles.emplace_back("hybrid-heuristic");
    profiles.emplace_back("hybrid-ml");
#endif
    for (const auto& profile : profiles) {
        const auto config_path = base / (profile + ".yaml");
        std::ofstream config(config_path);
        config << "composition:\n  schema_version: 1\n  profile: " << profile
               << "\n  seed: 37\n  seed_scheduler: {type: round-robin}\n"
                  "  campaign: {max_iterations: 40, max_det_steps: 0, stagnation_threshold: 0}\n";
        config.close();
        const auto out = base / profile;
        std::vector<std::string> args{FUZZER_BIN,
                                      "--exec-server",
                                      EXEC_SERVER_BIN,
                                      "--target",
                                      COV_STDIN_BIN,
                                      "--cov-library",
                                      COV_LIBRARY_PATH,
                                      "--out-dir",
                                      out.string(),
                                      "--config",
                                      config_path.string(),
                                      "--max-iterations",
                                      "9",
                                      "--mutator",
                                      "byteflip"};
#if !COMPOSITION_HAS_SMT
        args.emplace_back("--no-concolic");
#endif
        ASSERT_EQ(RunBinary(args), 0) << profile;
        const auto resolved = YAML::LoadFile((out / "resolved.yaml").string());
        EXPECT_EQ(resolved["seed"].as<unsigned>(), 37U);
        EXPECT_EQ(resolved["seed_scheduler"]["type"].as<std::string>(), "round-robin");
        EXPECT_EQ(resolved["campaign"]["max_iterations"].as<unsigned>(), 9U);
        EXPECT_TRUE(std::filesystem::exists(out / "run-manifest.yaml"));
        std::ifstream events(out / "events.jsonl");
        std::string line;
        unsigned executions = 0;
        while (std::getline(events, line)) {
            const auto event = YAML::Load(line);
            if (event["event"].as<std::string>() == "execution") {
                ++executions;
                EXPECT_EQ(
                    event["comparisons_available"].as<bool>(),
                    event["purpose"].as<unsigned>() == 2U && event["status"].as<unsigned>() == 0U);
                EXPECT_EQ(event["run_id"].as<unsigned>(), executions);
                EXPECT_GT(event["decision_id"].as<unsigned>(), 0U);
            }
        }
        EXPECT_EQ(executions, 9U) << profile;
    }
    std::filesystem::remove_all(base);
}
TEST(CompositionE2E, InvalidStageFailsBeforeExecutionServerStarts) {
    const auto base = std::filesystem::path(::testing::TempDir()) /
                      ("composition_invalid_" + std::to_string(::getpid()));
    std::filesystem::create_directories(base);
    const auto marker = base / "server_started";
    const auto server = base / "server.sh";
    std::ofstream script(server);
    script << "#!/bin/sh\n: > '" << marker.string() << "'\nexit 1\n";
    script.close();
    std::filesystem::permissions(server, std::filesystem::perms::owner_all);
    const auto config_path = base / "invalid.yaml";
    std::ofstream config(config_path);
    config << "schema_version: 1\nprofile: mutation-only\nstages: [{type: missing}]\n";
    config.close();
    EXPECT_NE(RunBinary({FUZZER_BIN, "--exec-server", server.string(), "--target", COV_STDIN_BIN,
                         "--cov-library", COV_LIBRARY_PATH, "--out-dir", (base / "out").string(),
                         "--config", config_path.string()}),
              0);
    EXPECT_FALSE(std::filesystem::exists(marker));
    std::filesystem::remove_all(base);
}
}  // namespace
