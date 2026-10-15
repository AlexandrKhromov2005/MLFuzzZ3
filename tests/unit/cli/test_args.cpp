// Unit tests for the fuzzer CLI parser (ADR 0040). Exercises the
// --target-args wiring added for external-target benchmarks alongside the
// pre-existing campaign flags, plus the parser's error paths.

#include <gtest/gtest.h>

#include <array>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>

#include "args.h"

namespace {

using mlfuzzz3::cli::Args;
using mlfuzzz3::cli::ParseArgs;

// Builds a span over a fixed argv, mirroring how main() views argv.
template <std::size_t N>
Args Parse(const std::array<const char*, N>& argv) {
    return ParseArgs(std::span<const char* const>(argv.data(), argv.size()));
}

TEST(CliArgs, DefaultsWhenNoFlags) {
    const std::array<const char*, 1> argv{"fuzzer"};
    const Args args = Parse(argv);
    EXPECT_TRUE(args.target_args.empty());
    EXPECT_EQ(args.mutator, "havoc");
    EXPECT_EQ(args.seed_scheduler, "random");
    EXPECT_FALSE(args.show_help);
    EXPECT_FALSE(args.show_version);
}

TEST(CliArgs, TargetArgsCapturedVerbatim) {
    const std::array<const char*, 3> argv{"fuzzer", "--target-args", "-d --ignore-garbage"};
    const Args args = Parse(argv);
    // The value is forwarded verbatim; whitespace splitting happens later,
    // on the exec-server side (ADR 0040).
    EXPECT_EQ(args.target_args, "-d --ignore-garbage");
}

TEST(CliArgs, TargetArgsSingleToken) {
    const std::array<const char*, 3> argv{"fuzzer", "--target-args", "-d"};
    EXPECT_EQ(Parse(argv).target_args, "-d");
}

TEST(CliArgs, FullCampaignLine) {
    const std::array<const char*, 15> argv{"fuzzer",   "--exec-server", "/bin/es",     "--target",
                                           "/bin/tgt", "--cov-library", "/lib/cov.so", "--out-dir",
                                           "/tmp/out", "--seed",        "7",           "--mutator",
                                           "byteflip", "--target-args", "-d"};
    const Args args = Parse(argv);
    EXPECT_EQ(args.exec_server, "/bin/es");
    EXPECT_EQ(args.target, "/bin/tgt");
    EXPECT_EQ(args.cov_library, "/lib/cov.so");
    EXPECT_EQ(args.out_dir, "/tmp/out");
    EXPECT_EQ(args.seed, 7U);
    EXPECT_EQ(args.mutator, "byteflip");
    EXPECT_EQ(args.target_args, "-d");
}

TEST(CliArgs, TargetArgsMissingValueThrows) {
    const std::array<const char*, 2> argv{"fuzzer", "--target-args"};
    EXPECT_THROW(Parse(argv), std::runtime_error);
}

// ADR 0036 experimental switch. The arm is ON unless --no-concolic is
// given: the default is asserted here, not merely assumed, so a later
// change of default cannot slip in silently.
TEST(CliArgs, ConcolicArmedByDefault) {
    const std::array<const char*, 3> argv{"fuzzer", "--mutator", "havoc"};
    EXPECT_TRUE(Parse(argv).concolic_enabled);
}

TEST(CliArgs, NoConcolicDisarmsTheArm) {
    const std::array<const char*, 2> argv{"fuzzer", "--no-concolic"};
    const Args args = Parse(argv);
    EXPECT_FALSE(args.concolic_enabled);
    // Takes no value: the next token is parsed as a flag in its own right.
    const std::array<const char*, 4> argv2{"fuzzer", "--no-concolic", "--seed", "3"};
    const Args args2 = Parse(argv2);
    EXPECT_FALSE(args2.concolic_enabled);
    EXPECT_EQ(args2.seed, 3U);
}

// The CLI -> campaign seam: main() builds CampaignConfig only through
// MakeCampaignConfig, so --no-concolic must reach the loop's config, and the
// default must stay armed. Each case is checked against both values so a
// seam hardwired to either constant fails one of them.
TEST(CliArgs, CampaignConfigCarriesConcolicSwitch) {
    const std::array<const char*, 1> armed_argv{"fuzzer"};
    const Args armed = Parse(armed_argv);
    ASSERT_TRUE(armed.concolic_enabled);
    EXPECT_TRUE(mlfuzzz3::cli::MakeCampaignConfig(armed).concolic_enabled);

    const std::array<const char*, 4> off_argv{"fuzzer", "--no-concolic", "--seed", "7"};
    const Args off = Parse(off_argv);
    ASSERT_FALSE(off.concolic_enabled);
    const mlfuzzz3::core::CampaignConfig off_cfg = mlfuzzz3::cli::MakeCampaignConfig(off);
    EXPECT_FALSE(off_cfg.concolic_enabled);
    EXPECT_EQ(off_cfg.rng_seed, 7U);
}

TEST(CliArgs, UsageNamesTheConcolicSwitch) {
    std::ostringstream out;
    mlfuzzz3::cli::PrintUsage(out);
    EXPECT_NE(out.str().find("--no-concolic"), std::string::npos);
}

TEST(CliArgs, RunSeedsFirstOffByDefault) {
    const std::array<const char*, 1> argv{"fuzzer"};
    EXPECT_FALSE(Parse(argv).run_seeds_first);
}

TEST(CliArgs, RunSeedsFirstTurnsOnAndTakesNoValue) {
    const std::array<const char*, 4> argv{"fuzzer", "--run-seeds-first", "--seed", "5"};
    const Args args = Parse(argv);
    EXPECT_TRUE(args.run_seeds_first);
    EXPECT_EQ(args.seed, 5U);
    EXPECT_FALSE(args.concolic_fix_addvars);  // the shared switch table sets only its own field
}

TEST(CliArgs, UsageNamesTheSeedPassSwitch) {
    std::ostringstream out;
    mlfuzzz3::cli::PrintUsage(out);
    EXPECT_NE(out.str().find("--run-seeds-first"), std::string::npos);
}

TEST(CliArgs, UnknownFlagThrows) {
    const std::array<const char*, 2> argv{"fuzzer", "--bogus"};
    EXPECT_THROW(Parse(argv), std::runtime_error);
}

}  // namespace

// ADR 0049: четыре починки за флагами. Все по умолчанию выключены — это
// условие принятия ADR, а не удобство: включать нечего, пока развёртка
// docs/experiments/solver-fix-ladder/ не назвала числа.
TEST(Args, Adr0049FixesAreOffByDefault) {
    const std::array<const char*, 1> argv{"fuzzer"};
    const auto args = mlfuzzz3::cli::ParseArgs(std::span<const char* const>(argv));
    EXPECT_FALSE(args.concolic_fix_findfirst_index);
    EXPECT_FALSE(args.concolic_fix_addvars);
    EXPECT_FALSE(args.concolic_fix_writeback_width);
    EXPECT_EQ(args.concolic_system_form, 0U);
}

TEST(Args, Adr0049FixesTurnOnIndependently) {
    const std::array<const char*, 4> argv{"fuzzer", "--concolic-fix-findfirst-index",
                                          "--concolic-fix-addvars",
                                          "--concolic-fix-writeback-width"};
    const auto args = mlfuzzz3::cli::ParseArgs(std::span<const char* const>(argv));
    EXPECT_TRUE(args.concolic_fix_findfirst_index);
    EXPECT_TRUE(args.concolic_fix_addvars);
    EXPECT_TRUE(args.concolic_fix_writeback_width);

    const std::array<const char*, 2> only_one{"fuzzer", "--concolic-fix-addvars"};
    const auto one = mlfuzzz3::cli::ParseArgs(std::span<const char* const>(only_one));
    EXPECT_TRUE(one.concolic_fix_addvars);
    EXPECT_FALSE(one.concolic_fix_findfirst_index);
    EXPECT_FALSE(one.concolic_fix_writeback_width);
}

TEST(Args, Adr0049SystemFormTakesThreeNamesAndRejectsOthers) {
    const std::array<const char*, 3> all_but{"fuzzer", "--concolic-system-form", "all-but-target"};
    EXPECT_EQ(mlfuzzz3::cli::ParseArgs(std::span<const char* const>(all_but)).concolic_system_form,
              0U);
    const std::array<const char*, 3> prefix{"fuzzer", "--concolic-system-form", "prefix"};
    EXPECT_EQ(mlfuzzz3::cli::ParseArgs(std::span<const char* const>(prefix)).concolic_system_form,
              1U);
    const std::array<const char*, 3> optimistic{"fuzzer", "--concolic-system-form", "optimistic"};
    EXPECT_EQ(
        mlfuzzz3::cli::ParseArgs(std::span<const char* const>(optimistic)).concolic_system_form,
        2U);

    const std::array<const char*, 3> wrong{"fuzzer", "--concolic-system-form", "suffix"};
    EXPECT_THROW(
        {
            [[maybe_unused]] const auto ignored =
                mlfuzzz3::cli::ParseArgs(std::span<const char* const>(wrong));
        },
        std::runtime_error);
    const std::array<const char*, 2> missing{"fuzzer", "--concolic-system-form"};
    EXPECT_THROW(
        {
            [[maybe_unused]] const auto ignored =
                mlfuzzz3::cli::ParseArgs(std::span<const char* const>(missing));
        },
        std::runtime_error);
}

// Composition selection must consume its value without swallowing following flags.
TEST(CliArgs, SeedSchedulerSelection) {
    const std::array<const char*, 5> argv{"fuzzer", "--seed-scheduler", "round-robin", "--seed",
                                          "9"};
    const Args args = Parse(argv);
    EXPECT_EQ(args.seed_scheduler, "round-robin");
    EXPECT_EQ(args.seed, 9U);
    const std::array<const char*, 2> missing{"fuzzer", "--seed-scheduler"};
    EXPECT_THROW(Parse(missing), std::runtime_error);
}

TEST(CliArgs, ExplicitOptionTrackingDistinguishesDefaults) {
    const std::array<const char*, 5> argv{"fuzzer", "--profile", "mutation-only", "--seed", "0"};
    const auto args = Parse(argv);
    EXPECT_TRUE(args.explicit_flags.contains("--seed"));
    EXPECT_FALSE(args.explicit_flags.contains("--mutator"));
    const auto resolved = mlfuzzz3::cli::resolve_composition(args);
    EXPECT_EQ(resolved.profile, "mutation-only");
    EXPECT_EQ(resolved.components.seed, 0U);
    EXPECT_FALSE(resolved.campaign.concolic_enabled);
}
