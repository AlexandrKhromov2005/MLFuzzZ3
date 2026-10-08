#include "args.h"

#include <array>
#include <cstddef>
#include <stdexcept>
#include <string>
#include <string_view>

namespace mlfuzzz3::cli {

namespace {

// Булевы флаги-включатели: починки ADR 0049 и --run-seeds-first. Таблица
// вместо цепочки веток — см. комментарий на месте вызова.
bool ApplySwitchFlag(const std::string& a, Args& args) {
    const std::array<std::pair<std::string_view, bool Args::*>, 4> flags = {{
        {"--concolic-fix-findfirst-index", &Args::concolic_fix_findfirst_index},
        {"--concolic-fix-addvars", &Args::concolic_fix_addvars},
        {"--concolic-fix-writeback-width", &Args::concolic_fix_writeback_width},
        {"--run-seeds-first", &Args::run_seeds_first},
    }};
    for (const auto& [name, field] : flags) {
        if (a == name) {
            args.*field = true;
            return true;
        }
    }
    return false;
}

}  // namespace

namespace {

// ADR 0049 F3: имя формы системы -> номер, как его понимает CampaignConfig.
// Вынесено из ParseArgs отдельной функцией не ради красоты: цепочка имён
// внутри разбора аргументов поднимала когнитивную сложность ParseArgs до 33
// при пороге 25 (readability-function-cognitive-complexity), и стадия lint
// краснела.
unsigned ParseSystemForm(const std::string& form) {
    if (form == "all-but-target") {
        return 0;
    }
    if (form == "prefix") {
        return 1;
    }
    if (form == "optimistic") {
        return 2;
    }
    throw std::runtime_error("--concolic-system-form: unknown form: " + form);
}

}  // namespace

Args ParseArgs(std::span<const char* const> argv_view) {
    const auto require_value = [&argv_view](std::size_t& idx,
                                            const std::string& flag) -> std::string {
        if (idx + 1 >= argv_view.size()) {
            throw std::runtime_error(flag + " requires a value");
        }
        return argv_view[++idx];
    };

    Args args;
    for (std::size_t i = 1; i < argv_view.size(); ++i) {
        const std::string a = argv_view[i];
        if (a == "--help" || a == "-h") {
            args.show_help = true;
        } else if (a == "--version" || a == "-V") {
            args.show_version = true;
        } else if (a == "--config") {
            args.config_path = require_value(i, a);
        } else if (a == "--exec-server") {
            args.exec_server = require_value(i, a);
        } else if (a == "--target") {
            args.target = require_value(i, a);
        } else if (a == "--cov-library") {
            args.cov_library = require_value(i, a);
        } else if (a == "--out-dir") {
            args.out_dir = require_value(i, a);
        } else if (a == "--seed-dir") {
            args.seed_dir = require_value(i, a);
        } else if (a == "--max-iterations") {
            args.max_iterations = std::stoull(require_value(i, a));
        } else if (a == "--max-seconds") {
            args.max_seconds = std::stod(require_value(i, a));
        } else if (a == "--metrics-interval") {
            args.metrics_interval = std::stoull(require_value(i, a));
        } else if (a == "--seed") {
            args.seed = std::stoull(require_value(i, a));
        } else if (a == "--mutator") {
            args.mutator = require_value(i, a);
        } else if (a == "--max-det-steps") {
            args.max_det_steps = std::stoull(require_value(i, a));
        } else if (a == "--target-args") {
            args.target_args = require_value(i, a);
        } else if (a == "--no-concolic") {
            args.concolic_enabled = false;
        } else if (ApplySwitchFlag(a, args)) {
            // Булевы флаги-включатели (три флага ADR 0049 и --run-seeds-first)
            // разбираются таблицей: отдельные ветки поднимали когнитивную
            // сложность ParseArgs выше порога
            // readability-function-cognitive-complexity.
        } else if (a == "--concolic-system-form") {
            args.concolic_system_form = ParseSystemForm(require_value(i, a));
        } else {
            throw std::runtime_error("unknown argument: " + a);
        }
    }
    return args;
}

void PrintUsage(std::ostream& out) {
    out << "Usage: fuzzer [options]\n"
           "\n"
           "Options:\n"
           "  --config <path>          Path to YAML configuration file.\n"
           "  -h, --help               Print this help text and exit.\n"
           "  -V, --version            Print the fuzzer version and exit.\n"
           "\n"
           "Campaign mode (ADR 0029) — enabled by --exec-server:\n"
           "  --exec-server <path>     Path to the exec-server binary.\n"
           "  --target <path>          Instrumented target binary.\n"
           "  --cov-library <path>     Absolute path to libmlfuzzz3_cov.\n"
           "  --out-dir <dir>          Output dir (corpus/, crashes/, hangs/, metrics.jsonl).\n"
           "  --seed-dir <dir>         Optional seed corpus directory.\n"
           "  --max-iterations <n>     Stop after n executions (0 = unbounded).\n"
           "  --max-seconds <s>        Stop after s seconds (0 = unbounded).\n"
           "  --metrics-interval <n>   Emit a metrics record every n executions.\n"
           "  --seed <n>               RNG seed for replayable runs.\n"
           "  --mutator <name>         Mutation operator: havoc|bitflip|byteflip "
           "(default havoc).\n"
           "  --target-args <args>     Whitespace-separated args passed to the target "
           "(input stays on stdin).\n"
           "  --max-det-steps <n>      Per-seed deterministic-stage cap; 0 disables "
           "the deterministic stage.\n"
           "  --run-seeds-first        Run every corpus seed once, unmutated, before "
           "mutations (counted in execs); default: off.\n"
           "  --no-concolic            Disarm the concolic arm for this run (ADR 0036, "
           "experimental); default: armed.\n"
           "  --concolic-fix-findfirst-index   ADR 0049 F1: index the input instead of "
           "scanning it per operand; default: off.\n"
           "  --concolic-fix-addvars   ADR 0049 F2: refuse degenerate kAddVars (i == j, "
           "zero field); default: off.\n"
           "  --concolic-fix-writeback-width   ADR 0049 F4: refuse a model value wider than "
           "its binding instead of truncating; default: off.\n"
           "  --concolic-system-form <form>    ADR 0049 F3: all-but-target (default), "
           "prefix, or optimistic.\n";
}

mlfuzzz3::core::CampaignConfig MakeCampaignConfig(const Args& args) {
    return mlfuzzz3::core::CampaignConfig{
        .max_iterations = args.max_iterations,
        .max_seconds = args.max_seconds,
        .metrics_interval = args.metrics_interval,
        .rng_seed = args.seed,
        .max_det_steps = args.max_det_steps,
        .run_seeds_first = args.run_seeds_first,
        .concolic_enabled = args.concolic_enabled,
        .concolic_fix_findfirst_index = args.concolic_fix_findfirst_index,
        .concolic_fix_addvars = args.concolic_fix_addvars,
        .concolic_fix_writeback_width = args.concolic_fix_writeback_width,
        .concolic_system_form = args.concolic_system_form};
}

}  // namespace mlfuzzz3::cli
