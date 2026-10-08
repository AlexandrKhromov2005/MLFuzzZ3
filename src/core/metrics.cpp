#include "metrics.h"

#include <fstream>
#include <ios>
#include <sstream>
#include <string>
#include <utility>

namespace mlfuzzz3::core {
namespace {

// Escape the characters JSON requires inside a string literal. Only the
// run-id field is a string; every other field is numeric and needs no
// escaping.
std::string JsonEscape(const std::string& value) {
    std::string out;
    out.reserve(value.size() + 2);
    for (const char ch : value) {
        switch (ch) {
            case '"':
                out += "\\\"";
                break;
            case '\\':
                out += "\\\\";
                break;
            case '\n':
                out += "\\n";
                break;
            case '\r':
                out += "\\r";
                break;
            case '\t':
                out += "\\t";
                break;
            default:
                out += ch;
                break;
        }
    }
    return out;
}

}  // namespace

tl::expected<MetricsEmitter, MetricsError> MetricsEmitter::Create(std::filesystem::path path,
                                                                  std::string run_id) {
    std::ofstream probe(path, std::ios::app);
    if (!probe) {
        return tl::unexpected(MetricsError::kOpenFailed);
    }
    return MetricsEmitter(std::move(path), std::move(run_id));
}

tl::expected<void, MetricsError> MetricsEmitter::Emit(const MetricsSnapshot& snapshot) {
    std::ofstream out(path_, std::ios::app);
    if (!out) {
        return tl::unexpected(MetricsError::kOpenFailed);
    }

    std::ostringstream line;
    line << '{' << R"("run_id":")" << JsonEscape(run_id_) << '"' << R"(,"execs":)" << snapshot.execs
         << R"(,"execs_per_sec":)" << snapshot.execs_per_sec << R"(,"corpus_size":)"
         << snapshot.corpus_size << R"(,"edges":)" << snapshot.edges << R"(,"crashes":)"
         << snapshot.crashes << R"(,"det_execs":)" << snapshot.det_execs << R"(,"havoc_execs":)"
         << snapshot.havoc_execs << R"(,"concolic_calls":)" << snapshot.concolic_calls
         << R"(,"concolic_candidates":)" << snapshot.concolic_candidates << R"(,"concolic_edges":)"
         << snapshot.concolic_edges << R"(,"concolic_crashes":)" << snapshot.concolic_crashes
         << R"(,"concolic_unsat":)" << snapshot.concolic_unsat << R"(,"concolic_timeout":)"
         << snapshot.concolic_timeout << R"(,"concolic_no_candidate":)"
         << snapshot.concolic_no_candidate << R"(,"concolic_no_binding":)"
         << snapshot.concolic_no_binding << R"(,"concolic_error":)" << snapshot.concolic_error
         << R"(,"concolic_time_ms_total":)" << snapshot.concolic_time_ms_total
         << R"(,"concolic_budget_skips":)" << snapshot.concolic_budget_skips
         << R"(,"concolic_seed_run_ms_total":)" << snapshot.concolic_seed_run_ms_total
         << R"(,"elapsed":)" << snapshot.elapsed << '}' << '\n';

    out << line.str();
    out.flush();
    if (!out.good()) {
        return tl::unexpected(MetricsError::kWriteFailed);
    }
    return {};
}

}  // namespace mlfuzzz3::core
