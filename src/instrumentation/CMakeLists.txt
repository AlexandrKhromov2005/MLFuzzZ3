# Aggregator for instrumentation/* components.
# Phase 1.5 Stage 2 adds the own LLVM edge-coverage pass (ADR 0024).
# Phase 3 adds the branch-tracing pass (ADR 0033).

add_subdirectory(edge_coverage_pass)
add_subdirectory(branch_trace_pass)
