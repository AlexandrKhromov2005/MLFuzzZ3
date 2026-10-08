# Aggregator for runtime/* components.
# Phase 2 may add llvm_pass/ or other runtime modules.

# Enable C language for this subtree — top-level project()
# declares CXX only; runtime libraries are written in C
# per ADR 0017.
enable_language(C)

add_subdirectory(coverage)
