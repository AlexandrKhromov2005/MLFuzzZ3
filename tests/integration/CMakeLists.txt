# coverage first: it defines the shared exec_server_bin target that the
# core campaign integration test reuses.
add_subdirectory(coverage)
add_subdirectory(core)
add_subdirectory(solver)
# concolic after coverage: reuses its exec_server_bin target.
add_subdirectory(concolic)
