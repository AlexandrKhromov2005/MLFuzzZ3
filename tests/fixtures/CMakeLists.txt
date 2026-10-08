# Test fixtures aggregator. New top-level test fixtures
# category for cmake-built C/C++ test programs (distinct
# from Go testdata fixtures inside individual modules).

add_subdirectory(cov_simple)
add_subdirectory(cov_stdin)
add_subdirectory(cov_crash)
add_subdirectory(cov_argv)
add_subdirectory(cov_parser)
add_subdirectory(branch_icmp)
add_subdirectory(cov_solve)
add_subdirectory(cov_xfield)
add_subdirectory(add_gate)
add_subdirectory(add_gate_be)
add_subdirectory(add_gate_w16)
add_subdirectory(sub_gate)
add_subdirectory(xor_gate)
