add_subdirectory(cli)
add_subdirectory(common)
add_subdirectory(core)
add_subdirectory(coverage)
add_subdirectory(instrumentation)
add_subdirectory(ipc)
add_subdirectory(mutation)

# The solver unit test only builds when the solver layer was built (it
# links fuzzer::solver, which requires the bundled Z3; see the root
# CMakeLists FUZZER_BUILD_Z3 gate).
if(TARGET fuzzer::solver)
  add_subdirectory(solver)
endif()

# The concolic unit test links fuzzer::concolic (which pulls in the solver
# layer / Z3); same gate.
if(TARGET fuzzer::concolic)
  add_subdirectory(concolic)
endif()
