add_library(fuzzer_core STATIC
  corpus.cpp
  metrics.cpp
  campaign.cpp
  runner.cpp
)
add_library(fuzzer::core ALIAS fuzzer_core)

target_include_directories(fuzzer_core
  PUBLIC
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(fuzzer_core
  PUBLIC
    # SeedScheduler (seed_scheduler.h) reuses mutation::make_rng /
    # rng_next_index; Corpus stores mutation::FuzzInput. PUBLIC so the
    # include paths propagate to consumers that pull core headers (CLI,
    # unit tests).
    fuzzer::mutation
    # Corpus / scheduler headers surface tl::expected in their API.
    tl::expected
    # runner.h / campaign.h surface ipc::ClientSession, ipc::IpcError,
    # and ipc::v1::RunResponse in their API (the campaign loop drives
    # Session::Run through the Runner seam).
    fuzzer::session
    # runner.h surfaces coverage::BranchReader::Record in its API and
    # SessionRunner maps a BranchReader (ADR 0036 LastBranchRecords).
    fuzzer::coverage
  PRIVATE
    fuzzer::warnings
    # campaign.cpp logs through the LOG_* facade.
    fuzzer::common
)

# ADR 0036: the campaign loop's concolic step (campaign.cpp) links
# fuzzer::concolic — the Z3-backed orchestrator — gated on FUZZER_BUILD_Z3,
# the same gate the root uses to build src/concolic. MLFUZZZ3_WITH_CONCOLIC
# is PUBLIC so every translation unit that includes campaign.h agrees on
# the CampaignLoop layout (the stagnation member sits behind the macro);
# the library link is PRIVATE since concolic types never appear in
# campaign.h. fuzzer::concolic is declared in a later add_subdirectory, but
# target_link_libraries resolves the name at generation time, so
# referencing it here is fine.
if(FUZZER_BUILD_Z3)
  target_link_libraries(fuzzer_core PRIVATE fuzzer::concolic)
  target_compile_definitions(fuzzer_core PUBLIC MLFUZZZ3_WITH_CONCOLIC)
endif()
