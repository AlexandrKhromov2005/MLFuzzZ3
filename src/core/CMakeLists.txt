# SPDX-License-Identifier: MIT
add_library(fuzzer_core STATIC corpus.cpp metrics.cpp campaign.cpp execution.cpp strategy.cpp hybrid_strategy.cpp)
add_library(fuzzer::core ALIAS fuzzer_core)
target_include_directories(fuzzer_core PUBLIC ${CMAKE_SOURCE_DIR}/include ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(fuzzer_core PUBLIC fuzzer::mutation tl::expected
  PRIVATE fuzzer::warnings fuzzer::common)
