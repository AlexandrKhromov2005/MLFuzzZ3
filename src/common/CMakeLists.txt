# Shared infrastructure: logging facade over spdlog and configuration
# facade over yaml-cpp. All project code must route logging through the
# LOG_* macros in log.h (project conventions) and read configuration through
# fuzzer::config (see src/common/config.h + docs/CONFIG.md).

add_library(fuzzer_common STATIC
  config.cpp
  log.cpp
)
add_library(fuzzer::common ALIAS fuzzer_common)

target_include_directories(fuzzer_common
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# spdlog and yaml-cpp come in as PUBLIC: config.h exposes no third-party
# types, but log.h re-exports spdlog's SPDLOG_* formatting machinery
# through the LOG_* macros. Consumers of fuzzer::common therefore need
# spdlog headers on their include path.
# SPDLOG_ACTIVE_LEVEL must reach every translation unit that uses LOG_*
# macros, otherwise the SPDLOG_TRACE / SPDLOG_DEBUG expansions are
# compile-time no-ops on release builds. Keeping the floor at TRACE lets
# the runtime level from LogConfig control what actually prints.
target_compile_definitions(fuzzer_common
  PUBLIC
    SPDLOG_ACTIVE_LEVEL=SPDLOG_LEVEL_TRACE
)

target_link_libraries(fuzzer_common
  PUBLIC
    spdlog::spdlog
    yaml-cpp::yaml-cpp
  PRIVATE
    fuzzer::warnings
)

# Expose the third-party headers as SYSTEM so clang-tidy's interprocedural
# analysis does not enforce our diagnostic policy on library internals
# (clang-analyzer reaches into spdlog's bundled fmt otherwise and reports
# fmtlib's intentional uninitialized-by-design pattern as a bug).
foreach(dep spdlog::spdlog yaml-cpp::yaml-cpp)
  get_target_property(_real ${dep} ALIASED_TARGET)
  if(NOT _real)
    set(_real ${dep})
  endif()
  get_target_property(_inc ${_real} INTERFACE_INCLUDE_DIRECTORIES)
  if(_inc)
    set_property(TARGET ${_real} PROPERTY INTERFACE_SYSTEM_INCLUDE_DIRECTORIES "${_inc}")
  endif()
endforeach()
