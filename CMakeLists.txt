cmake_minimum_required(VERSION 3.25)

project(MLFuzzZ3
  VERSION 0.0.0
  DESCRIPTION "Hybrid mutation + concolic + SMT fuzzer with pluggable LLM assist"
  LANGUAGES CXX
)

# Export compile_commands.json so clang-tidy and LSP-friendly tools can find
# translation units without a custom build system integration.
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type (Debug, Release, ...)" FORCE)
endif()

# Warning flags live on a dedicated INTERFACE target so they apply only to
# project code. Third-party dependencies pulled in via FetchContent or
# submodules never inherit -Werror or pedantic warnings.
add_library(fuzzer_warnings INTERFACE)
add_library(fuzzer::warnings ALIAS fuzzer_warnings)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
  target_compile_options(fuzzer_warnings INTERFACE
    -Wall
    -Wextra
    -Wpedantic
    $<$<CONFIG:Debug>:-Werror>
  )
endif()

# ----- Sanitizers (ADR 0037) -----------------------------------------------
#
# Sanitizers are a first-class build configuration that instruments ONLY
# project code, never third_party. The flags ride a dedicated INTERFACE
# target attached to the same boundary as fuzzer::warnings: every
# first-party library/executable/test links fuzzer::warnings (and nothing
# under third_party or the add_custom_command fixtures does), so attaching
# fuzzer::sanitizers here reaches exactly project code + tests and leaves
# Z3/protobuf/absl/gtest/spdlog/yaml-cpp uninstrumented. This dissolves the
# old workaround (disable Z3 + split the run) caused by UBSAN failing to
# compile abseil under GCC; absl simply never receives -fsanitize.
#
# Flags are applied as BOTH compile and link options: instrumentation is
# emitted at compile time, and the sanitizer runtime is pulled at link time.
add_library(fuzzer_sanitizers INTERFACE)
add_library(fuzzer::sanitizers ALIAS fuzzer_sanitizers)
target_link_libraries(fuzzer_warnings INTERFACE fuzzer_sanitizers)

# FUZZER_SANITIZE lives here, beside the FUZZER_BUILD_Z3 option below, so the
# build's tunable knobs sit together; the INTERFACE target above is declared
# next to fuzzer::warnings (its sibling boundary). Default "none" keeps the
# ordinary build byte-for-byte unchanged: fuzzer_sanitizers stays empty and
# adds no flags on either phase.
set(FUZZER_SANITIZE "none" CACHE STRING
    "Sanitizers for project code only: none | address | undefined | address+undefined")
set_property(CACHE FUZZER_SANITIZE PROPERTY STRINGS
    none address undefined address+undefined)

if(FUZZER_SANITIZE STREQUAL "none")
    # No flags: ordinary build, zero overhead.
elseif(FUZZER_SANITIZE STREQUAL "address")
    set(_fuzzer_san_flags -fsanitize=address)
elseif(FUZZER_SANITIZE STREQUAL "undefined")
    set(_fuzzer_san_flags -fsanitize=undefined -fno-sanitize-recover=undefined)
elseif(FUZZER_SANITIZE STREQUAL "address+undefined")
    set(_fuzzer_san_flags -fsanitize=address,undefined -fno-sanitize-recover=undefined)
else()
    message(FATAL_ERROR
        "FUZZER_SANITIZE='${FUZZER_SANITIZE}' is invalid; expected one of: "
        "none address undefined address+undefined")
endif()

if(DEFINED _fuzzer_san_flags)
    target_compile_options(fuzzer_sanitizers INTERFACE ${_fuzzer_san_flags})
    target_link_options(fuzzer_sanitizers INTERFACE ${_fuzzer_san_flags})
endif()

# ----- Z3 (external SMT solver) --------------------------------------------
#
# Z3 is pinned via a git submodule under third_party/z3 (see ADR 0001 for the
# rationale). We pull it in with add_subdirectory rather than a FindZ3.cmake
# module so everything builds with the same toolchain in one cmake invocation.
# Z3 is not linked against any project target yet; the solver facade in
# Phase 3 will be the first consumer.
option(FUZZER_BUILD_Z3 "Build the bundled Z3 submodule" ON)

if(FUZZER_BUILD_Z3)
    if(NOT EXISTS "${CMAKE_SOURCE_DIR}/third_party/z3/CMakeLists.txt")
        message(FATAL_ERROR
            "third_party/z3/CMakeLists.txt not found.\n"
            "Run 'git submodule update --init --recursive' (or "
            "'./scripts/bootstrap.sh') before configuring, or pass "
            "-DFUZZER_BUILD_Z3=OFF to skip.")
    endif()

    set(Z3_BUILD_LIBZ3_SHARED        OFF CACHE BOOL "" FORCE)
    set(Z3_BUILD_EXECUTABLE          OFF CACHE BOOL "" FORCE)
    set(Z3_BUILD_TEST_EXECUTABLES    OFF CACHE BOOL "" FORCE)
    set(Z3_BUILD_DOCUMENTATION       OFF CACHE BOOL "" FORCE)
    set(Z3_INCLUDE_GIT_HASH          OFF CACHE BOOL "" FORCE)
    set(Z3_INCLUDE_GIT_DESCRIBE      OFF CACHE BOOL "" FORCE)

    add_subdirectory(third_party/z3)
endif()

# ----- Protobuf (IPC schema) -----------------------------------------------
#
# Pinned to a release tag via FetchContent per ADR 0001 and 0002. The same
# build yields both the libprotobuf runtime linked into our C++ targets and
# the protoc binary used by scripts/gen-proto.sh for Go, so the generator
# and the runtime cannot drift apart.
include(FetchContent)

set(protobuf_BUILD_TESTS        OFF CACHE BOOL "" FORCE)
set(protobuf_BUILD_CONFORMANCE  OFF CACHE BOOL "" FORCE)
set(protobuf_BUILD_EXAMPLES     OFF CACHE BOOL "" FORCE)
set(protobuf_BUILD_SHARED_LIBS  OFF CACHE BOOL "" FORCE)
set(protobuf_INSTALL            OFF CACHE BOOL "" FORCE)
set(protobuf_ABSL_PROVIDER      "module" CACHE STRING "" FORCE)
set(ABSL_PROPAGATE_CXX_STD      ON  CACHE BOOL "" FORCE)
set(ABSL_ENABLE_INSTALL         OFF CACHE BOOL "" FORCE)
set(utf8_range_ENABLE_INSTALL   OFF CACHE BOOL "" FORCE)
set(utf8_range_ENABLE_TESTS     OFF CACHE BOOL "" FORCE)

FetchContent_Declare(
  protobuf
  GIT_REPOSITORY https://github.com/protocolbuffers/protobuf.git
  GIT_TAG        v34.1
  GIT_SHALLOW    TRUE
  SYSTEM
)
FetchContent_MakeAvailable(protobuf)

# ----- spdlog (logging facade) ---------------------------------------------
set(SPDLOG_INSTALL       OFF CACHE BOOL "" FORCE)
set(SPDLOG_BUILD_EXAMPLE OFF CACHE BOOL "" FORCE)
set(SPDLOG_BUILD_TESTS   OFF CACHE BOOL "" FORCE)
set(SPDLOG_FMT_EXTERNAL  OFF CACHE BOOL "" FORCE)

FetchContent_Declare(
  spdlog
  GIT_REPOSITORY https://github.com/gabime/spdlog.git
  GIT_TAG        v1.17.0
  GIT_SHALLOW    TRUE
  SYSTEM
)
FetchContent_MakeAvailable(spdlog)

# ----- yaml-cpp (config facade) --------------------------------------------
set(YAML_CPP_BUILD_TESTS    OFF CACHE BOOL "" FORCE)
set(YAML_CPP_BUILD_TOOLS    OFF CACHE BOOL "" FORCE)
set(YAML_CPP_BUILD_CONTRIB  OFF CACHE BOOL "" FORCE)
set(YAML_CPP_INSTALL        OFF CACHE BOOL "" FORCE)
set(YAML_CPP_FORMAT_SOURCE  OFF CACHE BOOL "" FORCE)

FetchContent_Declare(
  yaml-cpp
  GIT_REPOSITORY https://github.com/jbeder/yaml-cpp.git
  GIT_TAG        yaml-cpp-0.9.0
  GIT_SHALLOW    TRUE
  SYSTEM
)
FetchContent_MakeAvailable(yaml-cpp)

# tl::expected (ADR 0009) — header-only polyfill для std::expected.
# std::expected (C++23) недоступен на clang 18 + libstdc++ 13;
# tl::expected с идентичным API собирается на обоих компиляторах.
set(EXPECTED_BUILD_TESTS OFF CACHE BOOL "" FORCE)
FetchContent_Declare(tl-expected
    GIT_REPOSITORY https://github.com/TartanLlama/expected.git
    GIT_TAG        v1.1.0
    SYSTEM)
FetchContent_MakeAvailable(tl-expected)

add_subdirectory(src/ipc)
add_subdirectory(src/common)
add_subdirectory(src/core)
add_subdirectory(src/cli)
add_subdirectory(src/runtime)
add_subdirectory(src/instrumentation)
add_subdirectory(src/mutation)
add_subdirectory(src/coverage)

# Solver layer (ADR 0034) — the first consumer of the bundled Z3. Gated
# on FUZZER_BUILD_Z3 so the -DFUZZER_BUILD_Z3=OFF escape hatch still
# configures: without that option there is no libz3 target to link.
if(FUZZER_BUILD_Z3)
  add_subdirectory(src/solver)
  # Concolic orchestrator (ADR 0035) links fuzzer::solver, so it lives
  # inside the same Z3 gate.
  add_subdirectory(src/concolic)
endif()

# Stage 2 instrumentation helper (ADR 0024 §Compiler integration).
# Provides mlfuzzz3_instrument_target(<target>) — usable by fixtures
# and any future fuzz target. Included after src/instrumentation so
# EdgeCoveragePass and mlfuzzz3_cov are already declared.
include("${CMAKE_SOURCE_DIR}/cmake/MLFuzzZ3Instrument.cmake")

# Tests are built only when this project is the top-level build. When
# MLFuzzZ3 is consumed as a subproject (e.g. via add_subdirectory from a
# superbuild) the parent does not inherit our test tree or the GoogleTest
# download.
option(FUZZER_BUILD_TESTS "Build unit tests" ${PROJECT_IS_TOP_LEVEL})

if(FUZZER_BUILD_TESTS)
  include(FetchContent)

  # GoogleTest v1.17.0 — latest stable release as of 2025-04-30. Pinned
  # to a full release tag per ADR 0001; never track a moving branch.
  FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG        v1.17.0
    GIT_SHALLOW    TRUE
    SYSTEM
  )
  set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
  FetchContent_MakeAvailable(googletest)

  enable_testing()
  include(GoogleTest)
  add_subdirectory(tests)
endif()
