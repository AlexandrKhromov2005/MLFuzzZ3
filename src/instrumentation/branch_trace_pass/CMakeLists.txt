# Branch-tracing LLVM pass build (ADR 0033 Шаг 3).
#
# Pinned against the LLVM 20 dev install at /usr/lib/llvm-20, exactly
# like edge_coverage_pass (see that CMakeLists for the rationale on
# querying llvm-config directly instead of find_package(LLVM): the Z3
# submodule's `opt` target collides with LLVMExports' imported `opt`).
#
# The plugin .so links no LLVM libraries — it is loaded into clang at
# compile time via -fpass-plugin and clang supplies every LLVM symbol.

cmake_minimum_required(VERSION 3.20)

find_program(BRANCH_TRACE_LLVM_CONFIG
    NAMES llvm-config-20 llvm-config
    PATHS /usr/lib/llvm-20/bin /usr/bin
    NO_DEFAULT_PATH
    REQUIRED)

execute_process(
    COMMAND ${BRANCH_TRACE_LLVM_CONFIG} --version
    OUTPUT_VARIABLE BRANCH_TRACE_LLVM_VERSION
    OUTPUT_STRIP_TRAILING_WHITESPACE
    COMMAND_ERROR_IS_FATAL ANY)

string(REGEX MATCH "^([0-9]+)" _branch_trace_llvm_major
    "${BRANCH_TRACE_LLVM_VERSION}")
if(NOT CMAKE_MATCH_1 STREQUAL "20")
    message(FATAL_ERROR
        "Branch-trace pass requires LLVM 20 (ADR-0033); found ${BRANCH_TRACE_LLVM_VERSION}")
endif()

execute_process(
    COMMAND ${BRANCH_TRACE_LLVM_CONFIG} --includedir
    OUTPUT_VARIABLE BRANCH_TRACE_LLVM_INCLUDEDIR
    OUTPUT_STRIP_TRAILING_WHITESPACE
    COMMAND_ERROR_IS_FATAL ANY)

add_library(BranchTracePass MODULE BranchTracePass.cpp SiteMap.cpp)
target_include_directories(BranchTracePass PRIVATE
    "${BRANCH_TRACE_LLVM_INCLUDEDIR}")
set_target_properties(BranchTracePass PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF
    POSITION_INDEPENDENT_CODE ON)
