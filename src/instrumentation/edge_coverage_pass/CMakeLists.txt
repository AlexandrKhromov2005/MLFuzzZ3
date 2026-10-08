# Stage 2 LLVM edge-coverage pass build (ADR 0024).
#
# Pinned against the LLVM 20 dev install at /usr/lib/llvm-20.
#
# Why not the standalone-validated find_package pattern:
#   find_package(LLVM REQUIRED CONFIG
#     PATHS /usr/lib/llvm-20/lib/cmake/llvm NO_DEFAULT_PATH)
# LLVMConfig.cmake unconditionally includes LLVMExports.cmake, which
# imports an `opt` executable target. The Z3 submodule pulled in by
# the top-level CMakeLists already declares an `opt` OBJECT library
# (z3_add_component(opt ...) in third_party/z3/src/opt/), and target
# names are global across the build tree — the resulting "split
# state" trips the export-set consistency check inside LLVMExports.
#
# We query llvm-config-20 directly for the version anchor and include
# path. The plugin .so does not need to link any LLVM libraries: it
# is loaded into clang at compile time via -fpass-plugin, and clang
# already has every LLVM symbol the plugin references.

cmake_minimum_required(VERSION 3.20)

find_program(EDGE_COVERAGE_LLVM_CONFIG
    NAMES llvm-config-20 llvm-config
    PATHS /usr/lib/llvm-20/bin /usr/bin
    NO_DEFAULT_PATH
    REQUIRED)

execute_process(
    COMMAND ${EDGE_COVERAGE_LLVM_CONFIG} --version
    OUTPUT_VARIABLE EDGE_COVERAGE_LLVM_VERSION
    OUTPUT_STRIP_TRAILING_WHITESPACE
    COMMAND_ERROR_IS_FATAL ANY)

string(REGEX MATCH "^([0-9]+)" _edge_coverage_llvm_major
    "${EDGE_COVERAGE_LLVM_VERSION}")
if(NOT CMAKE_MATCH_1 STREQUAL "20")
    message(FATAL_ERROR
        "Stage 2 requires LLVM 20 (ADR-0024); found ${EDGE_COVERAGE_LLVM_VERSION}")
endif()

execute_process(
    COMMAND ${EDGE_COVERAGE_LLVM_CONFIG} --includedir
    OUTPUT_VARIABLE EDGE_COVERAGE_LLVM_INCLUDEDIR
    OUTPUT_STRIP_TRAILING_WHITESPACE
    COMMAND_ERROR_IS_FATAL ANY)

add_library(EdgeCoveragePass MODULE EdgeCoveragePass.cpp)
target_include_directories(EdgeCoveragePass PRIVATE
    "${EDGE_COVERAGE_LLVM_INCLUDEDIR}")
set_target_properties(EdgeCoveragePass PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF
    POSITION_INDEPENDENT_CODE ON)
