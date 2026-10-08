# Phase 2 mutation foundation (ADR 0027).
#
# Provides the FuzzInput owning buffer, the abstract Mutator interface,
# the reference mutators (BitFlip, ByteFlip, Havoc), the shared positional
# op primitives (ops.h, ADR 0031), and the deterministic stage operator
# (ADR 0031). This is an internal core module — not part of the public
# ABI exposed under include/fuzzer/. Corpus management and the mutation
# loop live in fuzzer::core and link against this library.

add_library(fuzzer_mutation STATIC
  mutators/bit_flip.cpp
  mutators/byte_flip.cpp
  mutators/havoc.cpp
  ops.cpp
  deterministic_stage.cpp
)
add_library(fuzzer::mutation ALIAS fuzzer_mutation)

target_include_directories(fuzzer_mutation
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(fuzzer_mutation
  PRIVATE
    fuzzer::warnings
)
