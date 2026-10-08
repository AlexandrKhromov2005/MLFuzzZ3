# Generated protobuf sources for the Core ↔ Exec Server IPC schema.
#
# Inputs live in ${CMAKE_SOURCE_DIR}/proto/*.proto; outputs are emitted
# into the build tree and are not committed (see ADR 0002 for the
# rationale). protobuf::protoc comes from the FetchContent-built
# protobuf, so the generator and the linked libprotobuf are guaranteed
# to agree on wire format.

set(IPC_PROTO_FILE ${CMAKE_SOURCE_DIR}/proto/ipc.proto)

set(IPC_GEN_DIR ${CMAKE_CURRENT_BINARY_DIR}/generated)
set(IPC_GEN_HEADER ${IPC_GEN_DIR}/ipc.pb.h)
set(IPC_GEN_SOURCE ${IPC_GEN_DIR}/ipc.pb.cc)

file(MAKE_DIRECTORY ${IPC_GEN_DIR})

add_custom_command(
  OUTPUT ${IPC_GEN_HEADER} ${IPC_GEN_SOURCE}
  COMMAND protobuf::protoc
    --cpp_out=${IPC_GEN_DIR}
    -I ${CMAKE_SOURCE_DIR}/proto
    ${IPC_PROTO_FILE}
  DEPENDS ${IPC_PROTO_FILE} protobuf::protoc
  COMMENT "Generating ipc.pb.{h,cc}"
  VERBATIM
)

add_library(fuzzer_proto STATIC
  ${IPC_GEN_HEADER}
  ${IPC_GEN_SOURCE}
)
add_library(fuzzer::proto ALIAS fuzzer_proto)

target_include_directories(fuzzer_proto
  PUBLIC
    ${IPC_GEN_DIR}
)

# Mark the generated headers directory as SYSTEM so consumers
# with -Werror (like fuzzer::warnings) don't choke on -Wpedantic
# violations transitively pulled from protobuf/abseil headers
# (e.g. __int128 usage in absl/numeric/int128). ADR policy:
# generated and third-party code is not held to our -Werror
# standard; our own code is.
set_property(TARGET fuzzer_proto
  PROPERTY INTERFACE_SYSTEM_INCLUDE_DIRECTORIES
    ${IPC_GEN_DIR}
)

# libprotobuf is a PUBLIC dependency because ipc.pb.h exposes protobuf
# types in its generated API; any consumer of fuzzer::proto needs the
# protobuf headers and must link the runtime. fuzzer::warnings is
# intentionally not attached: generated code must not be held to the
# project's -Werror policy.
target_link_libraries(fuzzer_proto
  PUBLIC
    protobuf::libprotobuf
)

# fuzzer_framing — length-prefixed envelope encoding/decoding
# (ADR 0004 wire protocol). Pure function — no I/O layer.
add_library(fuzzer_framing STATIC framing.cpp)
target_include_directories(fuzzer_framing
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(fuzzer_framing
    PUBLIC  fuzzer::proto tl::expected
    PRIVATE fuzzer::warnings)
add_library(fuzzer::framing ALIAS fuzzer_framing)

# fuzzer_session — C++ client-side IPC session layer
# (ADR 0004 client state machine + Conn abstraction over
# raw fd). No SCM_RIGHTS yet — Task 4c.
add_library(fuzzer_session STATIC session.cpp)
target_include_directories(fuzzer_session
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(fuzzer_session
    PUBLIC  fuzzer::proto fuzzer::framing tl::expected
    PRIVATE fuzzer::warnings)
add_library(fuzzer::session ALIAS fuzzer_session)
