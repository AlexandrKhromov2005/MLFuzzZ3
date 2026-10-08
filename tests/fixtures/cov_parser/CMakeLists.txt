# Discriminating parser fixture for the Phase 2 benchmark checkpoint
# (ADR 0032). Same build shape as cov_crash (clang + EdgeCoveragePass +
# libmlfuzzz3_cov via DT_NEEDED): positional coverage checkpoints, a
# length-preserving crash A and a length-growing crash B, used to separate
# mutation strategies. Built via add_custom_command with clang explicitly
# (the project default C compiler may be gcc, which lacks -fpass-plugin);
# self-skips when clang is absent (the benchmark smoke test self-skips too).

find_program(MLFUZZZ3_COV_PARSER_CLANG NAMES clang)

if(NOT MLFUZZZ3_COV_PARSER_CLANG)
    message(STATUS
        "clang not found; cov_parser_target will not be "
        "built (benchmark fixture smoke test will self-skip)")
    return()
endif()

set(_cov_parser_bin
    ${CMAKE_CURRENT_BINARY_DIR}/cov_parser_target)
set(_cov_parser_obj
    ${CMAKE_CURRENT_BINARY_DIR}/cov_parser_target.o)
set(_cov_parser_src
    ${CMAKE_CURRENT_SOURCE_DIR}/cov_parser_target.c)

add_custom_command(
    OUTPUT ${_cov_parser_obj}
    COMMAND ${MLFUZZZ3_COV_PARSER_CLANG}
        -O0 -g
        -fpass-plugin=$<TARGET_FILE:EdgeCoveragePass>
        -Wall -Wextra
        -c
        ${_cov_parser_src}
        -o ${_cov_parser_obj}
    DEPENDS ${_cov_parser_src} EdgeCoveragePass
    COMMENT "Compiling cov_parser_target.o with EdgeCoveragePass"
    VERBATIM)

add_custom_command(
    OUTPUT ${_cov_parser_bin}
    COMMAND ${MLFUZZZ3_COV_PARSER_CLANG}
        ${_cov_parser_obj}
        $<TARGET_FILE:mlfuzzz3_cov>
        -Wl,-rpath,$<TARGET_FILE_DIR:mlfuzzz3_cov>
        -o ${_cov_parser_bin}
    DEPENDS ${_cov_parser_obj} mlfuzzz3_cov
    COMMENT "Linking cov_parser_target against libmlfuzzz3_cov"
    VERBATIM)

add_custom_target(cov_parser_build ALL
    DEPENDS ${_cov_parser_bin})
