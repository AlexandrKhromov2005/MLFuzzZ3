# Branch-channel fixture (ADR 0033). For Шаг 3 it emits branch-pass-
# only instrumented IR consumed by the branch-pass IR unit test; the
# executable target for the Шаг 6 format smoke e2e is added later.
#
# Built with clang explicitly (the project default C compiler may be
# gcc, which lacks -fpass-plugin); self-skips when clang is absent —
# the branch-pass IR test then self-skips too.

find_program(MLFUZZZ3_BRANCH_ICMP_CLANG NAMES clang)

if(NOT MLFUZZZ3_BRANCH_ICMP_CLANG)
    message(STATUS
        "clang not found; branch_icmp fixture will not be built "
        "(branch-pass IR test will self-skip)")
    return()
endif()

set(_branch_icmp_src ${CMAKE_CURRENT_SOURCE_DIR}/branch_icmp_target.c)
set(_branch_icmp_ll ${CMAKE_CURRENT_BINARY_DIR}/branch_icmp_instrumented.ll)

# Instrumented IR with ONLY the branch pass (no edge pass), so the IR
# contains exactly the fixture's own icmps and their inserted hooks.
add_custom_command(
    OUTPUT ${_branch_icmp_ll}
    COMMAND ${MLFUZZZ3_BRANCH_ICMP_CLANG}
        -O0
        -fpass-plugin=$<TARGET_FILE:BranchTracePass>
        -Wall -Wextra
        -emit-llvm -S
        ${_branch_icmp_src}
        -o ${_branch_icmp_ll}
    DEPENDS ${_branch_icmp_src} BranchTracePass
    COMMENT "Emitting branch-pass-instrumented IR for branch_icmp_target"
    VERBATIM)

add_custom_target(branch_icmp_ll ALL DEPENDS ${_branch_icmp_ll})

# Таблица сайтов (ADR 0047 §Решение-5): тот же исходник собирается ОТДЕЛЬНОЙ
# командой с -g и с заданным MLFUZZZ3_SITEMAP_DIR. Команда выше не трогается
# намеренно: -g меняет IR, а её вывод читает тест инструментации.
set(_branch_icmp_sitemap_dir ${CMAKE_CURRENT_BINARY_DIR}/sitemap)
set(_branch_icmp_sitemap_stamp ${CMAKE_CURRENT_BINARY_DIR}/sitemap.stamp)

add_custom_command(
    OUTPUT ${_branch_icmp_sitemap_stamp}
    COMMAND ${CMAKE_COMMAND} -E rm -rf ${_branch_icmp_sitemap_dir}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${_branch_icmp_sitemap_dir}
    COMMAND ${CMAKE_COMMAND} -E env MLFUZZZ3_SITEMAP_DIR=${_branch_icmp_sitemap_dir}
        ${MLFUZZZ3_BRANCH_ICMP_CLANG}
        -O0 -g
        -fpass-plugin=$<TARGET_FILE:BranchTracePass>
        -c ${_branch_icmp_src}
        -o ${CMAKE_CURRENT_BINARY_DIR}/branch_icmp_sitemap.o
    COMMAND ${CMAKE_COMMAND} -E touch ${_branch_icmp_sitemap_stamp}
    DEPENDS ${_branch_icmp_src} BranchTracePass
    COMMENT "Emitting site map for branch_icmp_target"
    VERBATIM)

add_custom_target(branch_icmp_sitemap ALL DEPENDS ${_branch_icmp_sitemap_stamp})

# Executable fixture for the Шаг 6 format smoke e2e: same source built
# with BOTH passes and linked against libmlfuzzz3_cov (DT_NEEDED), same
# shape as cov_parser. The branch plugin is loaded FIRST so its
# PipelineStartEP callback runs before the edge pass — it then only
# sees the fixture's own icmps, never the edge pass's inserted
# saturating-compare. So the branch log holds exactly the five user
# comparisons while edge coverage is collected on the same run.
set(_branch_icmp_bin ${CMAKE_CURRENT_BINARY_DIR}/branch_icmp_target)
set(_branch_icmp_obj ${CMAKE_CURRENT_BINARY_DIR}/branch_icmp_target.o)

add_custom_command(
    OUTPUT ${_branch_icmp_obj}
    COMMAND ${MLFUZZZ3_BRANCH_ICMP_CLANG}
        -O0 -g
        -fpass-plugin=$<TARGET_FILE:BranchTracePass>
        -fpass-plugin=$<TARGET_FILE:EdgeCoveragePass>
        -Wall -Wextra
        -c
        ${_branch_icmp_src}
        -o ${_branch_icmp_obj}
    DEPENDS ${_branch_icmp_src} BranchTracePass EdgeCoveragePass
    COMMENT "Compiling branch_icmp_target.o with Branch+Edge passes"
    VERBATIM)

add_custom_command(
    OUTPUT ${_branch_icmp_bin}
    COMMAND ${MLFUZZZ3_BRANCH_ICMP_CLANG}
        ${_branch_icmp_obj}
        $<TARGET_FILE:mlfuzzz3_cov>
        -Wl,-rpath,$<TARGET_FILE_DIR:mlfuzzz3_cov>
        -o ${_branch_icmp_bin}
    DEPENDS ${_branch_icmp_obj} mlfuzzz3_cov
    COMMENT "Linking branch_icmp_target against libmlfuzzz3_cov"
    VERBATIM)

add_custom_target(branch_icmp_build ALL
    DEPENDS ${_branch_icmp_bin})
