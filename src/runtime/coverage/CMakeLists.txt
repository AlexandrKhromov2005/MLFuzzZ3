# mlfuzzz3 coverage instrumentation library (Stage 1
# per ADR 0017). Standalone — no dependencies on other
# project libs.

add_library(mlfuzzz3_cov SHARED
    mlfuzzz3_cov.c
)

set_target_properties(mlfuzzz3_cov PROPERTIES
    OUTPUT_NAME "mlfuzzz3_cov"
    C_STANDARD 11
    C_STANDARD_REQUIRED ON
    POSITION_INDEPENDENT_CODE ON
)

target_compile_options(mlfuzzz3_cov PRIVATE
    -Wall
    -Wextra
    -Werror
)
