#!/bin/bash
set -e
##
# Pre-requirements:
# - env FUZZER, TARGET, MAGMA, OUT
# - env CFLAGS/CXXFLAGS carry Magma instrumentation (-include canary.h, etc.)
# - env MLFUZZZ3_EDGE_PASS / MLFUZZZ3_BRANCH_PASS / MLFUZZZ3_COV_LIB exported
##
# Mirrors fuzzers/afl/instrument.sh: point CC/CXX at our self-injecting wrapper
# and append our engine object (the stdin shim) to $LIBS, then build the Magma
# canary object and the target. The wrapper applies Branch+Edge passes and
# links libmlfuzzz3_cov; the shim supplies main().

export CC="$FUZZER/bin/mlfuzzz3-clang-fast"
export CXX="$FUZZER/bin/mlfuzzz3-clang-fast++"

export LIBS="$LIBS -l:mlfuzzz3_shim.o -lstdc++"

"$MAGMA/build.sh"
"$TARGET/build.sh"
