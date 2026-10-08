#!/bin/bash
set -e
##
# Pre-requirements:
# - env FUZZER: path to this fuzzer's work dir
# - env OUT: artifact dir
# - env MLFUZZZ3_CLANG: real C compiler (clang-20)
##
# Build the stdin one-shot driver shim as a relocatable object, uninstrumented
# (it carries no target code; instrumenting it would only add constant edges).
# It is linked into the target via instrument.sh's $LIBS, supplying main().
# Also ensure the C++ wrapper alias exists and the wrappers are executable.

chmod +x "$FUZZER/bin/mlfuzzz3-clang-fast"
ln -sf mlfuzzz3-clang-fast "$FUZZER/bin/mlfuzzz3-clang-fast++"

"${MLFUZZZ3_CLANG:-clang-20}" -O1 -g -fPIC -c \
    "$FUZZER/src/mlfuzzz3_shim.c" -o "$OUT/mlfuzzz3_shim.o"
