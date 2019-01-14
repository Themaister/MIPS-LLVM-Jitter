#!/bin/bash

OUTPUT="$1"
LLDIR="$2"

echo "== Linking LLVM IR =="
llvm-link -o __llvm_linked.bc "$LLDIR"/*.ll
echo "== Compiling static library to object file with LLC =="
llc -relocation-model=pic -filetype obj -o __linked.o __llvm_linked.bc -O3
echo "== Linking shared library =="
gcc -o "$OUTPUT" -shared __linked.o

rm -f __llvm_linked.bc
rm -f __linked.o
