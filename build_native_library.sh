#!/bin/bash

OUTPUT="$1"
LLDIR="$2"

echo "== Linking LLVM IR =="
llvm-link -o __llvm_linked.bc "$LLDIR"/*.ll
echo "== Optimizing offline LLVM IR =="
opt -O3 -o __llvm_opt.bc __llvm_linked.bc -disable-inlining
#cp __llvm_linked.bc __llvm_opt.bc
echo "== Compiling static library to object file with LLC =="
llc -relocation-model=pic -filetype obj -o __linked.o __llvm_opt.bc -O3
echo "== Linking shared library =="
gcc -o "$OUTPUT" -shared __linked.o

rm -f __llvm_linked.bc
rm -f __llvm_opt.bc
rm -f __linked.o
