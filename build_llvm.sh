#!/bin/bash

cd llvm
cmake --build . --target install -- -j2 # parallel

