# MIPS-LLVM-Jitter

This implements a basic MIPS I to LLVM recompiler.
It loads MIPS ELF files which target Linux.
Little-endian and big-endian are both supported.
No privileged instructions are supported, a handful of syscalls, enough to run some applications.
The recompiler has been tested with glibc and libstdc++.

Floating point for MIPS I is supported, except FP control register rounding modes.

Only Linux as the host-OS is currently supported/tested, due to how the syscalls are implemented.
Other OSes could be supported with more sophisticated syscall emulation.

LLVM 7 and 8 have been tested.

## Build

Build with CMake. Nothing unusual.

## Blog series

There is a blog series about this project. See:

- [Part 1](http://themaister.net/blog/2019/01/27/an-unusual-recompiler-experiment-mips-to-llvm-ir-part-1/)
- [Part 2](http://themaister.net/blog/2019/01/29/an-unusual-recompiler-experiment-mips-to-llvm-ir-part-2/)
- [Part 3](http://themaister.net/blog/2019/02/03/an-unusual-recompiler-experiment-mips-to-llvm-ir-part-3/)
- [Part 4](http://themaister.net/blog/2019/02/09/an-unusual-recompiler-experiment-mips-to-llvm-ir-part-4/)

## Potential use cases

A major use case I have in mind is porting old game titles or applications with binary translation.
MIPS was a fairly common architecture in the 90s and early 00s. There might be legacy applications out there
which could benefit from this work.

## Disclaimer

This codebase is placed on Github under a permissive license in the hope someone finds it interesting and educational. It is not expected to be useful as-is. Do not expect any support or further development (for free).

If you have any commercial use for this project which needs further development to accomplish, I might be available for contracting work. Contact me by e-mail on "post at arntzen-software.no".

