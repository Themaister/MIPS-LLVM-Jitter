cmake_minimum_required(VERSION 3.5)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_C_STANDARD 99)
project(MIPS-LLVM-Jitter LANGUAGES CXX C)

find_package(LLVM REQUIRED CONFIG)
message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")

if (CMAKE_COMPILER_IS_GNUCXX OR (${CMAKE_CXX_COMPILER_ID} MATCHES "Clang"))
    set(JITTER_CXX_FLAGS -Wall -Wextra -Wno-missing-field-initializers -Wno-empty-body -ffast-math -Wno-unused-parameter)
elseif (MSVC)
    set(JITTER_CXX_FLAGS /D_CRT_SECURE_NO_WARNINGS /wd4267 /wd4244 /wd4309 /wd4005 /MP /DNOMINMAX)
endif()

add_library(mips-llvm-jitter STATIC
        jitter.hpp jitter.cpp
        ir_function.hpp ir_function.cpp
        linuxvm.cpp linuxvm.hpp
        mips.hpp mips.cpp
        mips_c_stubs.inc
        mips_external_calls.cpp
        mips_recompile.cpp
        register_tracker.cpp register_tracker.hpp
        mips_opcode.hpp mips_opcode.cpp
        cli_parser.hpp cli_parser.cpp
        ir_recompile.cpp ir_recompile.hpp)

add_executable(mipsvm mipsvm.cpp)
target_link_libraries(mipsvm PRIVATE mips-llvm-jitter)
target_compile_options(mipsvm PRIVATE ${JITTER_CXX_FLAGS})
set_target_properties(mipsvm PROPERTIES LINK_FLAGS "-rdynamic")

target_compile_options(mips-llvm-jitter PRIVATE ${JITTER_CXX_FLAGS})
target_include_directories(mips-llvm-jitter PUBLIC ${LLVM_INCLUDE_DIRS})
target_compile_definitions(mips-llvm-jitter PUBLIC ${LLVM_DEFINITIONS})
if (${LLVM_VERSION_MAJOR} LESS 8)
    target_compile_definitions(mips-llvm-jitter PUBLIC JITTER_LLVM_VERSION_LEGACY)
endif()

llvm_map_components_to_libnames(llvm_libs Core Support OrcJIT X86Info X86Utils X86CodeGen X86AsmParser)
target_link_libraries(mips-llvm-jitter PRIVATE ${llvm_libs})

