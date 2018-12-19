cmake_minimum_required(VERSION 3.5)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_C_STANDARD 99)
project(Jitter LANGUAGES CXX C)

find_package(LLVM REQUIRED CONFIG)
message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")

if (CMAKE_COMPILER_IS_GNUCXX OR (${CMAKE_CXX_COMPILER_ID} MATCHES "Clang"))
    set(JITTER_CXX_FLAGS -Wall -Wextra -Wno-missing-field-initializers -Wno-empty-body -ffast-math)
elseif (MSVC)
    set(JITTER_CXX_FLAGS /D_CRT_SECURE_NO_WARNINGS /wd4267 /wd4244 /wd4309 /wd4005 /MP /DNOMINMAX)
endif()

add_library(jitter STATIC jitter.hpp jitter.cpp)
add_executable(jitter-test main.cpp)
target_link_libraries(jitter-test PRIVATE jitter)
target_compile_options(jitter-test PRIVATE ${JITTER_CXX_FLAGS})

target_compile_options(jitter PRIVATE ${JITTER_CXX_FLAGS})
target_include_directories(jitter PUBLIC ${LLVM_INCLUDE_DIRS})
target_compile_definitions(jitter PUBLIC ${LLVM_DEFINITIONS})

llvm_map_components_to_libnames(llvm_libs Core OrcJIT X86Info X86Utils X86CodeGen X86AsmParser X86AsmPrinter)
target_link_libraries(jitter PRIVATE ${llvm_libs})

