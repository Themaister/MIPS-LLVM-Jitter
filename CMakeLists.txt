cmake_minimum_required(VERSION 3.5)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_C_STANDARD 99)
project(Jitter LANGUAGES CXX C)

include(ExternalProject)
ExternalProject_Add(llvm
	SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/llvm
	INSTALL_DIR ${CMAKE_BINARY_DIR}/llvm
	TEST_COMMAND ${CMAKE_COMMAND} -E touch ${CMAKE_CURRENT_LIST_FILE}
	CMAKE_ARGS
		-DCMAKE_BUILD_TYPE=Release
		-DCMAKE_INSTALL_PREFIX=<INSTALL_DIR>
		-DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}
		-DLLVM_TARGETS_TO_BUILD=X86
		-DLLVM_INCLUDE_TESTS=OFF
		-DLLVM_INCLUDE_EXAMPLES=OFF
		-DLLVM_BUILD_DOCS=OFF
		-DLLVM_ENABLE_RTTI=OFF
		-DLLVM_BUILD_LLVM_DYLIB=OFF
	LOG_CONFIGURE 1
	LOG_BUILD 1
	LOG_INSTALL 1)

option(USE_SYSTEM_LLVM "Use system LLVM." ON)

if (USE_SYSTEM_LLVM)
    find_package(LLVM REQUIRED CONFIG)
else()
    find_package(LLVM REQUIRED CONFIG PATHS ${CMAKE_BINARY_DIR}/llvm NO_DEFAULT_PATH)
    if (NOT LLVM_FOUND)
        ExternalProject_Get_Property(llvm INSTALL_DIR)
        set(LLVM_ROOT ${INSTALL_DIR})
        set(LLVM_DIR ${LLVM_ROOT}/share/llvm/cmake CACHE PATH "Forced location of LLVM cmake config" FORCE)
        message(WARNING "No LLVM found. Rebuild.")
    endif()
endif()

set_target_properties(llvm PROPERTIES EXCLUDE_FROM_ALL ON)
message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")

if (CMAKE_COMPILER_IS_GNUCXX OR (${CMAKE_CXX_COMPILER_ID} MATCHES "Clang"))
    set(JITTER_CXX_FLAGS -Wall -Wextra -Wno-missing-field-initializers -Wno-empty-body -ffast-math -Wno-unused-parameter)
elseif (MSVC)
    set(JITTER_CXX_FLAGS /D_CRT_SECURE_NO_WARNINGS /wd4267 /wd4244 /wd4309 /wd4005 /MP /DNOMINMAX)
endif()

add_library(jitter STATIC
        jitter.hpp jitter.cpp
        ir_frontend.hpp ir_frontend.cpp)

add_executable(jitter-test main.cpp)
target_link_libraries(jitter-test PRIVATE jitter)
target_compile_options(jitter-test PRIVATE ${JITTER_CXX_FLAGS})

target_compile_options(jitter PRIVATE ${JITTER_CXX_FLAGS})
target_include_directories(jitter PUBLIC ${LLVM_INCLUDE_DIRS})
target_compile_definitions(jitter PUBLIC ${LLVM_DEFINITIONS})
if (${LLVM_VERSION_MAJOR} LESS 8)
    target_compile_definitions(jitter PUBLIC JITTER_LLVM_VERSION_LEGACY)
endif()

llvm_map_components_to_libnames(llvm_libs Core Support OrcJIT X86Info X86Utils X86CodeGen X86AsmParser X86AsmPrinter)
target_link_libraries(jitter PRIVATE ${llvm_libs})

