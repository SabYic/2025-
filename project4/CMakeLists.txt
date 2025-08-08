
cmake_minimum_required(VERSION 3.12)
project(sm3_project C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

option(ENABLE_AVX2 "Enable AVX2 for sm3_parallel" ON)

add_library(sm3_base STATIC sm3_base.c)
add_library(sm3_parallel STATIC sm3_parallel.c)

if(ENABLE_AVX2)
  include(CheckCCompilerFlag)
  check_c_compiler_flag("-mavx2" HAS_AVX2_FLAG)
  if(HAS_AVX2_FLAG)
    target_compile_options(sm3_parallel PRIVATE -mavx2)
    target_compile_definitions(sm3_parallel PRIVATE __AVX2__=1)
  endif()
endif()

add_executable(sm3_benchmark sm3_benchmark.c)
target_link_libraries(sm3_benchmark PRIVATE sm3_base sm3_parallel)

if (CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
  add_compile_options(-O3 -Wall -Wextra -Wpedantic)
endif()