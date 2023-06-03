project(ttf-mesh-fuzz)

cmake_minimum_required(VERSION 3.10)
set(CMAKE_CXX_STANDARD 20)

add_compile_options(-fsanitize=fuzzer,undefined)
add_link_options(-fsanitize=fuzzer,undefined)

add_executable(ttf-mesh-fuzz fuzz_lib.cpp ../ttf2mesh.c)
include_directories(..)



