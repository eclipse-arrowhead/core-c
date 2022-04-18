cmake_minimum_required(VERSION 3.15)
project(git_describe_header C)

set(CMAKE_C_STANDARD 99)
add_executable(git_metadata_to_header source/main.c)