cmake_minimum_required(VERSION 3.10)
project(FuzzTarget CXX)

add_library(FuzzTarget STATIC src/harness.cpp)
