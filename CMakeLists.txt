cmake_minimum_required(VERSION 3.29)
project(Injector)

set(CMAKE_CXX_STANDARD 20)

add_executable(Injector main.cpp
        Injector.cpp
        Injector.h)

set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static")
