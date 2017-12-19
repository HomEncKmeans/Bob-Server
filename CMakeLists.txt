cmake_minimum_required(VERSION 3.8)
project(UServer)

set(CMAKE_CXX_STANDARD 11)

include_directories(/usr/local/include/FHESI)
include_directories(/usr/local/include/NTL)
set(SOURCE_FILES main.cpp userverfhesiutils.cpp userverfhesiutils.h UServerV3.cpp UServerV3.h)
add_executable(UServer ${SOURCE_FILES})
target_link_libraries(UServer libfhesi.a libntl.a libgmp.a libm.a)