cmake_minimum_required(VERSION 3.8)
project(UServer)

set(CMAKE_CXX_STANDARD 11)

include_directories(/usr/local/include/FHESI)
include_directories(/usr/local/include/NTL)
#set(SOURCE_FILES main.cpp userverfhesiutils.cpp userverfhesiutils.h UServerT1V1.cpp UServerT1V1.h)
#set(SOURCE_FILES main.cpp userverfhesiutils.cpp userverfhesiutils.h UServerT1V2.cpp UServerT1V2.h)
#set(SOURCE_FILES main.cpp userverfhesiutils.cpp userverfhesiutils.h UServerT1V3.cpp UServerT1V3.h)
set(SOURCE_FILES main.cpp userverfhesiutils.cpp userverfhesiutils.h UServerT2V1.cpp UServerT2V1.h)
#set(SOURCE_FILES main.cpp userverfhesiutils.cpp userverfhesiutils.h UServerT2V2.cpp UServerT2V2.h)
#set(SOURCE_FILES main.cpp userverfhesiutils.cpp userverfhesiutils.h UServerT2V3.cpp UServerT2V3.h)

add_executable(UServer ${SOURCE_FILES})
target_link_libraries(UServer libfhesi.a libntl.a libgmp.a libm.a)