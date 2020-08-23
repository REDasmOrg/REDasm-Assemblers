cmake_minimum_required(VERSION 3.10)

project(REDasm_Assemblers)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

add_subdirectory(x86)
add_subdirectory(mips)
#add_subdirectory(arm)
#add_subdirectory(avr8)
#add_subdirectory(xtensa)
#add_subdirectory(cil)
