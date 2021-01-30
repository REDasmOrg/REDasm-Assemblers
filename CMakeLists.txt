cmake_minimum_required(VERSION 3.12)

project(REDasm_Assemblers)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

add_subdirectory(capstonebundle)
add_subdirectory(xtensa)
add_subdirectory(mips)
add_subdirectory(x86)
#add_subdirectory(avr8)
#add_subdirectory(cil)
