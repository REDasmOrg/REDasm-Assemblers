cmake_minimum_required(VERSION 3.10)

project(MIPS)
find_package(REDasm REQUIRED)

file(GLOB_RECURSE HEADERS *.h*)
file(GLOB_RECURSE SOURCES *.cpp)

redasm_plugin(${PROJECT_NAME} ${ASSEMBLER_TYPE} ${HEADERS} ${SOURCES})
