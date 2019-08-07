cmake_minimum_required(VERSION 3.10)

project(Xtensa)
find_package(REDasm REQUIRED)

file(GLOB_RECURSE HEADERS *.h*)
file(GLOB_RECURSE SOURCES *.cpp)

redasm_plugin(${PROJECT_NAME} ${HEADERS} ${SOURCES})
