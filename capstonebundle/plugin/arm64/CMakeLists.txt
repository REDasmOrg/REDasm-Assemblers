cmake_minimum_required(VERSION 3.12)

project(ARM64)
find_package(REDasm REQUIRED)

file(GLOB_RECURSE HEADERS *.h*)
file(GLOB_RECURSE SOURCES *.cpp)

redasm_plugin(${PROJECT_NAME} ${ASSEMBLER_TYPE} ${HEADERS} ${SOURCES})
target_link_libraries(${PROJECT_NAME} PRIVATE capstone-static)
