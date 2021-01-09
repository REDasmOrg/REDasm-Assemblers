cmake_minimum_required(VERSION 3.12)

project(X86)
find_package(REDasm REQUIRED)

set(HEADERS zydiscommon.h x86.h x86_lifter.h x86_prologue.h)
set(SOURCES zydiscommon.cpp x86.cpp x86_lifter.cpp x86_prologue.cpp)

option(ZYDIS_BUILD_TOOLS "" OFF)
option(ZYDIS_BUILD_EXAMPLES "" OFF)
add_subdirectory(zydis EXCLUDE_FROM_ALL)

redasm_plugin(${PROJECT_NAME} ${ASSEMBLER_TYPE} ${HEADERS} ${SOURCES})
target_link_libraries(${PROJECT_NAME} PRIVATE Zydis)
