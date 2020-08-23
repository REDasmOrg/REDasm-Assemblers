cmake_minimum_required(VERSION 3.10)

project(X86)
find_package(REDasm REQUIRED)

set(HEADERS zydiscommon.h x86.h x86_lifter.h)
set(SOURCES zydiscommon.cpp x86.cpp x86_lifter.cpp)

option(ZYDIS_BUILD_TOOLS "" OFF)
option(ZYDIS_BUILD_EXAMPLES "" OFF)
add_subdirectory(zydis)

redasm_plugin(${PROJECT_NAME} ${HEADERS} ${SOURCES})
target_link_libraries(${PROJECT_NAME} PRIVATE Zydis)
