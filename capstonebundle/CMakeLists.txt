cmake_minimum_required(VERSION 3.12)

project(CapstoneBundle)
find_package(REDasm REQUIRED)

# Override some options and enable all needed architectures
set(CAPSTONE_INSTALL OFF CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(CAPSTONE_ARCHITECTURE_DEFAULT OFF CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_SHARED OFF CACHE BOOL "" FORCE)
set(CAPSTONE_ARM_SUPPORT ON CACHE BOOL "" FORCE)
set(CAPSTONE_ARM64_SUPPORT ON CACHE BOOL "" FORCE)
add_subdirectory(capstone EXCLUDE_FROM_ALL)
include_directories(${PROJECT_NAME} PRIVATE capstone/include)

file(GLOB_RECURSE HEADERS plugin/*.h*)
file(GLOB_RECURSE SOURCES plugin/*.cpp)

redasm_plugin(${PROJECT_NAME} ${ASSEMBLER_TYPE} ${HEADERS} ${SOURCES})
target_link_libraries(${PROJECT_NAME} PRIVATE capstone-static)
