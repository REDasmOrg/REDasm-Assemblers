cmake_minimum_required(VERSION 3.10)

project(ARM64)
find_package(REDasm REQUIRED)

file(GLOB_RECURSE HEADERS plugin/*.h*)
file(GLOB_RECURSE SOURCES plugin/*.cpp)

# Override some Capstone options and enable ARM64
set(CAPSTONE_INSTALL OFF CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(CAPSTONE_ARCHITECTURE_DEFAULT OFF CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_SHARED OFF CACHE BOOL "" FORCE)
set(CAPSTONE_ARM64_SUPPORT ON CACHE BOOL "" FORCE)
add_subdirectory(capstone EXCLUDE_FROM_ALL)

redasm_plugin(${PROJECT_NAME} ${ASSEMBLER_TYPE} ${HEADERS} ${SOURCES})
target_include_directories(${PROJECT_NAME} PRIVATE capstone/include)
target_link_libraries(${PROJECT_NAME} PRIVATE capstone-static)
