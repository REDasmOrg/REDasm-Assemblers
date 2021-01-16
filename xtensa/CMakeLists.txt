cmake_minimum_required(VERSION 3.12)

project(Xtensa)
find_package(REDasm REQUIRED)

file(GLOB HEADERS *.h*)
file(GLOB SOURCES *.cpp)

add_subdirectory(xtensagnu EXCLUDE_FROM_ALL)
redasm_plugin(${PROJECT_NAME} ${HEADERS} ${SOURCES})
target_link_libraries(${PROJECT_NAME} PRIVATE XtensaGNU)
