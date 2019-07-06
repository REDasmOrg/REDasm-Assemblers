cmake_minimum_required(VERSION 3.10)

project(ARM)
find_package(REDasm REQUIRED)

set(ARM_COMMON_HEADERS arm/arm_common.h metaarm/metaarm_printer.h)
set(ARM_COMMON_SOURCES arm/arm_common.cpp metaarm/metaarm_printer.cpp)
set(ARM_HEADERS ${ARM_COMMON_HEADERS} arm/arm.h)
set(ARM_SOURCES ${ARM_COMMON_SOURCES} arm/arm.cpp arm_plugin.cpp)
set(ARM_THUMB_HEADERS ${ARM_COMMON_HEADERS} arm/arm_thumb.h)
set(ARM_THUMB_SOURCES ${ARM_COMMON_SOURCES} arm/arm_thumb.cpp armthumb_plugin.cpp)

file(GLOB_RECURSE META_ARM_COMMON_HEADERS arm/*.h* metaarm/*.h*)
file(GLOB_RECURSE META_ARM_COMMON_SOURCES arm/*.cpp, metaarm/*.cpp)
set(META_ARM_HEADERS ${META_ARM_COMMON_HEADERS})
set(META_ARM_SOURCES ${META_ARM_COMMON_SOURCES} metaarm_plugin.cpp)

redasm_plugin(ARM ${ARM_HEADERS} ${ARM_SOURCES})
redasm_plugin(ARMThumb ${ARM_THUMB_HEADERS} ${ARM_THUMB_SOURCES})
redasm_plugin(MetaARM ${META_ARM_HEADERS} ${META_ARM_SOURCES})
