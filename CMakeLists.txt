cmake_minimum_required(VERSION 3.18.1)

project("elfhooker")

SET(cc_files src/elf_common.cc
             src/elf_hooker.cc
             src/elf_module.cc
             src/elf_file.cc
             src/elf_mapped.cc)

SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-omit-frame-pointer")
SET(CMAKE_LINKER_FLAGS "${CMAKE_STATIC_LINKER_FLAGS} -fno-omit-frame-pointer")

ADD_LIBRARY(elfhooker STATIC ${cc_files})

ADD_EXECUTABLE(hooker src/main.cc)

TARGET_LINK_LIBRARIES(hooker elfhooker)

