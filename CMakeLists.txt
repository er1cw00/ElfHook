cmake_minimum_required(VERSION 3.18.1)

project("elfhooker")

SET(cc_files src/elf_common.cc
             src/elf_hooker.cc
             src/elf_module.cc
             src/elf_file.cc
             src/elf_mapped.cc)

ADD_LIBRARY(elfhooker STATIC ${cc_files})

ADD_EXECUTABLE(hooker src/main.cc)

TARGET_LINK_LIBRARIES(hooker elfhooker)