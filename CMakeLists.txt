cmake_minimum_required(VERSION 3.18.1)

project("elfhooker")

SET(files src/elf_common.cc
          src/elf_hooker.cc
          src/elf_module.cc
          src/elf_file.cc
          src/elf_mapped.cc)

SET(headers src/elf_common.h
            src/elf_hooker.h
            src/elf_module.h
            src/elf_log.h)

SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-omit-frame-pointer")
SET(CMAKE_LINKER_FLAGS "${CMAKE_STATIC_LINKER_FLAGS} -fno-omit-frame-pointer")
MESSAGE(WANNING "source dir: ${PROJECT_SOURCE_DIR}")


ADD_LIBRARY(elfhook STATIC ${files})
SET_TARGET_PROPERTIES(elfhook PROPERTIES PUBLIC_HEADER "${headers}")
INSTALL(TARGETS elfhook
        ARCHIVE
        DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/${ANDROID_ABI}
        PUBLIC_HEADER
        DESTINATION ${CMAKE_INSTALL_PREFIX}/inc)

IF (${ANDROID_ABI} STREQUAL "armeabi-v7a")
    SET(HOOKER "hooker.32")
ELSEIF(${ANDROID_ABI} STREQUAL "arm64-v8a")
    SET(HOOKER "hooker.64")
ELSE()
    MESSAGE(FATAL_ERROR "unsupport ARCH_API: ${ANDROID_ABI}" )
ENDIF()

ADD_EXECUTABLE(${HOOKER} src/main.cc)
TARGET_LINK_LIBRARIES(${HOOKER} elfhook)
INSTALL(TARGETS ${HOOKER}
        RUNTIME
        DESTINATION ${CMAKE_INSTALL_PREFIX}/bin)
