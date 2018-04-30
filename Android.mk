LOCAL_PATH := $(call my-dir)


include $(CLEAR_VARS)

LOCAL_MODULE := libElfHook_static

LOCAL_SRC_FILES := \
                src/elf_common.cc \
                src/elf_hooker.cc \
                src/elf_module.cc \
                src/elf_file.cc \
                src/elf_mapped.cc \
                src/main.cc

LOCAL_C_INCLUDES :=

LOCAL_LDFLAGS :=

#LOCAL_STATIC_LIBRARIES :=
LOCAL_SHARED_LIBRARIES := stdc++

LOCAL_CFLAGS := \
                -Wno-write-strings \
                -DHAVE_LITTLE_ENDIAN \
                -Werror

include $(BUILD_STATIC_LIBRARY)

####################################

include $(CLEAR_VARS)

LOCAL_MODULE := ElfHook
LOCAL_LDLIBS := -llog
LOCAL_SRC_FILES := \
                src/main.cc

LOCAL_C_INCLUDES :=

LOCAL_LDFLAGS :=

LOCAL_STATIC_LIBRARIES := ElfHook_static
LOCAL_SHARED_LIBRARIES := stdc++

LOCAL_CFLAGS := \
                -Wno-write-strings \
                -DHAVE_LITTLE_ENDIAN \
                -DSTANDALONE=0
include $(BUILD_SHARED_LIBRARY)

####################################

include $(CLEAR_VARS)

LOCAL_MODULE := ElfHook.out
LOCAL_LDLIBS := -llog
LOCAL_SRC_FILES := \
                src/main.cc

LOCAL_C_INCLUDES :=

LOCAL_LDFLAGS := -fPIC -pie

LOCAL_STATIC_LIBRARIES := ElfHook_static
LOCAL_SHARED_LIBRARIES := stdc++

LOCAL_CFLAGS := \
                -Wno-write-strings \
                -DHAVE_LITTLE_ENDIAN \
                -DSTANDALONE=1

include $(BUILD_EXECUTABLE)
