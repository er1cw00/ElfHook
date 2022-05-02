#if !defined(__ELF_LOG_H__)
#define __ELF_LOG_H__

#include <stdio.h>
#include <stdlib.h>
#include <android/log.h>

#define LOG_TO_CONSOLE (1)

#if (LOG_TO_CONSOLE)

#define log_info(...)   do{ fprintf(stdout, __VA_ARGS__); } while(0)
#define log_error(...)  do{ fprintf(stdout, __VA_ARGS__); } while(0)
#define log_warn(...)   do{ fprintf(stdout, __VA_ARGS__); } while(0)
#define log_fatal(...)  do{ fprintf(stdout, __VA_ARGS__); } while(0)
#define log_dbg(...)    do{ fprintf(stdout, __VA_ARGS__); } while(0)

#else

#define sTag ("ELFKooH")
#define log_info(...)   do{ __android_log_print(ANDROID_LOG_INFO,   sTag,  __VA_ARGS__); }while(0)
#define log_error(...)  do{ __android_log_print(ANDROID_LOG_ERROR,  sTag,  __VA_ARGS__); }while(0)
#define log_warn(...)   do{ __android_log_print(ANDROID_LOG_WARN,   sTag,  __VA_ARGS__); }while(0)
#define log_dbg(...)    do{ __android_log_print(ANDROID_LOG_DEBUG,  sTag,  __VA_ARGS__); }while(0)
#define log_fatal(...)  do{ __android_log_print(ANDROID_LOG_FATAL,  sTag,  __VA_ARGS__); }while(0)

#endif

#endif

