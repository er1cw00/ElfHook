
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <dlfcn.h>

#include "elf_hooker.h"
#include "elf_log.h"

static void* (*__old_impl_dlopen)(const char* filename, int flag);

static int (*__old_impl_connect)(int sockfd,struct sockaddr * serv_addr,int addrlen);

static void* (*__old_impl_android_dlopen_ext)(const char* filename, int flags, const void* extinfo);

extern "C" {

    static void* __nativehook_impl_dlopen(const char* filename, int flag) {

        log_info("__nativehook_impl_dlopen -> (%s)\n", filename);
        void* res = __old_impl_dlopen(filename, flag);
        log_info("res: %p\n", res);
        return res;
    }

    static int __nativehook_impl_connect(int sockfd,struct sockaddr * serv_addr,int addrlen) {

        log_info("__nativehook_impl_connect ->\n");
        int res = __old_impl_connect(sockfd, serv_addr, addrlen);
        return res;
    }

    static void* __nativehook_impl_android_dlopen_ext(const char* filename, int flags, const void* extinfo) {

        log_info("__nativehook_impl_android_dlopen_ext -> (%s)\n", filename);
        void* res = __old_impl_android_dlopen_ext(filename, flags, extinfo);
        log_info("res: %p\n", res);
        return res;
    }

}

static bool __prehook(const char* module_name) {
    if (strstr(module_name, "libwebviewchromium.so") != NULL) {
       return true;
    }
    return false;
}

#if (STANDALONE)

int main(int argc, char* argv[]) {
    char ch = 0;
    elf_hooker hooker;

    void* h = dlopen("libart.so", RTLD_LAZY);
    void* f = dlsym(h,"artAllocObjectFromCodeResolvedRegion");
    log_info("artAllocObjectFromCodeResolvedRegion : %p\n", f);

    hooker.set_prehook_cb(__prehook);

    hooker.load();
    hooker.dump_soinfo_list();
    
    struct elf_rebinds rebinds[4] = {
        {"dlopen",            (void *)__nativehook_impl_dlopen,            (void **)&__old_impl_dlopen},
        {"connect",           (void *)__nativehook_impl_connect,           (void **)&__old_impl_connect},
        {"android_dlopen_ext", (void*)__nativehook_impl_android_dlopen_ext, (void**)&__old_impl_android_dlopen_ext},
        {NULL, NULL, NULL},
    };

    hooker.hook_all_modules(rebinds);

    fprintf(stderr, "old dlopen: %p\n", __old_impl_dlopen);
    fprintf(stderr, "old connect: %p\n", __old_impl_connect);

    uintptr_t origin_dlopen = static_cast<uintptr_t>(NULL);
    hooker.find_function_addr("/system/lib/libdl.so", "dlopen", origin_dlopen);
    fprintf(stderr ,"origin_dlopen: %p\n", (void*)origin_dlopen);
    
    do {
        ch = getc(stdin);
    } while(ch != 'q');
    return 0;
}

#else

#include <jni.h>

static char* __class_name = "com/wadahana/testhook/ElfHooker";
static elf_hooker __hooker;
static JavaVM* __java_vm = NULL;
static bool __is_attached = false;

static JNIEnv* __getEnv(bool* attached);
static void __releaseEnv(bool attached);
static int __set_hook(JNIEnv *env, jobject thiz);
static int __test(JNIEnv *env, jobject thiz);
static int __elfhooker_init(JavaVM* vm, JNIEnv* env);
static void __elfhooker_deinit(void);

static JNINativeMethod __methods[] =
{
    {"setHook","()I",(void *)__set_hook },
    {"test","()I",(void *)__test },
};

typedef uint32_t (*fn_get_sdk_version)(void);



static int __set_hook(JNIEnv *env, jobject thiz)
{
    log_info("__set_hook() -->\r\n");
    __hooker.set_prehook_cb(__prehook);
    __hooker.load();
    __hooker.dump_soinfo_list();

    struct elf_rebinds rebinds[4] = {
        {"dlopen",            (void *)__nativehook_impl_dlopen,            (void **)&__old_impl_dlopen},
        {"connect",           (void *)__nativehook_impl_connect,           (void **)&__old_impl_connect},
        {"android_dlopen_ext", (void*)__nativehook_impl_android_dlopen_ext, (void**)&__old_impl_android_dlopen_ext},
        {NULL, NULL, NULL},
    };

    __hooker.hook_all_modules(rebinds);

    elf_module module;
    if (__hooker.new_module("libart.so", module)) {
        
        log_info("module base:%lx, %lx, %s\n",
                (unsigned long)module.get_base_addr(),
                (unsigned long)module.get_bias_addr(),
                module.get_module_name());

        void * h = dlopen("/system/lib/libc.so", RTLD_GLOBAL);
        log_info("dlopen() h (%p)\n", h);

        module.hook("dlopen",             (void*)__nativehook_impl_dlopen,             (void**)&__old_impl_dlopen);
        module.hook("connect",            (void*)__nativehook_impl_connect,            (void**)&__old_impl_connect);
        module.hook("android_dlopen_ext", (void*)__nativehook_impl_android_dlopen_ext, (void**)&__old_impl_android_dlopen_ext);
    }
    return 0;
}

static int __test(JNIEnv *env, jobject thiz)
{
    log_info("__test() -->\r\n");
    return 0;
}

static int __elfhooker_register_native_methods(JNIEnv* env, const char* class_name,
                                JNINativeMethod* methods, int num_methods)
{

    log_info("RegisterNatives start for \'%s\'", __class_name);

    jclass clazz = env->FindClass(class_name);
    if (clazz == NULL)
    {
        log_error("Native registration unable to find class \'%s\'", class_name);
        return JNI_FALSE;
    }

    if (env->RegisterNatives(clazz, methods, num_methods) < 0)
    {
        log_error("RegisterNatives failed for \'%s\'", class_name );
        return JNI_FALSE;
    }

    return JNI_TRUE;
}

static int __elfhooker_init(JavaVM* vm, JNIEnv* env)
{
    log_info("hookwrapper_init() -->\r\n");
    if (!__elfhooker_register_native_methods(env, __class_name,
                __methods, sizeof(__methods) / sizeof(__methods[0])))
    {
        log_error("register hookJNIMethod fail, \r\n");
        __elfhooker_deinit();
        return -2;
    }

  return 0;
}

static void __elfhooker_deinit(void)
{
    log_info("hookwrapper_deinit()->\r\n");
    return;
}


JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved)
{
    JNIEnv* env = NULL;
    bool attached;
    __java_vm = vm;

    if ((env = __getEnv(&__is_attached)) == NULL)
    {
        log_error("getEnv fail\r\n");
        return -1;
    }
    assert(!__is_attached);
    if (__elfhooker_init(vm, env) < 0)
    {
        log_error("__elfhooker_init fail\r\n");
        return -1;
    }
    return JNI_VERSION_1_4;
}

JNIEXPORT void JNICALL JNI_OnUnload(JavaVM* vm, void* reserved)
{
    bool attached;
    JNIEnv* env = __getEnv(&__is_attached);
    assert(!__is_attached);

    __elfhooker_deinit();
    return ;
}

static JNIEnv* __getEnv(bool* attached)
{
    JNIEnv* env = NULL;
    *attached = false;
    int ret = __java_vm->GetEnv((void**)&env, JNI_VERSION_1_4);
    if (ret == JNI_EDETACHED)
    {
        if (0 != __java_vm->AttachCurrentThread(&env, NULL)) {
            return NULL;
        }
        *attached = true;
        return env;
    }

    if (ret != JNI_OK) {
        return NULL;
    }

    return env;
}

static void __releaseEnv(bool attached)
{
    if (attached)
        __java_vm->DetachCurrentThread();
}

#endif
