
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <signal.h>
#include <dlfcn.h>
#include <execinfo.h>

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
    if (strncmp(module_name, "[vdso]", 6) == 0) {
        return false;
    }
    return true;
}


static struct sigaction __origin_sa[NSIG];

static void __segv_signal_handler(int sig, siginfo_t * info, void * content) {
    if (sig == SIGSEGV) {
        log_error(">>>>>> SIGSEGV <<<<<<");
        return
    } else if (sig == SIGSYS) {
        log_error(">>>>>> SIGSYS <<<<<<");
        return
    }
}

void __segv_signal_setup() {
    struct sigaction sa;
    memset(&__origin_sa, 0, sizeof(struct sigaction) * NSIG);
    memset(&sa, 0, sizeof(struct sigaction));

    sa.sa_handler = __segv_signal_handler;
    sa.sa_flags = SA_RESETHAND;
    sigaction(SIGSEGV, &sa, &__origin_sa[SIGSEGV]);
    sigaction(SIGSYS, &sa, &__origin_sa[SIGSYS]);
    return;
}

void __segv_signal_dispose() {
    sigaction(SIGSEGV, &__origin_sa[SIGSEGV], NULL);
    sigaction(SIGSYS, &__origin_sa[SIGSYS], NULL);
    return;
}

int main(int argc, char* argv[]) {
    char ch = 0;
    elf_hooker hooker;

//    __segv_signal_setup();

    void* h = dlopen("libart.so", RTLD_LAZY);
    void* f = dlsym(h,"artAllocObjectFromCodeResolvedRegion");
    log_info("artAllocObjectFromCodeResolvedRegion : %p\n", f);

    hooker.set_prehook_cb(__prehook);
    hooker.load();
    hooker.dump_soinfo_list();

    struct elf_rebinds rebinds[4] = {
        {"dlopen",            (void *)__nativehook_impl_dlopen,             (void **)&__old_impl_dlopen},
        {"connect",           (void *)__nativehook_impl_connect,            (void **)&__old_impl_connect},
        {"android_dlopen_ext", (void*)__nativehook_impl_android_dlopen_ext, (void**)&__old_impl_android_dlopen_ext},
        {NULL, NULL, NULL},
    };
    hooker.hook_all_modules(rebinds);

    log_info("old dlopen:             %p\n", __old_impl_dlopen);
    log_info("old connect:            %p\n", __old_impl_connect);
    log_info("old android_dlopen_ext: %p\n", __old_impl_android_dlopen_ext);

    uintptr_t origin_dlopen = static_cast<uintptr_t>(NULL);
#if __LP64__
    const char * ldfile = "/system/lib64/libdl.so";
#else
    const char * ldfile = "/system/lib/libdl.so";
#endif
    hooker.find_function_addr(ldfile, "dlopen", origin_dlopen);
    fprintf(stderr ,"origin_dlopen: %p\n", (void*)origin_dlopen);

    void* caller_addr = __builtin_return_address(0);

    void* h_libc = hooker.dlopen_ext("libc.so", RTLD_LAZY, NULL, caller_addr);
    void* f_connect = dlsym(h_libc,"connect");
    log_info("libc handle : %p\n", f_connect);

    do {
        ch = getc(stdin);
    } while(ch != 'q');

//    __segv_signal_dispose();

    return 0;
}

