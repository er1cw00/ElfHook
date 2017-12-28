
#include <unistd.h>
#include <errno.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/system_properties.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include "elf_hooker.h"
#include "elf_common.h"
#include "elf_file.h"
#include "elf_soinfo.h"

elf_hooker::elf_hooker()
{
    this->m_modules.clear();
    this->m_prehook_cb              = NULL;
    this->m_origin_dlopen           = (fn_dlopen)dlsym(NULL, "dlopen");
    this->m_origin_dlopen_ext       = NULL;
    this->m_origin_soinfo_map_find  = NULL;
    log_dbg("dlopen: %p\n", this->m_origin_dlopen);
}

elf_hooker::~elf_hooker()
{
    this->m_modules.clear();
    this->m_prehook_cb = NULL;
}

bool elf_hooker::phrase_proc_base_addr(char* addr, void** pbase_addr, void** pend_addr)
{
    char* split = strchr(addr, '-');
    if (split != NULL) {
        if (pbase_addr != NULL)
        {
            *pbase_addr = (void *) strtoul(addr, NULL, 16);
        }
        if (pend_addr != NULL)
        {
            *pend_addr = (void *) strtoul(split + 1, NULL, 16);
        }
        return true;
    }
    return false;
}

bool elf_hooker::phrase_dev_num(char* devno, int *pmajor, int *pminor)
{
    *pmajor = 0;
    *pminor = 0;
    if (devno != NULL)
    {
        char* colon_pos = strchr(devno, ':');
        if (colon_pos != NULL)
        {
            *pmajor = strtoul(devno, NULL, 16);
            *pminor = strtoul(colon_pos + 1, NULL, 16);
            return true;
        }
    }
    return false;
}

bool elf_hooker::phrase_proc_maps_line(char* line, char** paddr, char** pflags, char** pdev, char** pfilename)
{
    const char *sep = "\t \r\n";
    char *buff = NULL;
    char *unused = NULL;
    *paddr = strtok_r(line, sep, &buff);
    *pflags = strtok_r(NULL, sep, &buff);
    unused =strtok_r(NULL, sep, &buff);  // offsets
    *pdev = strtok_r(NULL, sep, &buff);  // dev number.
    unused = strtok_r(NULL, sep, &buff);  // node
    *pfilename = strtok_r(NULL, sep, &buff); //module name
    return (*paddr != NULL && *pfilename != NULL && *pflags != NULL);
}

bool elf_hooker::check_flags_and_devno(char* flags, char* dev)
{
    if (!flags || flags[0] != 'r' || flags[3] == 's') {
        /*
            1. mem section cound NOT be read, without 'r' flag.
            2. read from base addr of /dev/mail module would crash.
               i dont know how to handle it, just skip it.

               1f5573000-1f58f7000 rw-s 1f5573000 00:0c 6287 /dev/mali0

        */
        return false;
    }
    int major = 0, minor = 0;
    if (!phrase_dev_num(dev, &major, &minor) || major == 0) {
        /*
            if dev major number equal to 0, mean the module must NOT be
            a shared or executable object loaded from disk.
            e.g:
            lookup symbol from [vdso] would crash.
            7f7b48a000-7f7b48c000 r-xp 00000000 00:00 0  [vdso]
        */
        return false;
    }
    return true;
}

size_t elf_hooker::phrase_proc_maps(const char* so_name, std::map<std::string, elf_module> & modules) {

    FILE* fd = fopen("/proc/self/maps", "r");
    if (fd != NULL) {
        char buff[2048+1];
        while(fgets(buff, 2048, fd) != NULL) {
            char *addr = NULL;
            char *flags = NULL;
            char *dev = NULL;
            char *filename = NULL;
            if (phrase_proc_maps_line(buff, &addr, &flags, &dev, &filename)) {
                if (!check_flags_and_devno(flags, dev)) {
                    continue;
                }

                if (so_name != NULL && strstr(filename, so_name) == NULL) {
                    continue;
                }
                std::string module_name = filename;
                std::map<std::string, elf_module>::iterator itor = modules.find(module_name);
                if (itor == modules.end()) {
                    void* base_addr = NULL;
                    void* end_addr = NULL;
                    if (phrase_proc_base_addr(addr, &base_addr, &end_addr) && elf_module::is_elf_module(base_addr)) {
                        log_dbg("module_name: %s\n", module_name.c_str());
                        elf_module module(reinterpret_cast<ElfW(Addr)>(base_addr), module_name.c_str());
                        modules.insert(std::pair<std::string, elf_module>(module_name, module));
                    }
                }
            }
        }
        fclose(fd);
    }
    return modules.size();
}

void elf_hooker::dump_soinfo_list()
{
    log_dbg("dump_soinfo_list()-> %p\n", this->m_soinfo_list);
    if (this->m_soinfo_list) {
        struct soinfo * soinfo = reinterpret_cast<struct soinfo *>(m_soinfo_list);
        while(soinfo) {
            log_info("BaseAddr: %lx ModuleName: %s\n", (unsigned long)soinfo->base, (char*)soinfo->old_name);
            soinfo = reinterpret_cast<struct soinfo *>(soinfo->next);
        }
    }
}

bool elf_hooker::new_module(const char* soname, elf_module & module)
{   
    struct soinfo * so = this->find_loaded_soinfo(soname);
    if (so && so->base && elf_module::is_elf_module((void *)so->base)) {
        module.set_base_addr(so->base);
        module.set_module_name(soname);
        return true;
    }
    std::map<std::string, elf_module> modules;
    if (this->phrase_proc_maps(soname, modules) > 0) {
        module = modules.begin()->second;
        return true;
    }
    return false;
}

void elf_hooker::hook_all_modules(const char* func_name, void* pfn_new, void** ppfn_old) {

    if (this->m_soinfo_list) {
        struct soinfo * soinfo = reinterpret_cast<struct soinfo *>(m_soinfo_list);
        while(soinfo) {
            if (this->m_prehook_cb && !this->m_prehook_cb(soinfo->old_name, func_name)) {
                continue;
            }
            if (soinfo->base && elf_module::is_elf_module((void *)soinfo->base)) {
                void * handle = this->dlopen(soinfo->old_name, RTLD_LAZY);
                elf_module module(soinfo->base, soinfo->old_name);
                log_info("Hook Module : %s, Function: %s\n", soinfo->old_name, func_name);
                this->hook(&module, func_name, pfn_new, ppfn_old);
                if (handle) {
                    ::dlclose(handle);
                }
            }
            soinfo = reinterpret_cast<struct soinfo *>(soinfo->next);
        }
    } else {
        log_dbg("hook_all_modules -> \n");
        std::map<std::string, elf_module> modules;
        if (this->phrase_proc_maps(NULL, modules)) {
            for (std::map<std::string, elf_module>::iterator itor = m_modules.begin();
                                                            itor != m_modules.end();
                                                            itor++ ) {
                if (this->m_prehook_cb && !this->m_prehook_cb(itor->second.get_module_name(), func_name)) {
                    continue;
                }
                log_info("Hook Module: %s, Function: %s\n", itor->second.get_module_name(), func_name);
                this->hook(&itor->second, func_name, pfn_new, ppfn_old);
            }
        }
    }

    return;
}

void elf_hooker::dump_proc_maps()
{
    FILE* fd = fopen("/proc/self/maps", "r");
    if (fd != NULL)
    {
        char buff[2048+1];
        while(fgets(buff, 2048, fd) != NULL)
        {
            log_info("%s\n", buff);
        }
        fclose(fd);
    }
    return;
}

void * elf_hooker::dlopen(const char * soname, int flags) {

    if (this->get_sdk_version() < 24) {
        if (this->m_origin_dlopen) {
            return this->m_origin_dlopen(soname, flags);
        }
        return ::dlopen(soname, flags);
    } else if (this->m_origin_dlopen_ext){
        struct soinfo * ss = find_loaded_soinfo("libc.so");
        if (ss && ss->base) {
            return this->m_origin_dlopen_ext(soname, flags, NULL, (void*)ss->base);
        }
    }
    return NULL;
}

uint32_t elf_hooker::get_sdk_version() 
{
    char sdk[32] = {0};
    __system_property_get("ro.build.version.sdk", sdk);
    return atoi(sdk);
}

void * elf_hooker::base_addr_from_soinfo(void * soinfo_addr)
{
    struct soinfo * soinfo = reinterpret_cast<struct soinfo *>(soinfo_addr);
    if (soinfo != NULL) {
        return reinterpret_cast<void *>(soinfo->base);
    }
    return NULL;
}

struct soinfo * elf_hooker::find_loaded_soinfo(const char* soname) {
    if (m_soinfo_list) {
        struct soinfo * soinfo = reinterpret_cast<struct soinfo *>(m_soinfo_list);
        while(soinfo) {
            if (strstr((char*)soinfo->old_name, soname)) {
                return soinfo;
            }
            soinfo = reinterpret_cast<struct soinfo *>(soinfo->next);
        }
    }
    return NULL;
}

void elf_hooker::load_soinfo_handle_map(uintptr_t bias_addr) {
    elf_file sfile;
    if (!sfile.load("/system/bin/linker")) {
        log_error("read /system/bin/linker fail\n");
        return;
    }
    uintptr_t soinfo_handles_map_offset = static_cast<uintptr_t>(NULL);
    size_t soinfo_handles_map_size = 0;

    if (!sfile.find_variable("__dl__ZL20g_soinfo_handles_map", 
            soinfo_handles_map_offset, 
            soinfo_handles_map_size)) {
        if (!sfile.find_variable("__dl_g_soinfo_handles_map", 
                soinfo_handles_map_offset, 
                soinfo_handles_map_size)) {
            log_warn("find g_soinfo_handles_map variable offset fail\n");
        }
    }
    log_dbg("soinfo_handler_map_offset:(%p), soinfo_handler_map_size(%d)\n", (void *)soinfo_handles_map_offset, soinfo_handles_map_size);
    if (soinfo_handles_map_offset) {
        this->m_soinfo_handles_map = reinterpret_cast<void *>(bias_addr + soinfo_handles_map_offset);
    }

    uintptr_t soinfo_map_find_offset = static_cast<uintptr_t>(NULL);
    if (!sfile.find_function("__dl__ZNSt3__112__hash_tableINS_17__hash_value_typeIjP6soinfoEENS_22__unordered_map_hasherIjS4_NS_4hashIjEELb1EEENS_21__unordered_map_equalIjS4_NS_8equal_toIjEELb1EEENS_9allocatorIS4_EEE4findIjEENS_15__hash_iteratorIPNS_11__hash_nodeIS4_PvEEEERKT_",
            soinfo_map_find_offset)) {
        if (!sfile.find_function("__dl__ZNSt3__112__hash_tableINS_17__hash_value_typeIjNS_4pairI9MapStringS3_EEEENS_22__unordered_map_hasherIjS5_NS_4hashIjEELb1EEENS_21__unordered_map_equalIjS5_NS_8equal_toIjEELb1EEENS_9allocatorIS5_EEE4findIjEENS_15__hash_iteratorIPNS_11__hash_nodeIS5_PvEEEERKT_", 
                soinfo_map_find_offset)) {
            log_warn("find soinfo_map's find function offset fail\n");
        }
    }
    log_dbg("soinfo_map_find_offset:(%p)\n", (void *)soinfo_map_find_offset);
    if (soinfo_map_find_offset) {
        this->m_origin_soinfo_map_find = reinterpret_cast<fn_soinfo_map_find>(bias_addr + soinfo_map_find_offset);
    }

    uintptr_t dlopen_ext_offset = static_cast<uintptr_t>(NULL); 
     if (!sfile.find_function("__dl__ZL10dlopen_extPKciPK17android_dlextinfoPKv", dlopen_ext_offset)) {
         if (!sfile.find_function("__dl__ZL10dlopen_extPKciPK17android_dlextinfoPv", dlopen_ext_offset)) {
             log_warn("find dlopen_ext function offset fail\n");
         }
     }
     log_dbg("dlopen_ext_offset:(%p)\n", (void *)dlopen_ext_offset);
     if (dlopen_ext_offset) {
         this->m_origin_dlopen_ext = reinterpret_cast<fn_dlopen_ext>(bias_addr + dlopen_ext_offset);
     }

    uintptr_t solist_offset = static_cast<uintptr_t>(NULL);
    size_t solist_size = 0;
    if (!sfile.find_variable("__dl__ZL6solist", solist_offset, solist_size)) {
        log_warn("find solist variable offset fail!\n");
    }
    log_dbg("solist_offset:(%p)\n", (void *)solist_offset);
    if (solist_offset) {
        uint32_t * addr  = *reinterpret_cast<uint32_t**>(bias_addr + solist_offset);
        this->m_soinfo_list = reinterpret_cast<void*>(addr);
    }

    return;
} 


struct soinfo * elf_hooker::soinfo_from_handle(void * handle) {
    struct soinfo * soinfo = NULL;
    if ((reinterpret_cast<uintptr_t>(handle) & 1) == 0) {
        return reinterpret_cast<struct soinfo *>(handle);
    }
    if (this->m_soinfo_handles_map && this->m_origin_soinfo_map_find) {
        void * itor = this->m_origin_soinfo_map_find(this->m_soinfo_handles_map, reinterpret_cast<uintptr_t*>(&handle));
        if (itor != NULL) { // itor != g_soinfo_handles_map.end()
#if defined(__LP64__)
            //TODO 
            //this->m_soinfo_list = reinterpret_cast<soinfo *>(*(uint64_t *)((uintptr_t)itor + 0x0c));
#else
            soinfo = reinterpret_cast<struct soinfo *>(*(uint32_t *)((uintptr_t)itor + 0x0c));
#endif
            log_dbg("soinfo_from_handle()-> handle(%p), soinfo:(%p)\n", handle, soinfo);
        }
    }
    return soinfo;
}

bool elf_hooker::load_soinfo_list() {
    if (this->m_soinfo_list == NULL) {
        char * ld_soname = "libdl.so";
        int sdk_version = elf_hooker::get_sdk_version();
        if (sdk_version >= 26) {
            ld_soname = "ld-android.so";
        }
        void * libdl_handle = NULL;
        if (this->m_origin_dlopen) {
            libdl_handle = m_origin_dlopen(ld_soname, RTLD_GLOBAL);
        } else {
            libdl_handle = ::dlopen(ld_soname, RTLD_GLOBAL);
        }
        log_dbg("libdl_handle(%p)\n", libdl_handle);
        this->m_soinfo_list = soinfo_from_handle(libdl_handle);
        log_dbg("m_soinfo_list:(%p)\n", (void*)this->m_soinfo_list);
    }
    return this->m_soinfo_list != NULL;
}

bool elf_hooker::load() {
    void * base_addr = NULL;
    void * bias_addr = NULL;
    elf_module module;
    if (!this->new_module("/system/bin/linker", module)) {
        return false;
    }

    if (module.load()) {
        bias_addr = reinterpret_cast<void *>(module.get_bias_addr());
    }

    log_dbg("bias_addr: %p\n", bias_addr);
    if (bias_addr) {
        this->load_soinfo_handle_map(reinterpret_cast<uintptr_t>(bias_addr));
        this->load_soinfo_list();
    }

	return true;
}

bool elf_hooker::find_function_addr(const char * module_name, const char * sym_name, uintptr_t & func_addr) {
    elf_module module;
    if (!this->new_module(module_name, module)) {
        log_error("module(%s) not found!\n", module_name);
        return false;
    }

    if (!module.load()) {
        log_error("load elf module(%s) fail\n", module_name);
        return false;
    }

    uintptr_t bias_addr = reinterpret_cast<uintptr_t>(module.get_bias_addr());
    if (bias_addr) {
        elf_file sfile;
        if (!sfile.load(module_name)) {
            log_error("read module (%s) fail\n", module_name);
            return false;
        }
        uintptr_t offset;
        if (!sfile.find_function(sym_name, offset)) {
            log_error("count not find sym (%s)\n", sym_name);
            return false;
        }
        if (offset) {
            func_addr = reinterpret_cast<uintptr_t>(bias_addr + offset);
            return true;
        }
    }
    return false;
}

