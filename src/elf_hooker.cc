
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
    this->m_prehook_cb = NULL;
}

elf_hooker::~elf_hooker()
{
    m_modules.clear();
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
    if (flags[0] != 'r' || flags[3] == 's') {
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

void elf_hooker::phrase_proc_maps()
{

    FILE* fd = fopen("/proc/self/maps", "r");
    if (fd != NULL)
    {
        char buff[2048+1];
        while(fgets(buff, 2048, fd) != NULL)
        {
            char *addr = NULL;
            char *flags = NULL;
            char *dev = NULL;
            char *filename = NULL;
            if (phrase_proc_maps_line(buff, &addr, &flags, &dev, &filename))
            {
                if (!check_flags_and_devno(flags, dev))
                {
                    continue;
                }
                std::string module_name = filename;
                std::map<std::string, elf_module>::iterator itor = m_modules.find(module_name);
                if (itor == m_modules.end())
                {
                    void* base_addr = NULL;
                    void* end_addr = NULL;
                    if (phrase_proc_base_addr(addr, &base_addr, &end_addr) && elf_module::is_elf_module(base_addr))
                    {
                        log_dbg("module_name: %s\n", module_name.c_str());
                        elf_module module(reinterpret_cast<ElfW(Addr)>(base_addr), module_name.c_str());
                        m_modules.insert(std::pair<std::string, elf_module>(module_name, module));
                    }
                }
            }
        }
        fclose(fd);
    }
}

bool elf_hooker::get_module_by_name(const char * filename, elf_module & module) {
    std::string module_name = filename;
    std::map<std::string, elf_module>::iterator itor = m_modules.find(module_name);
    if (itor != m_modules.end()) {
        module = itor->second;
        return true;
    }
    return false;
}

elf_module* elf_hooker::create_module(const char* soname)
{   
    FILE* fd = fopen("/proc/self/maps", "r");
    if (fd != NULL)
    {
        char buff[2048+1];
        while(fgets(buff, 2048, fd) != NULL)
        {
            char *addr = NULL;
            char *flags = NULL;
            char *dev = NULL;
            char *filename = NULL;
            if (phrase_proc_maps_line(buff, &addr, &flags, &dev, &filename))
            {
                if (strstr(filename, soname) != NULL) {

                    if (!check_flags_and_devno(flags, dev)) {
                        continue;
                    }
                    void* base_addr = NULL;
                    void* end_addr = NULL;
                    if (phrase_proc_base_addr(addr, &base_addr, &end_addr) && elf_module::is_elf_module(base_addr))
                    {
                        elf_module* module = new elf_module(reinterpret_cast<ElfW(Addr)>(base_addr), filename);
                        fclose(fd);
                        return module;
                    }
                } // strstr
            } //phrase_proc_maps_lines
        }// fgets
        fclose(fd);
    }
    return NULL;
}

void elf_hooker::dump_module_list()
{
    for (std::map<std::string, elf_module>::iterator itor = m_modules.begin();
                    itor != m_modules.end();
                    itor++ )
    {
        log_info("BaseAddr: %lx ModuleName: %s\n", (unsigned long)itor->second.get_base_addr(), itor->second.get_module_name());
    }
}

void elf_hooker::hook_all_modules(const char* func_name, void* pfn_new, void** ppfn_old)
{
    for (std::map<std::string, elf_module>::iterator itor = m_modules.begin();
                    itor != m_modules.end();
                    itor++ )
    {
        if (this->m_prehook_cb && !this->m_prehook_cb(itor->second.get_module_name(), func_name))
        {
            continue;
        }
        log_info("Hook Module : %s, Function: %s\n", itor->second.get_module_name(), func_name);
        this->hook(&itor->second, func_name, pfn_new, ppfn_old);
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

uint32_t elf_hooker::get_sdk_version() 
{
    char sdk[32] = {0};
    __system_property_get("ro.build.version.sdk", sdk);
    log_dbg("get_sdk_version() -> sdk version: %s\n", sdk);
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

void * elf_hooker::lookup_loaded_dylib(const char* soname) {
    if (m_soinfo_list) {
        struct soinfo * soinfo = reinterpret_cast<struct soinfo *>(m_soinfo_list);
        while(soinfo) {
            if (strstr((char*)soinfo->old_name, soname)) {
                return reinterpret_cast<void *>(soinfo);
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
    return;
} 

bool elf_hooker::load_soinfo_list() {
    if (this->m_soinfo_list == NULL) {
        char * ld_soname = "libdl.so";
        int sdk_version = elf_hooker::get_sdk_version();
        if (sdk_version >= 26) {
            ld_soname = "ld-android.so";
        }
        void * libdl_handle = dlopen(ld_soname, RTLD_GLOBAL);
//        log_dbg("m_soinfo_list(%p), ld_soname(%s)\n", libdl_handle, ld_soname);
        if ((uintptr_t)libdl_handle & 0x01 == 0) {
            this->m_soinfo_list = libdl_handle;
        } else {
            if (this->m_soinfo_handles_map && this->m_origin_soinfo_map_find) {
//                log_dbg("map:(%p), find(%p)\n", (void*)this->m_soinfo_handles_map, (void*)this->m_origin_soinfo_map_find);
                void * itor = this->m_origin_soinfo_map_find(this->m_soinfo_handles_map, reinterpret_cast<uintptr_t*>(&libdl_handle));
                if (itor != NULL) { // itor != g_soinfo_handles_map.end()
#if defined(__LP64__)
                    //TODO 
                    //this->m_soinfo_list = reinterpret_cast<soinfo *>(*(uint64_t *)((uintptr_t)itor + 0x0c));
#else
                    this->m_soinfo_list = reinterpret_cast<soinfo *>(*(uint32_t *)((uintptr_t)itor + 0x0c));
#endif
                    log_dbg("m_soinfo_list:(%p)\n", (void*)this->m_soinfo_list);
                }
            }
        }
        if (0 && this->m_soinfo_list) {
            dump_hex((uint8_t *)m_soinfo_list, 256);
        }
    }
    return this->m_soinfo_list != NULL;
}

bool elf_hooker::load() {
    void * base_addr = NULL;
    void * bias_addr = NULL;
    this->phrase_proc_maps();
    dump_module_list();
    std::map<std::string, elf_module>::iterator itor = this->m_modules.find("/system/bin/linker");
    if (itor != this->m_modules.end()) {
        elf_module module = itor->second;
        if (module.load()) {
            bias_addr = reinterpret_cast<void *>(module.get_bias_addr());
        }
    }
    log_dbg("bias_addr: %p\n", bias_addr);
    if (bias_addr) {
        this->load_soinfo_handle_map(reinterpret_cast<uintptr_t>(bias_addr));
        this->load_soinfo_list();
    }
}

bool elf_hooker::find_function_addr(const char * module_name, const char * sym_name, uintptr_t & func_addr) {
    elf_module module;
    if (!get_module_by_name(module_name, module)) {
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
    return true;
}


