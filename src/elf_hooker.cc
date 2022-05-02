
#include <unistd.h>
#include <errno.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <libgen.h>

#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/system_properties.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <dlfcn.h>

#include "elf_hooker.h"
#include "elf_common.h"
#include "elf_file.h"
#include "elf_soinfo.h"
#include "elf_log.h"

elf_hooker::elf_hooker() {

    this->m_modules.clear();
    this->m_is_loaded               = false;
    this->m_is_use_solist           = false;
    this->m_prehook_cb              = NULL;
    this->m_origin_dlopen           = (fn_dlopen)dlsym(NULL, "dlopen");
    this->m_origin_dlopen_ext       = NULL;
    this->m_origin_soinfo_map_find  = NULL;
    this->m_dl_mutex_lock           = NULL;
    this->m_dl_mutex_unlock         = NULL;
    this->m_soinfo_handles_map      = NULL;
    this->m_dl_mutex                = NULL;
}

elf_hooker::~elf_hooker() {
    this->m_modules.clear();
    this->m_prehook_cb              = NULL;
    this->m_origin_dlopen_ext       = NULL;
    this->m_origin_soinfo_map_find  = NULL;
    this->m_soinfo_handles_map      = NULL;
    this->m_dl_mutex                = NULL;
    this->m_dl_mutex_lock           = NULL;
    this->m_dl_mutex_unlock         = NULL;
}

bool elf_hooker::phrase_proc_base_addr(char* addr, void** pbase_addr, void** pend_addr) {
    char* split = strchr(addr, '-');
    if (split != NULL) {
        if (pbase_addr != NULL) {
            *pbase_addr = (void *) strtoul(addr, NULL, 16);
        }
        if (pend_addr != NULL) {
            *pend_addr = (void *) strtoul(split + 1, NULL, 16);
        }
        return true;
    }
    return false;
}

bool elf_hooker::phrase_dev_num(char* devno, int *pmajor, int *pminor) {
    *pmajor = 0;
    *pminor = 0;
    if (devno != NULL) {
        char* colon_pos = strchr(devno, ':');
        if (colon_pos != NULL) {
            *pmajor = strtoul(devno, NULL, 16);
            *pminor = strtoul(colon_pos + 1, NULL, 16);
            return true;
        }
    }
    return false;
}

bool elf_hooker::build_all_modules() {
    if (m_modules.empty()) {
        phrase_proc_maps(NULL, this->m_modules, true);
    }
    return !m_modules.empty();
}
bool elf_hooker::phrase_proc_maps_line(char* line, char** paddr, char** pflags, char** pdev, char** pfilename) {
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

bool elf_hooker::check_flags_and_devno(char* flags, char* dev) {

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

size_t elf_hooker::phrase_proc_maps(const char * so_name, std::map<std::string, elf_module> & modules, bool lock) {
    modules.clear();
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
                        if (lock && this->get_sdk_version() < 24) {
                            /* * * * * * * * * * *
                                android 7 以后版本，同一个动态库，被属于不同android_namespce的caller加载时，会创建多个soinfo对象!
                                
                            * */
                            void * handle = this->dlopen(filename, RTLD_LAZY);
                        }
                        elf_module module(reinterpret_cast<ElfW(Addr)>(base_addr), module_name.c_str());
                        modules.insert(std::pair<std::string, elf_module>(module_name, module));
                        if (so_name != NULL) {
                            break;
                        }
                    }
                }
            }
        }
        fclose(fd);
    }
    return modules.size();
}

void elf_hooker::dump_module_list() {
    for (std::map<std::string, elf_module>::iterator itor = m_modules.begin();
                    itor != m_modules.end();
                    itor++ ) {
        log_info("BaseAddr: %p ModuleName: %s\n", 
            reinterpret_cast<void *>(itor->second.get_base_addr()),
            itor->second.get_module_name());
    }
}
void elf_hooker::dump_soinfo_list() {
    if (this->m_is_use_solist) {
        this->dl_mutex_lock();
        struct soinfo * soinfo = reinterpret_cast<struct soinfo *>(m_soinfo_list);
        while(soinfo) {
            const char * realpath = get_realpath_from_soinfo(soinfo);
            realpath = (realpath == NULL) ? "None" : realpath;
            log_info("BaseAddr: %p ModuleName: %s\n", 
                reinterpret_cast<void *>(soinfo->base),
                realpath);
            soinfo = reinterpret_cast<struct soinfo *>(soinfo->next);
        } // while
        this->dl_mutex_unlock();
    }
    return;
}

bool elf_hooker::new_module(const char * filename, elf_module & module) {
    bool found = false;
    if (this->m_is_use_solist && this->m_soinfo_list) {
        this->dl_mutex_lock();
        struct soinfo * ss = reinterpret_cast<struct soinfo *>(m_soinfo_list);
        while(ss) {
            const char * realpath = get_realpath_from_soinfo(ss);
            if (ss != NULL) {
                void * base_addr = base_addr_from_soinfo(ss);
                if (base_addr != NULL && strstr(realpath, filename)) {
//                    log_dbg("new_module found: %s, base: %p", realpath, base_addr);
                    module.set_module_name(realpath);
                    module.set_base_addr((ElfW(Addr))base_addr);
                    found = true;
                    break;
                }
            }
            ss = reinterpret_cast<struct soinfo *>(ss->next);
        } // while
        this->dl_mutex_unlock();
    } else {
        std::string module_name = filename;
        std::map<std::string, elf_module>::iterator itor = m_modules.find(module_name);
        if (itor != m_modules.end()) {
            module = itor->second;
            found = true;
        }
    }
    return found;
}

void elf_hooker::hook_all_modules(struct elf_rebinds * rebinds) {
    if (this->m_is_use_solist && this->m_soinfo_list) {
        this->dl_mutex_lock();
        struct soinfo * ss = reinterpret_cast<struct soinfo *>(m_soinfo_list);
        while(ss) {
            const char * realpath = get_realpath_from_soinfo(ss);
            if (ss != NULL) {
                void * base_addr = base_addr_from_soinfo(ss);
                if (base_addr != NULL) {
                    if (!this->m_prehook_cb || this->m_prehook_cb(realpath)) {
                        log_info("Hook module(%s), base(%p)", realpath,  base_addr);
                        elf_module module(reinterpret_cast<ElfW(Addr)>(base_addr), realpath);
                        for (int i = 0; rebinds[i].func_name != NULL; i++) {
                            this->hook(&module, rebinds[i].func_name, rebinds[i].pfn_new, rebinds[i].ppfn_old);
                        }
                    }
                }
            }
            ss = reinterpret_cast<struct soinfo *>(ss->next);
        } // while
        this->dl_mutex_unlock();
    } else {
        // for android 6 below
        for (std::map<std::string, elf_module>::iterator itor = m_modules.begin();
                        itor != m_modules.end();
                        itor++ ) {
            elf_module module = itor->second;
            if (!this->m_prehook_cb || this->m_prehook_cb(module.get_module_name())) {
                log_info("Hook Module(%s), base(%p)\n", module.get_module_name(), (void*)module.get_base_addr());
                for (int i = 0; rebinds[i].func_name != NULL; i++) {
                    this->hook(&module, rebinds[i].func_name, rebinds[i].pfn_new, rebinds[i].ppfn_old);
                }
            } 
        }
    }
    return;
}

void elf_hooker::dump_proc_maps() {
    FILE* fd = fopen("/proc/self/maps", "r");
    if (fd != NULL) {
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

void * elf_hooker::dlopen_ext(const char * soname, int flags, void * extinfo, void * caller_addr) {
    if (this->m_origin_dlopen_ext) {
		return m_origin_dlopen_ext(soname, flags, extinfo, caller_addr);
    }
    return NULL;
}

uint32_t elf_hooker::get_sdk_version() {
    char sdk[32] = {0};
    __system_property_get("ro.build.version.sdk", sdk);
    return atoi(sdk);
}

void * elf_hooker::base_addr_from_soinfo(void * soinfo_addr) {
    struct soinfo * soinfo = reinterpret_cast<struct soinfo *>(soinfo_addr);
    if (soinfo != NULL) {
        return reinterpret_cast<void *>(soinfo->base);
    }
    return NULL;
}

struct soinfo * elf_hooker::find_loaded_soinfo(const char* soname) {
    struct soinfo * ss = NULL;
    if (m_soinfo_list) {
        this->dl_mutex_lock();
        struct soinfo * soinfo = reinterpret_cast<struct soinfo *>(m_soinfo_list);
        while(soinfo) {
            const char * realpath = get_realpath_from_soinfo(soinfo);
            if (strstr((char*)realpath, soname)) {
                ss = soinfo;
                break;
            } // strstr
            soinfo = reinterpret_cast<struct soinfo *>(soinfo->next);
        } // while
        this->dl_mutex_unlock();
    }
    return ss;
}

struct soinfo * elf_hooker::soinfo_from_handle(void * handle) {
    void * soinfo = NULL;
    if ((reinterpret_cast<uintptr_t>(handle) & 1) == 0) {
        return reinterpret_cast<struct soinfo *>(handle);
    }
    if (this->m_soinfo_handles_map && this->m_origin_soinfo_map_find) {
        void * itor = this->m_origin_soinfo_map_find(this->m_soinfo_handles_map, reinterpret_cast<uintptr_t*>(&handle));
        if (itor != NULL) { // itor != g_soinfo_handles_map.end()
#if defined(__LP64__)
            #error "arm64 unsupport!"
#else
            soinfo = reinterpret_cast<void *>(*(uint32_t *)((uintptr_t)itor + 0x0c));
#endif
            log_dbg("soinfo_from_handle()-> handle(%p), soinfo:(%p)\n", handle, soinfo);
        }
    }
    return reinterpret_cast<struct soinfo *>(soinfo);
}

bool elf_hooker::load() {
    if (this->m_is_loaded) {
        return this->m_is_loaded;
    }
    int sdk_version = get_sdk_version();
    if (get_sdk_version() >= 23) { 
        // android [6, 7, 8]
        uintptr_t base_addr = static_cast<uintptr_t>(NULL);
        uintptr_t bias_addr = static_cast<uintptr_t>(NULL);
        if (this->phrase_proc_maps("/system/bin/linker", m_modules, false) > 0) {
            std::map<std::string, elf_module>::iterator itor = m_modules.find("/system/bin/linker");
            if (itor != m_modules.end()) {
                elf_module module = itor->second;
                if (module.load()) {
                    bias_addr = reinterpret_cast<uintptr_t>(module.get_bias_addr());
                }
            }
        }
        log_info("modules->size() = %d\n", m_modules.size());
        log_info("bias_addr(%p)\n", reinterpret_cast<void *>(bias_addr));
        if (bias_addr != static_cast<uintptr_t>(NULL)) {
            elf_file sfile;
            if (!sfile.load("/system/bin/linker")) {
                log_error("read /system/bin/linker fail\n");
                goto fail;
            }
#if defined(__LP64__)
            #error "arm64 unsupport!"
#else
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
           if (soinfo_handles_map_offset) {
                this->m_soinfo_handles_map = reinterpret_cast<void *>(bias_addr + soinfo_handles_map_offset);
                log_dbg("soinfo_handler_map_offset:(%p), soinfo_handler_map_size(%d), m_soinfo_handles_map(%p)\n", 
                    reinterpret_cast<void *>(soinfo_handles_map_offset),
                    soinfo_handles_map_size,
                    reinterpret_cast<void *>(this->m_soinfo_handles_map));
            }

            uintptr_t soinfo_map_find_offset = static_cast<uintptr_t>(NULL);
            if (!sfile.find_function("__dl__ZNSt3__112__hash_tableINS_17__hash_value_typeIjP6soinfoEENS_22__unordered_map_hasherIjS4_NS_4hashIjEELb1EEENS_21__unordered_map_equalIjS4_NS_8equal_toIjEELb1EEENS_9allocatorIS4_EEE4findIjEENS_15__hash_iteratorIPNS_11__hash_nodeIS4_PvEEEERKT_",
                    soinfo_map_find_offset)) {
                if (!sfile.find_function("__dl__ZNSt3__112__hash_tableINS_17__hash_value_typeIjNS_4pairI9MapStringS3_EEEENS_22__unordered_map_hasherIjS5_NS_4hashIjEELb1EEENS_21__unordered_map_equalIjS5_NS_8equal_toIjEELb1EEENS_9allocatorIS5_EEE4findIjEENS_15__hash_iteratorIPNS_11__hash_nodeIS5_PvEEEERKT_", 
                        soinfo_map_find_offset)) {
                    log_warn("find soinfo_map's find function offset fail\n");
                }
            }
            
            if (soinfo_map_find_offset) {
                this->m_origin_soinfo_map_find = reinterpret_cast<fn_soinfo_map_find>(bias_addr + soinfo_map_find_offset);
                log_dbg("soinfo_map_find_offset:(%p), m_origin_soinfo_map_find(%p)\n", 
                    reinterpret_cast<void *>(soinfo_map_find_offset),
                    reinterpret_cast<void *>(this->m_origin_soinfo_map_find));
            }

            uintptr_t dlopen_ext_offset = static_cast<uintptr_t>(NULL); 
             if (!sfile.find_function("__dl__ZL10dlopen_extPKciPK17android_dlextinfoPKv", dlopen_ext_offset)) {
                 if (!sfile.find_function("__dl__ZL10dlopen_extPKciPK17android_dlextinfoPv", dlopen_ext_offset)) {
                     log_warn("find dlopen_ext function offset fail\n");
                 }
             }
             if (dlopen_ext_offset) {
                 this->m_origin_dlopen_ext = reinterpret_cast<fn_dlopen_ext>(bias_addr + dlopen_ext_offset);
                 log_info("dlopen_ext_offset:(%p), m_origin_dlopen_ext:(%p)\n", 
                    reinterpret_cast<void *>(dlopen_ext_offset),
                    reinterpret_cast<void *>(this->m_origin_dlopen_ext));
             }

            uintptr_t solist_offset = static_cast<uintptr_t>(NULL);
            size_t solist_size = 0; 
            if (!sfile.find_variable("__dl__ZL6solist", solist_offset, solist_size)) {
                log_warn("find solist variable offset fail!\n");
            }
            if (solist_offset) {
                uint32_t * addr  = *reinterpret_cast<uint32_t**>(bias_addr + solist_offset);
                this->m_soinfo_list = reinterpret_cast<void*>(addr);
                log_info("solist_offset:(%p), m_soinfo_list:(%p)\n", 
                    reinterpret_cast<void *>(solist_offset),
                    reinterpret_cast<void *>(this->m_soinfo_list));
            }

            uintptr_t dl_mutex_offset = static_cast<uintptr_t>(NULL);
            size_t dl_mutex_size = 0;
            if (!sfile.find_variable("__dl__ZL10g_dl_mutex", dl_mutex_offset, dl_mutex_size)) {
                log_warn("find g_dl_mutex variable offset fail!\n");
            }
            if (dl_mutex_offset) {
                uint32_t * addr  = reinterpret_cast<uint32_t*>(bias_addr + dl_mutex_offset);
                this->m_dl_mutex = reinterpret_cast<void*>(addr);
                log_info("dl_mutex_offset:(%p), m_dl_mutex:(%p)\n", 
                    reinterpret_cast<void *>(dl_mutex_offset),
                    reinterpret_cast<void *>(this->m_dl_mutex));
            }

            uintptr_t dl_mutex_lock_offset = static_cast<uintptr_t>(NULL);
            if (!sfile.find_function("__dl_pthread_mutex_lock", dl_mutex_lock_offset)) {
                log_warn("find __dl_pthread_mutex_lock funciton offset fail!\n");
            }

            if (dl_mutex_lock_offset) {
                this->m_dl_mutex_lock = reinterpret_cast<fn_dl_mutex_lock>(bias_addr + dl_mutex_lock_offset);
                log_info("dl_mutex_lock_offset:(%p), m_dl_mutex_lock:(%p)\n", 
                    reinterpret_cast<void *>(dl_mutex_lock_offset),
                    reinterpret_cast<void *>(this->m_dl_mutex_lock));
            }

            uintptr_t dl_mutex_unlock_offset = static_cast<uintptr_t>(NULL);
            if (!sfile.find_function("__dl_pthread_mutex_unlock", dl_mutex_unlock_offset)) {
                log_warn("find __dl_pthread_mutex_lock funciton offset fail!\n");
            }

            if (dl_mutex_unlock_offset) {
                this->m_dl_mutex_unlock = reinterpret_cast<fn_dl_mutex_lock>(bias_addr + dl_mutex_unlock_offset);
                log_info("dl_mutex_unlock_offset:(%p)， m_dl_mutex_unlock:(%p)\n", 
                    reinterpret_cast<void *>(dl_mutex_unlock_offset), 
                    reinterpret_cast<void *
                    >(this->m_dl_mutex_unlock));
            }
            if (this->m_soinfo_list && this->m_dl_mutex && this->m_dl_mutex_lock && this->m_dl_mutex_unlock) {
                this->m_is_use_solist = true;
            }
        } /* bias_addr != NULL */
        if (this->m_is_use_solist) {
            this->m_is_loaded = true;
            log_info("sdk version (%d), loaded(%d), modules->size() %d\n", sdk_version, this->m_is_loaded, m_modules.size());
            return this->m_is_loaded;
        }
#endif
    } /* get_sdk_version() >= 23 */

fail:
    this->m_is_loaded = this->build_all_modules();
    log_info("sdk version (%d), loaded(%d), modules->size() %d\n", sdk_version, this->m_is_loaded, m_modules.size());
    this->m_is_use_solist = false;
    return this->m_is_loaded;
}

bool elf_hooker::find_function_addr(const char * module_name, const char * sym_name, uintptr_t & func_addr) {
    elf_module module;
    func_addr = (uintptr_t)NULL;
    if(!this->new_module(module_name, module)) {
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

const char * elf_hooker::get_realpath_from_soinfo(struct soinfo * soinfo) {
    const char * soname = soinfo->old_name;
    if (soinfo) {
        const char * realpath = NULL;
        uint32_t * p = reinterpret_cast<uint32_t *>((uintptr_t)soinfo + 0x17c);
        uint8_t b = *reinterpret_cast<uint8_t*>((uintptr_t)soinfo + 0x17c);
        if (b & 0x01) {
            realpath = *reinterpret_cast<const char **>((uintptr_t)soinfo + 0x184);
        } else {
            realpath = reinterpret_cast<const char *>((uintptr_t)soinfo + 0x17d);
        }
        if (realpath) {
            soname = realpath;
        }
        if (!soname) {
            soname = (const char *)soinfo->old_name;
        }
    }
    return soname;
}

