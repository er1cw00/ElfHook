#if !defined(__ELF_HOOKER_H__)
#define __ELF_HOOKER_H__


#include <map>
#include <string>

#include "elf_module.h"

struct elf_rebinds {
    const char * func_name;
    void * pfn_new;
    void ** ppfn_old;
};

class elf_hooker {

public:

typedef void * (*fn_dlopen)(const void * soname, int flags);
typedef void * (*fn_soinfo_map_find)(void * map, uintptr_t * handle);
typedef void * (*fn_dlopen_ext)(const char * soname, int flags, void * extinfo, void * caller_addr);
typedef void (*fn_dl_mutex_lock)(void * mutex);
typedef void (*fn_dl_mutex_unlock)(void * mutex);

    elf_hooker();
    ~elf_hooker();

    static uint32_t get_sdk_version();
    static void* base_addr_from_soinfo(void* soinfo_addr);
    bool load();
    bool build_all_modules();
    bool find_function_addr(const char * module_name, const char * sym_name, uintptr_t & func_addr);

    bool new_module(const char * filename, elf_module & module);


    struct soinfo * find_loaded_soinfo(const char* soname);
    struct soinfo * soinfo_from_handle(void * handle);
    const char * get_realpath_from_soinfo(struct soinfo * soinfo);
    
    /* *
        prehook_cb invoked before really hook,
        if prehook_cb NOT set or return true, this module will be hooked,
        if prehook_cb set and return false, this module will NOT be hooked,
    */
    inline void set_prehook_cb(bool (*pfn)(const char *)) { this->m_prehook_cb = pfn; }
    inline bool hook(elf_module* module, const char *func_name, void *pfn_new, void **ppfn_old) {
         return module->hook(func_name, pfn_new, ppfn_old);
    }

    void hook_all_modules(struct elf_rebinds * rebinds);
    void dump_soinfo_list();
    void dump_module_list();
    void dump_proc_maps();

    void * dlopen(const char * soname, int flags);
    void * dlopen_ext(const char * soname, int flags, void * extinfo, void * caller_addr);

    void dl_mutex_lock() {
        if (this->m_is_use_solist) {
            this->m_dl_mutex_lock(this->m_dl_mutex);
        }
    }

    void dl_mutex_unlock() {
        if (this->m_is_use_solist) {
            this->m_dl_mutex_unlock(this->m_dl_mutex);
        }
    }

protected:

    int phrase_proc_maps(const char* so_name, std::map<std::string, elf_module> & modules, bool lock);
    bool phrase_proc_base_addr(char* addr, void** pbase_addr, void** pend_addr);
    bool phrase_dev_num(char* devno, int *pmajor, int *pminor);

protected:

    bool                    m_is_loaded;
    bool                    m_is_use_solist;
    fn_dlopen               m_origin_dlopen;
    fn_dlopen_ext           m_origin_dlopen_ext;
    fn_soinfo_map_find      m_origin_soinfo_map_find;
    fn_dl_mutex_lock        m_dl_mutex_lock;
    fn_dl_mutex_unlock      m_dl_mutex_unlock;
    void                    *m_dl_mutex;
    void                    *m_soinfo_handles_map;
    void                    *m_soinfo_list;
    std::map<std::string, elf_module> m_modules;
    bool (*m_prehook_cb)(const char* module_name);

};

#endif
