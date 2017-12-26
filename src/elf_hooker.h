#if !defined(__ELF_HOOKER_H__)
#define __ELF_HOOKER_H__


#include <map>
#include <string>

#include "elf_module.h"

typedef void * (*fn_soinfo_map_find)(void * map, uintptr_t * handle);
typedef void * (*fn_dlopen_ext)(const char * soname, int flags, void * extinfo, void * caller_addr);

class elf_hooker {

public:
    elf_hooker();
    ~elf_hooker();

    bool load();
    
    void dump_module_list();
    bool get_module_by_name(const char * filename, elf_module & module);
    void * get_dlopen_ext_function() {return reinterpret_cast<void *>(m_origin_dlopen_ext);}


    elf_module* create_module(const char* soname);

    static uint32_t get_sdk_version();
    static void* base_addr_from_soinfo(void* soinfo_addr);
    
    void* find_loaded_soinfo(const char* soname);
    /* *
        prehook_cb invoked before really hook,
        if prehook_cb NOT set or return true, this module will be hooked,
        if prehook_cb set and return false, this module will NOT be hooked,
    */
    inline void set_prehook_cb(bool (*pfn)(const char*, const char*)) { this->m_prehook_cb = pfn; }
    inline bool hook(elf_module* module, const char *func_name, void *pfn_new, void **ppfn_old)
    {
         return module->hook(func_name, pfn_new, ppfn_old);
    }

    void hook_all_modules(const char* func_name, void* pfn_new, void** ppfn_old);
    void dump_proc_maps();

    bool find_function_addr(const char * module_name, const char * sym_name, uintptr_t & func_addr);
protected:

    void phrase_proc_maps();
    bool load_soinfo_list();
    void load_soinfo_handle_map(uintptr_t bias_addr);

    bool phrase_proc_base_addr(char* addr, void** pbase_addr, void** pend_addr);
    bool phrase_dev_num(char* devno, int *pmajor, int *pminor);
    bool phrase_proc_maps_line(char* line, char** paddr, char** pflags, char** pdev, char** pfilename);
    bool check_flags_and_devno(char* flags, char* dev);
    
protected:
     
    fn_dlopen_ext           m_origin_dlopen_ext;
    fn_soinfo_map_find      m_origin_soinfo_map_find;
    void                    *m_soinfo_handles_map;
    void                    *m_soinfo_list;

    std::map<std::string, elf_module> m_modules;
    bool (*m_prehook_cb)(const char* module_name, const char* func_name);
};

#endif
