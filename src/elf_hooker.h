#if !defined(__ELF_HOOKER_H__)
#define __ELF_HOOKER_H__


#include <map>
#include <string>

#include "elf_module.h"

class elf_hooker {

public:
    elf_hooker();
    ~elf_hooker();


    bool phrase_proc_maps();
    void dump_module_list();
    elf_module* create_module(const char* soname);

    static uint32_t get_sdk_version();
    void* lookup_loaded_dylib(const char* soname);
    void* base_addr_from_soinfo(void* soinfo_addr);
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

protected:

    bool phrase_proc_base_addr(char* addr, void** pbase_addr, void** pend_addr);
    bool phrase_dev_num(char* devno, int *pmajor, int *pminor);
    bool phrase_proc_maps_line(char* line, char** paddr, char** pflags, char** pdev, char** pfilename);
    bool check_flags_and_devno(char* flags, char* dev);
    
protected:

    void * m_soinfo_list;
    std::map<std::string, elf_module> m_modules;
    bool (*m_prehook_cb)(const char* module_name, const char* func_name);
};

#define SOINFO_NAME_LEN (128)

struct soinfo_header {
    char                    old_name[SOINFO_NAME_LEN];
    const ElfW(Phdr)        *phdr;
    size_t                  phnum;
    ElfW(Addr)              unused0;
    ElfW(Addr)              base;
    size_t                  size;
    uint32_t                unused1;   // DO NOT USE, maintained for compatibility.
    ElfW(Dyn)               *dynamic;
    uint32_t                unused2;   // DO NOT USE, maintained for compatibility
    uint32_t                unused3;   // DO NOT USE, maintained for compatibility
    struct soinfo_header    *next;
    uint32_t                flags;
    const char              *strtab;
    ElfW(Sym)               *symtab;
    size_t                  nbucket;
    size_t                  nchain;
    uint32_t                *bucket;
    uint32_t                *chain;
};

#endif
