#if !defined(__ELF_FILE_H__)
#define __ELF_FILE_H__

#include <string>
#include "elf_common.h"

#include "elf_mapped.h"

class elf_file {

public:
    elf_file();
    ~elf_file();

    bool load(const char * filename);

    inline const char * get_soname() {return m_soname.c_str();}
    inline const int get_fd(){return m_fd;}
    inline const char * get_realpath() {return m_realpath.c_str();}

    ElfW(Sym) * find_symbol(const char * name, int type = -1);
    ElfW(Sym) * find_dynamic_symbol(const char * name, int type = -1);

    bool find_function(const char * name, uintptr_t & offset);
    bool find_variable(const char * name, uintptr_t & offset, size_t & size);

    void dump_elf_header(void);
    void dump_section_headers(void);
    void dump_program_headers(void);
    void dump_dynamics(void);
    void dump_symbols(void);
    void dump_dynamic_symbols(void);

protected:

    bool read_program_headers();
    bool read_section_headers();
    bool read_sections();

    bool check_file_range(ElfW(Addr) offset, size_t size, size_t alignment);

protected:

    uintptr_t       m_base_addr;
    std::string     m_soname;
    std::string     m_realpath;
    bool            m_is_loaded;
    int             m_fd;
    int             m_file_size;

    elf_mapped m_phdr_fragment;
    elf_mapped m_shdr_fragment;
    elf_mapped m_dynamic_fragment;
    elf_mapped m_dynstr_fragment;
    elf_mapped m_dynsym_fragment;
    elf_mapped m_strtab_fragment;
    elf_mapped m_symtab_fragment;
    elf_mapped m_shstrtab_fragment;

protected:

    ElfW(Ehdr)      m_ehdr;

    ElfW(Phdr)      *m_phdr;
    ElfW(Word)      m_phdr_num;

    ElfW(Shdr)      *m_shdr;
    ElfW(Word)      m_shdr_num;




    ElfW(Dyn)       *m_dynamic;
    ElfW(Sym)       *m_dynsym;
    ElfW(Sym)       *m_symtab;
    const char      *m_dynstr;
    const char      *m_strtab;
    const char      *m_shstrtab;  
    ElfW(Word)      m_dynamic_size;
    ElfW(Word)      m_dynsym_size;
    ElfW(Word)      m_symtab_size;
    ElfW(Word)      m_dynstr_size;
    ElfW(Word)      m_strtab_size;
    ElfW(Word)      m_shstrtab_size;

};
#endif
