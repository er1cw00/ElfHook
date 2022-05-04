#if !defined(__ELFKIT_SOINFO_H__)
#define __ELFKIT_SOINFO_H__

#define SOINFO_NAME_LEN (128)

struct soinfo {
#if defined(__work_around_b_24465209__)
    char                    old_name[SOINFO_NAME_LEN];
#endif
    const ElfW(Phdr)        *phdr;
    size_t                  phnum;
#if defined(__work_around_b_24465209__)
    ElfW(Addr)              unused0;
#endif
    ElfW(Addr)              base;
    size_t                  size;
#if defined(__work_around_b_24465209__)
    uint32_t                unused1;   // DO NOT USE, maintained for compatibility.
#endif
    ElfW(Dyn)               *dynamic;

#if defined(__work_around_b_24465209__)
    uint32_t                unused2;   // DO NOT USE, maintained for compatibility
    uint32_t                unused3;   // DO NOT USE, maintained for compatibility
#endif
    struct soinfo           *next;
    uint32_t                flags;
    const char              *strtab;
    ElfW(Sym)               *symtab;
    size_t                  nbucket;
    size_t                  nchain;
    uint32_t                *bucket;
    uint32_t                *chain;

#if defined(__mips__) || !defined(__LP64__)
    ElfW(Addr)**            plt_got;
#endif

#if defined(USE_RELA)
    ElfW(Rela)*             plt_rela;
    size_t                  plt_rela_count;

    ElfW(Rela)*             rela;
    size_t                  rela_count;
#else
    ElfW(Rel)*              plt_rel;
    size_t                  plt_rel_count;

    ElfW(Rel)*              rel;
    size_t                  rel_count;
#endif
};

#endif