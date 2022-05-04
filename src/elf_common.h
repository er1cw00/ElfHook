#if !defined (__ELF_COMMON_H__)
#define __ELF_COMMON_H__

#include <elf.h>

#include <stdio.h>
#include <stdlib.h>

#if defined(__LP64__)
#define ElfW(type) Elf64_##type
static inline ElfW(Word) elf_r_sym(ElfW(Xword) info) { return ELF64_R_SYM(info); }
static inline ElfW(Xword) elf_r_type(ElfW(Xword) info) { return ELF64_R_TYPE(info); }
#else
#define ElfW(type) Elf32_##type
static inline ElfW(Word) elf_r_sym(ElfW(Word) info) { return ELF32_R_SYM(info); }
static inline ElfW(Word) elf_r_type(ElfW(Word) info) { return ELF32_R_TYPE(info); }
#endif

#define R_GENERIC_NONE 0   // R_*_NONE is always 0

#if defined (__aarch64__)

#define R_GENERIC_JUMP_SLOT     R_AARCH64_JUMP_SLOT
// R_AARCH64_ABS64 is classified as a static relocation but it is common in DSOs.
#define R_GENERIC_ABSOLUTE      R_AARCH64_ABS64
#define R_GENERIC_GLOB_DAT      R_AARCH64_GLOB_DAT
#define R_GENERIC_RELATIVE      R_AARCH64_RELATIVE
#define R_GENERIC_IRELATIVE     R_AARCH64_IRELATIVE
#define R_GENERIC_COPY          R_AARCH64_COPY
#define R_GENERIC_TLS_DTPMOD    R_AARCH64_TLS_DTPMOD
#define R_GENERIC_TLS_DTPREL    R_AARCH64_TLS_DTPREL
#define R_GENERIC_TLS_TPREL     R_AARCH64_TLS_TPREL
#define R_GENERIC_TLSDESC       R_AARCH64_TLSDESC

#elif defined (__arm__)

#define __work_around_b_24465209__ (1)
#define R_GENERIC_JUMP_SLOT     R_ARM_JUMP_SLOT
// R_ARM_ABS32 is classified as a static relocation but it is common in DSOs.
#define R_GENERIC_ABSOLUTE      R_ARM_ABS32
#define R_GENERIC_GLOB_DAT      R_ARM_GLOB_DAT
#define R_GENERIC_RELATIVE      R_ARM_RELATIVE
#define R_GENERIC_IRELATIVE     R_ARM_IRELATIVE
#define R_GENERIC_COPY          R_ARM_COPY
#define R_GENERIC_TLS_DTPMOD    R_ARM_TLS_DTPMOD32
#define R_GENERIC_TLS_DTPREL    R_ARM_TLS_DTPOFF32
#define R_GENERIC_TLS_TPREL     R_ARM_TLS_TPOFF32
#define R_GENERIC_TLSDESC       R_ARM_TLS_DESC

#elif defined (__i386__)

#define __work_around_b_24465209__ (1)
#define R_GENERIC_JUMP_SLOT     R_386_JMP_SLOT
#define R_GENERIC_ABSOLUTE      R_386_32
#define R_GENERIC_GLOB_DAT      R_386_GLOB_DAT
#define R_GENERIC_RELATIVE      R_386_RELATIVE
#define R_GENERIC_IRELATIVE     R_386_IRELATIVE
#define R_GENERIC_COPY          R_386_COPY
#define R_GENERIC_TLS_DTPMOD    R_386_TLS_DTPMOD32
#define R_GENERIC_TLS_DTPREL    R_386_TLS_DTPOFF32
#define R_GENERIC_TLS_TPREL     R_386_TLS_TPOFF
#define R_GENERIC_TLSDESC       R_386_TLS_DESC

#elif defined (__x86_64__)

#define R_GENERIC_JUMP_SLOT     R_X86_64_JUMP_SLOT
#define R_GENERIC_ABSOLUTE      R_X86_64_64
#define R_GENERIC_GLOB_DAT      R_X86_64_GLOB_DAT
#define R_GENERIC_RELATIVE      R_X86_64_RELATIVE
#define R_GENERIC_IRELATIVE     R_X86_64_IRELATIVE
#define R_GENERIC_COPY          R_X86_64_COPY
#define R_GENERIC_TLS_DTPMOD    R_X86_64_DTPMOD64
#define R_GENERIC_TLS_DTPREL    R_X86_64_DTPOFF64
#define R_GENERIC_TLS_TPREL     R_X86_64_TPOFF64
#define R_GENERIC_TLSDESC       R_X86_64_TLSDESC

#endif


#define PAGE_START(addr)             (~(getpagesize() - 1) & (addr))
#define PAGE_END(addr)               PAGE_START((addr) + (PAGE_SIZE-1))
#define PAGE_OFFSET(x)               ((x) & ~PAGE_MASK)

#define SAFE_SET_VALUE(t, v)         if(t) *(t) = (v)

#define MAYBE_MAP_FLAG(x, from, to)  (((x) & (from)) ? (to) : 0)
#define PFLAGS_TO_PROT(x)            (MAYBE_MAP_FLAG((x), PF_X, PROT_EXEC) | \
                                      MAYBE_MAP_FLAG((x), PF_R, PROT_READ) | \
                                      MAYBE_MAP_FLAG((x), PF_W, PROT_WRITE))

#define powerof2(x)                  ((((x)-1)&(x))==0)

inline static int GetTargetElfMachine()
{
#if defined(__arm__)
    return EM_ARM;
#elif defined(__aarch64__)
    return EM_AARCH64;
#elif defined(__i386__)
    return EM_386;
#elif defined(__mips__)
    return EM_MIPS;
#elif defined(__x86_64__)
    return EM_X86_64;
#endif
}

#define CHECK(predicate) \
    do { \
        if (!(predicate)) { \
            log_fatal("%s:%d: %s CHECK '" #predicate "' failed", \
                  __FILE__, __LINE__, __FUNCTION__); \
        } \
    } while(0)



void dump_hex(uint8_t * pbuf, int size);
bool safe_add(off64_t* out, off64_t a, size_t b);

#endif
