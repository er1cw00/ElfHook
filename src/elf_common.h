#if !defined (__ELF_COMMON_H__)
#define __ELF_COMMON_H__

#include <elf.h>

#include <stdio.h>
#include <stdlib.h>

#if defined(__LP64__)
#define ElfW(type) Elf64_ ## type
static inline ElfW(Word) elf_r_sym(ElfW(Xword) info) { return ELF64_R_SYM(info); }
static inline ElfW(Xword) elf_r_type(ElfW(Xword) info) { return ELF64_R_TYPE(info); }
#else
#define ElfW(type) Elf32_ ## type
static inline ElfW(Word) elf_r_sym(ElfW(Word) info) { return ELF32_R_SYM(info); }
static inline ElfW(Word) elf_r_type(ElfW(Word) info) { return ELF32_R_TYPE(info); }
#endif

#if defined(__arm__)

#if !defined(R_ARM_ABS32)
#define R_ARM_ABS32                 2
#endif
#if !defined(R_ARM_GLOB_DAT)
#define R_ARM_GLOB_DAT              21
#endif
#if !defined(R_ARM_JUMP_SLOT)
#define R_ARM_JUMP_SLOT             22
#endif
#if !defined(R_ARM_RELATIVE)
#define R_ARM_RELATIVE              23
#endif
#if !defined(R_ARM_IRELATIVE)
#define R_ARM_IRELATIVE             160
#endif

#define R_GENERIC_JUMP_SLOT R_ARM_JUMP_SLOT
#define R_GENERIC_GLOB_DAT  R_ARM_GLOB_DAT
#define R_GENERIC_RELATIVE  R_ARM_RELATIVE
#define R_GENERIC_IRELATIVE R_ARM_IRELATIVE
#define R_GENERIC_ABS       R_ARM_ABS32

#elif defined(__aarch64__)

#if !defined(R_AARCH64_ABS64)
#define R_AARCH64_ABS64                 257
#endif
#if !defined(R_AARCH64_GLOB_DAT)
#define R_AARCH64_GLOB_DAT              1025
#endif
#if !defined(R_AARCH64_JUMP_SLOT)
#define R_AARCH64_JUMP_SLOT             1026
#endif
#if !defined(R_AARCH64_RELATIVE)
#define R_AARCH64_RELATIVE              1027
#endif
#if !defined(R_AARCH64_IRELATIVE)
#define R_AARCH64_IRELATIVE             1032
#endif

#define R_GENERIC_JUMP_SLOT R_AARCH64_JUMP_SLOT
#define R_GENERIC_GLOB_DAT  R_AARCH64_GLOB_DAT
#define R_GENERIC_RELATIVE  R_AARCH64_RELATIVE
#define R_GENERIC_IRELATIVE R_AARCH64_IRELATIVE
#define R_GENERIC_ABS       R_AARCH64_ABS64
#endif

#define DT_GNU_HASH      ((int)0x6ffffef5)
#define DT_ANDROID_REL   ((int)0x6000000f)
#define DT_ANDROID_RELSZ ((int)0x60000010)


#define PAGE_START(addr)    (~(getpagesize() - 1) & (addr))
#define PAGE_END(addr)      PAGE_START((addr) + (PAGE_SIZE-1))
#define PAGE_OFFSET(x)      ((x) & ~PAGE_MASK)

#define SAFE_SET_VALUE(t, v) if(t) *(t) = (v)

#define MAYBE_MAP_FLAG(x, from, to)  (((x) & (from)) ? (to) : 0)
#define PFLAGS_TO_PROT(x)            (MAYBE_MAP_FLAG((x), PF_X, PROT_EXEC) | \
                                      MAYBE_MAP_FLAG((x), PF_R, PROT_READ) | \
                                      MAYBE_MAP_FLAG((x), PF_W, PROT_WRITE))


#define powerof2(x)     ((((x)-1)&(x))==0)
#define SOINFO_NAME_LEN (128)

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
