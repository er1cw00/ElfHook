

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/syscall.h>

#include <assert.h>
#include <libgen.h>

#include "elf_common.h"
#include "elf_file.h"
#include "elf_module.h"


elf_file::elf_file() {
    this->m_phdr = NULL;
    this->m_shdr = NULL;
    this->m_dynamic  = NULL;
    this->m_dynsym   = NULL;
    this->m_symtab   = NULL;
    this->m_dynstr   = NULL;
    this->m_strtab   = NULL;
    this->m_shstrtab = NULL;
    this->m_dynamic_size  = 0;
    this->m_dynsym_size   = 0;
    this->m_symtab_size   = 0;
    this->m_dynstr_size   = 0;
    this->m_strtab_size   = 0;
    this->m_shstrtab_size = 0;
}

elf_file::~elf_file() {
    if (this->m_fd >= 0) {
        close(this->m_fd);
    }
}

bool elf_file::load(const char * realpath) {
    int fd = open(realpath, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        log_error("open \"%s\" fail, error: %s", realpath, strerror(errno));
        return false;
    }
    struct stat file_stat;
    if (fstat(fd, &file_stat) < 0) {
        log_error("get \"%s\" filesz fail, error: %s", realpath, strerror(errno));
        return false;
    }

    this->m_file_size = file_stat.st_size;
    this->m_realpath = realpath;
    this->m_soname = basename(realpath);
    this->m_fd = fd;

    pread(this->m_fd, &m_ehdr, sizeof(m_ehdr), 0);
    if (!elf_module::is_elf_module((void *)&this->m_ehdr)) {
        log_error("%s check elf header fail.\n", this->get_realpath());
        return false;
    }
    if (!this->read_program_headers() ||
        !this->read_section_headers() || 
        !this->read_sections())  {
        return false;
    }
    return true;
}

bool elf_file::check_file_range(ElfW(Addr) offset, size_t size, size_t alignment) {
    off64_t range_start;
    off64_t range_end;
    return offset > 0 &&
        safe_add(&range_start, 0, offset) &&
        safe_add(&range_end, range_start, size) &&
        (range_start < m_file_size) &&
        (range_end <= m_file_size) &&
        ((offset % alignment) == 0);
}

bool elf_file::read_program_headers() {
    this->m_phdr_num = m_ehdr.e_phnum;
    
    if (this->m_phdr_num == 0) {
        log_error("\"%s\" has no program headers", this->get_realpath());
        return false;
    }

    if (this->m_phdr_num < 1 || this->m_phdr_num > 65536/sizeof(ElfW(Phdr))) {
        log_error("\"%s\" has invalid e_phnum: %zd", this->get_soname(), this->m_phdr_num);
        return false;
    }

    // Boundary checks
    size_t size = this->m_phdr_num * sizeof(ElfW(Phdr));
    if (!check_file_range(this->m_ehdr.e_phoff, size, 4)) {
        log_error("\"%s\" has invalid phdr offset/size: %zu/%zu\n",
                this->get_soname(),
                static_cast<size_t>(this->m_ehdr.e_phoff),
                size);
        return false;
    }
    if (!this->m_phdr_fragment.map(this->m_fd, 0, m_ehdr.e_phoff, size)) {
        log_error("\"%s\" phdr mmap failed: %s\n", this->get_realpath(), strerror(errno));
        return false;
    }

    this->m_phdr = static_cast<ElfW(Phdr)*>(m_phdr_fragment.data());
    return true;
}

bool elf_file::read_section_headers() {
    this->m_shdr_num = this->m_ehdr.e_shnum;
    if (this->m_shdr_num == 0) {
        log_error("\"%s\" has no section headers\n", this->get_realpath());
        return false;
    }

    if (this->m_ehdr.e_shstrndx >= this->m_shdr_num) {
      log_error("\"%s\" section headers nums less than e_shstrndx\n", this->get_realpath());
        return false;
    }

    size_t size = this->m_shdr_num * sizeof(ElfW(Shdr));
    if (!check_file_range(this->m_ehdr.e_shoff, size, 4)) {
        log_error("\"%s\" has invalid shdr offset/size: %zu/%zu",
                  this->get_realpath(),
                  static_cast<size_t>(this->m_ehdr.e_shoff),
                  size);
        return false;
    }

    if (!this->m_shdr_fragment.map(this->m_fd, 0, this->m_ehdr.e_shoff, size)) {
        log_error("\"%s\" shdr mmap failed: %s", this->get_realpath(), strerror(errno));
        return false;
    }

    this->m_shdr = static_cast<ElfW(Shdr)*>(this->m_shdr_fragment.data());

    ElfW(Shdr) * shstrtab_shdr = &this->m_shdr[this->m_ehdr.e_shstrndx];
    if (!this->check_file_range(shstrtab_shdr->sh_offset, shstrtab_shdr->sh_size, 1)) {
       log_error("\"%s\" has invalid shdr offset/size: %zu/%zu",
                  this->get_realpath(),
                  static_cast<size_t>(this->m_ehdr.e_shoff),
                  size);
       return false;
    }
    if (!this->m_shstrtab_fragment.map(this->m_fd, 0, shstrtab_shdr->sh_offset, shstrtab_shdr->sh_size)) {
        log_error("\"%s\" shstrtab mmap failed: %s", this->get_realpath(), strerror(errno));
        return false;
    }
    this->m_shstrtab = static_cast<const char *>(this->m_shstrtab_fragment.data());
    this->m_shstrtab_size = shstrtab_shdr->sh_size;
    return true;
}

bool elf_file::read_sections() {

    ElfW(Shdr) * dynamic_shdr = NULL;
    ElfW(Shdr) * dynsym_shdr = NULL;
    ElfW(Shdr) * strtab_shdr = NULL;
    ElfW(Shdr) * dynstr_shdr = NULL;
    ElfW(Shdr) * symtab_shdr = NULL;

    for (size_t i = 0; i < this->m_shdr_num; ++i) {
        const char * sh_name = &this->m_shstrtab[this->m_shdr[i].sh_name];
    //    log_dbg("%-30s %d\n", sh_name, this->m_shdr[i].sh_type);
        if (this->m_shdr[i].sh_type == SHT_DYNAMIC) {
            dynamic_shdr = &this->m_shdr[i];
        } else if (this->m_shdr[i].sh_type == SHT_DYNSYM) {
            dynsym_shdr = &this->m_shdr[i];
        } else if (this->m_shdr[i].sh_type == SHT_STRTAB) {
            if (strncmp(sh_name, ".strtab", 7) == 0) {
                strtab_shdr = &this->m_shdr[i];
            } else if (strncmp(sh_name, ".dynstr", 7) == 0) {
                dynstr_shdr = &this->m_shdr[i];
            }
        } else if (this->m_shdr[i].sh_type == SHT_SYMTAB) {
            if (strncmp(sh_name, ".symtab", 7) == 0) {
                symtab_shdr = &this->m_shdr[i];
            }
        }
    }

    if (dynamic_shdr)
        log_dbg(".dynamic %p, %p, %zd\n", (void*)dynamic_shdr, (void*)dynamic_shdr->sh_offset, (size_t)dynamic_shdr->sh_size);
    if (dynsym_shdr)
        log_dbg(".dynsym  %p, %p, %zd\n", (void*)dynsym_shdr,  (void*)dynsym_shdr->sh_offset,  (size_t)dynsym_shdr->sh_size);
    if (dynstr_shdr)
        log_dbg(".dynstr  %p, %p, %zd\n", (void*)dynstr_shdr,  (void*)dynstr_shdr->sh_offset,  (size_t)dynstr_shdr->sh_size);
    if (symtab_shdr)
        log_dbg(".symtab  %p, %p, %zd\n", (void*)symtab_shdr,  (void*)symtab_shdr->sh_offset,  (size_t)symtab_shdr->sh_size);
    if (strtab_shdr)    
        log_dbg(".strtab  %p, %p, %zd\n", (void*)strtab_shdr,  (void*)strtab_shdr->sh_offset,  (size_t)strtab_shdr->sh_size);
    
    if (dynamic_shdr && 
        check_file_range(dynamic_shdr->sh_offset, dynamic_shdr->sh_size, 4)) {
        if (!this->m_dynamic_fragment.map(this->m_fd, 0, dynamic_shdr->sh_offset, dynamic_shdr->sh_size)) {
            log_warn("dynamic map fail, %s\n", strerror(errno));
        }
        this->m_dynamic = static_cast<ElfW(Dyn) *>(this->m_dynamic_fragment.data());
        this->m_dynamic_size = dynamic_shdr->sh_size;
    }
    if (dynsym_shdr && check_file_range(dynsym_shdr->sh_offset, dynsym_shdr->sh_size, 4)) {
        if (!this->m_dynsym_fragment.map(this->m_fd, 0, dynsym_shdr->sh_offset, dynsym_shdr->sh_size) ) {
            log_warn("dynsym map fail, %s\n", strerror(errno));
        }
        this->m_dynsym = static_cast<ElfW(Sym) *>(this->m_dynsym_fragment.data());
        this->m_dynsym_size = dynsym_shdr->sh_size;
    }
    if (symtab_shdr && 
        check_file_range(symtab_shdr->sh_offset, symtab_shdr->sh_size, 4)) {
        if (!this->m_symtab_fragment.map(this->m_fd, 0, symtab_shdr->sh_offset, symtab_shdr->sh_size)) {
            log_warn("symtab map fail, %s\n", strerror(errno));
        }
        this->m_symtab = static_cast<ElfW(Sym) *>(this->m_symtab_fragment.data());
        this->m_symtab_size = symtab_shdr->sh_size;
    }
    if (dynstr_shdr && 
        check_file_range(dynstr_shdr->sh_offset, dynstr_shdr->sh_size, 1)) {
        if (!this->m_dynstr_fragment.map(this->m_fd, 0, dynstr_shdr->sh_offset, dynstr_shdr->sh_size)) {
            log_warn("dynstr map fail, %s\n", strerror(errno));
        }
        this->m_dynstr = static_cast<const char *>(this->m_dynstr_fragment.data());
        this->m_dynstr_size = dynstr_shdr->sh_size;
    }
    if (strtab_shdr && 
        check_file_range(strtab_shdr->sh_offset, strtab_shdr->sh_size, 1)) {
        if (!this->m_strtab_fragment.map(this->m_fd, 0, strtab_shdr->sh_offset, strtab_shdr->sh_size)) {
            log_warn("strtab map fail, %s\n", strerror(errno));
        }
        this->m_strtab = static_cast<const char *>(this->m_strtab_fragment.data());
        this->m_strtab_size = strtab_shdr->sh_size; 
    }
    return true;
}

ElfW(Sym) * elf_file::find_symbol(const char * name, int type) {
    ElfW(Sym) * sym = this->m_symtab;
    const char * strtab = this->m_strtab;
    for (int i = 0; i < this->m_symtab_size/sizeof(ElfW(Sym)); i++) {
        const char * sym_name = sym[i].st_name + strtab;
        if (type == -1 || type == ELF_ST_TYPE(sym[i].st_info)) {
            if (strcmp(name, sym_name) == 0) {
                return &sym[i];
            }
        }
    }
    return NULL;
}

ElfW(Sym) * elf_file::find_dynamic_symbol(const char * name, int type) {
    ElfW(Sym) * sym = this->m_dynsym;
    const char * strtab = this->m_dynstr;
    for (int i = 0; i < this->m_dynsym_size/sizeof(ElfW(Sym)); i++) {
        const char * sym_name = sym[i].st_name + strtab;
        if (type == -1 || type == ELF_ST_TYPE(sym[i].st_info)) {
            if (strcmp(name, sym_name) == 0) {
                return &sym[i];
            }
        }
    }
    return NULL;
}

bool elf_file::find_function(const char * name, uintptr_t & offset) {
    bool retval = false;
    ElfW(Sym) * sym = this->find_dynamic_symbol(name, STT_FUNC);
    if (!sym) {
        sym = this->find_symbol(name, STT_FUNC);
    }
    if (sym) {
        offset = static_cast<uintptr_t>(sym->st_value);
        retval = true;
    }
    return retval;
}

bool elf_file::find_variable(const char * name, uintptr_t & offset, size_t & size) {
    bool retval = false;
    ElfW(Sym) * sym = this->find_dynamic_symbol(name, STT_OBJECT);
    if (!sym) {
        sym = this->find_symbol(name, STT_OBJECT);
    }
    if (sym) {
        offset = static_cast<uintptr_t>(sym->st_value);
        size = static_cast<size_t>(sym->st_size);
        retval = true;
    }
    return retval;
}
