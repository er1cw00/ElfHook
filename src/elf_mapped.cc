#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>

#include <inttypes.h>
#include <stdlib.h>
#include <assert.h>

#include "elf_common.h"
#include "elf_mapped.h"
#include "elf_log.h"

elf_mapped::elf_mapped() : m_map_start(NULL), m_map_size(0),
                                         m_data(NULL), m_size (0) {
}

elf_mapped::~elf_mapped() {
    if (m_map_start != NULL) {
        munmap(m_map_start, m_map_size);
    }
}

bool elf_mapped::map(int fd, off64_t base_offset, size_t elf_offset, size_t size) {
    off64_t offset;

    CHECK(safe_add(&offset, base_offset, elf_offset));
    off64_t page_min = PAGE_START(offset);
    off64_t end_offset;

    CHECK(safe_add(&end_offset, offset, size));
    CHECK(safe_add(&end_offset, end_offset, PAGE_OFFSET(offset)));

    size_t map_size = static_cast<size_t>(end_offset - page_min);
    CHECK(map_size >= size);

    uint8_t* map_start = static_cast<uint8_t*>(
                          mmap64(NULL, map_size, PROT_READ, MAP_PRIVATE, fd, page_min));

    if (map_start == MAP_FAILED) {
        return false;
    }

    m_map_start = map_start;
    m_map_size = map_size;

    m_data = map_start + PAGE_OFFSET(offset);
    m_size = size;

    return true;
}
