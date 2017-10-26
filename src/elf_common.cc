#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "elf_common.h"

bool safe_add(off64_t* out, off64_t a, size_t b) {
    assert(a >= 0);
    if (static_cast<uint64_t>(INT64_MAX - a) < b) {
        return false;
    }
    *out = a + b;
    return true;
}