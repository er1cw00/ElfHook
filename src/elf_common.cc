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

void dump_hex(uint8_t * pbuf, int size) {
        int i = 0;
        for (int j = 0; j < size; j += 16) {
            i = j;
            fprintf(stderr, "%02X %02X %02X %02X %02X %02X %02X %02X  ", 
                pbuf[i + 0], pbuf[i + 1], pbuf[i + 2], pbuf[i + 3],
                pbuf[i + 4], pbuf[i + 5], pbuf[i + 6], pbuf[i + 7]);
            fprintf(stderr, "%02X %02X %02X %02X %02X %02X %02X %02X\n", 
                pbuf[i + 8], pbuf[i + 9], pbuf[i + 10], pbuf[i + 11],
                pbuf[i + 12], pbuf[i + 13], pbuf[i + 14], pbuf[i + 15]);
        }
        for (int j = i; j < size; j += 1) {
            fprintf(stderr, "%02X ", pbuf[j]);
        }
        fprintf(stderr, "\n");
        return;
    }