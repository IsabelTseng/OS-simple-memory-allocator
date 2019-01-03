#ifndef HW_MALLOC_H
#define HW_MALLOC_H

#include <sys/queue.h>
#include <stddef.h>
#include <inttypes.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/mman.h>
#include <math.h>

// TAILQ_HEAD(tailhead,entry) bin[7];

typedef struct chunk_header* chunk_ptr_t;
typedef long long int chunk_size_t;
typedef long long int chunk_flag_t;

typedef struct chunk_header_info {
    unsigned int pre_chunk_size : 31;
    unsigned int allocated_flag : 1;
    unsigned int current_chunk_size : 31;
    unsigned int mmap_flag : 1;
} chunk_header_info;

typedef struct chunk_header {
    // TAILQ_ENTRY(chunk_header) entry;
    // size_t pre_chunk_size;
    // size_t chunk_size;
    // int prev_free_flag;
    struct chunk_header* prev;
    struct chunk_header* next;
    struct chunk_header_info size_and_flag;
} chunk_header;

chunk_header head;
chunk_header* mmap_head;
extern void *hw_malloc(size_t bytes);
extern int hw_free(void *mem);
extern void *get_start_sbrk(void);

#endif
