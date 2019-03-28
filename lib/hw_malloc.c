#include <stdlib.h>
#include <stdio.h>
#include "hw_malloc.h"

struct chunk_header bin[10];
struct chunk_header *start_brk = NULL;
struct chunk_header *end_brk = NULL;
int chunk_header_size = sizeof(struct chunk_header);

static void *shift(void *const chunk, const long long size)
{
    return chunk + size;
}

static chunk_header *regular(chunk_header *const chunk)
{
    if ((void *)chunk < (void *)start_brk) {
        return shift(chunk, 65536);
    } else if ((void *)chunk >= (void *)start_brk + 65536) {
        return shift(chunk, -(65536));
    } else {
        return chunk;
    }
}

static struct chunk_header *prev_header(struct chunk_header *const chunk)
{
    return regular(shift(chunk, -(chunk->size_and_flag.pre_chunk_size)));
}

static struct chunk_header *next_header(struct chunk_header *const chunk)
{
    return regular(shift(chunk, chunk->size_and_flag.current_chunk_size));
}

static int chunk_is_free(struct chunk_header *const chunk)
{
    return chunk->size_and_flag.allocated_flag == 1;
}

static int set_chunk_free_flag(struct chunk_header *const chunk, int _free)
{
    chunk->size_and_flag.allocated_flag = _free;
}

// static int in_range(struct chunk_header *const chunk)
// {
// 	return (((void *)start_brk <= (void *)chunk) &&
// 	        ((void *)chunk + 24 <=
// 	         (void *)start_brk + 65536));

// }

// static int can_merge_next(struct chunk_header *const chunk)
// {
// 	if (next_header(chunk) > chunk &&
// 	    chunk_is_free(next_header(chunk)) &&
// 	    chunk_is_free(chunk)) {
// 		return 1;
// 	}
// 	return 0;
// }

// static void merge_next(struct chunk_header *const chunk)
// {
// 	delete_list(chunk);
// 	delete_list(next_header(chunk));
// 	chunk->chunk_size = chunk->chunk_size + next_header(chunk)->chunk_size;
// 	next_header(chunk)->pre_chunk_size = chunk->chunk_size;
// 	add_list(chunk);
// }

void add_list(struct chunk_header *chunk, int whichbin)
{
    puts("add to heap");
    // chunk_header *now = &bin[whichbin];
    // // memcpy(map_memory,&newnode,sizeof(chunk_header));
    // // *((chunk_header*)map_memory) = newnode;
    // // printf("%d!!\n",(*((chunk_header*)map_memory)).size_and_flag.current_chunk_size);
    // // chunk_header* newnodePtr = (chunk_header*)map_memory;
    // while (now->next != now){
    //     // if(size < now->next->size_and_flag.current_chunk_size)break;
    //     now = now->next;
    // }
    // newnodePtr->next = now->next;
    // newnodePtr->next->prev = newnodePtr;
    // now->next = newnodePtr;
    // newnodePtr->prev = now;

    // bin[whichbin].prev->next = chunk;
    // chunk->prev = bin[bin_no].prev;
    // chunk->next = &bin[bin_no];
    // bin[bin_no].prev = chunk;

    // int bin_no;
    // if (chunk->chunk_size == 32) bin_no = 0;
    // else if (chunk->chunk_size == 32) bin_no = 1;
    // else if (chunk->chunk_size == 64) bin_no = 2;
    // else if (chunk->chunk_size == 128) bin_no = 3;
    // else if (chunk->chunk_size == 256) bin_no = 4;
    // else if (chunk->chunk_size == 512) bin_no = 5;
    // else bin_no = 6;

    // if (bin_no == 6) {	//largest at bin[6].next
    // 	struct chunk_header *ptr = bin[6].next;
    // 	while (ptr != &bin[6] && ptr->chunk_size >= chunk->chunk_size)
    // 		ptr = ptr->next;
    // 	ptr->prev->next = chunk;
    // 	chunk->prev = ptr->prev;
    // 	chunk->next = ptr;
    // 	ptr->prev = chunk;
    // } else {	//newest at bin[].prev
    // 	bin[bin_no].prev->next = chunk;
    // 	chunk->prev = bin[bin_no].prev;
    // 	chunk->next = &bin[bin_no];
    // 	bin[bin_no].prev = chunk;
    // }
    return;
}

// void delete_list(struct chunk_header *chunk)
// {
// 	chunk->prev->next = chunk->next;
// 	chunk->next->prev = chunk->prev;
// 	chunk->prev = chunk;
// 	chunk->next = chunk;
// 	return;
// }

void *hw_malloc(size_t bytes)
{
    struct chunk_header *allocated_chunk = NULL;
    struct chunk_header *free_chunk = NULL;
    struct chunk_header *next_chunk = NULL;
    //adjust chunk size to multiple of 8
    int size = 0;
    void *map_memory;
    if(bytes + chunk_header_size > 32768) {
        size = bytes + chunk_header_size;
        map_memory = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        // printf("%d --- 0x%08lx\n", size, map_memory);
        chunk_header *now = mmap_head;
        chunk_header newnode= {NULL, NULL, .size_and_flag = {chunk_header_size, 0, size, 1}};
        newnode.size_and_flag.current_chunk_size = size;
        // printf("%d!!%d!!\n",size,newnode.size_and_flag.current_chunk_size);
        // memcpy(map_memory,&newnode,sizeof(chunk_header));
        *((chunk_header*)map_memory) = newnode;
        // printf("%d!!\n",(*((chunk_header*)map_memory)).size_and_flag.current_chunk_size);
        chunk_header* newnodePtr = (chunk_header*)map_memory;
        while (now->next != mmap_head && now!=now->next) {
            if(size < now->next->size_and_flag.current_chunk_size)break;
            now = now->next;
        }
        newnodePtr->next = now->next;
        newnodePtr->next->prev = newnodePtr;
        now->next = newnodePtr;
        newnodePtr->prev = now;
        return map_memory+chunk_header_size;
    } else {
        int temp = bytes, hsize = 1; // min msize = 1
        while(temp>1) {
            temp/=2;
            ++hsize;
        }
        size = pow(2,hsize) + chunk_header_size;
        if (start_brk == NULL) {
            //create heap
            int free_space = 65536;
            start_brk = sbrk(free_space);
            end_brk = sbrk(0);
            //create bin
            int i;
            for (i = 0; i < 10; i++) {
                chunk_header initbin = {&bin[i], &bin[i], {chunk_header_size, 0, chunk_header_size, 0}};
                bin[i] = initbin;
            }

            chunk_header newchunk = {&bin[10], &bin[10], {chunk_header_size, 0, free_space/2, 0}};
            *free_chunk = newchunk;
            next_chunk = (long long int)free_chunk + free_space/2;
            chunk_header newchunk2 = {&bin[10], &bin[10], {free_space/2, 0, free_space/2, 0}};
            *next_chunk = newchunk2;

            set_chunk_free_flag(free_chunk, 1);
            set_chunk_free_flag(next_chunk, 1);
            add_list(free_chunk,10);
            add_list(next_chunk,10);


            // allocated_chunk = start_brk;
            // free_chunk = (long long int)allocated_chunk + size;

            // allocated_chunk->size_and_flag.current_chunk_size = size;
            // next_header(allocated_chunk)->size_and_flag.pre_chunk_size = allocated_chunk->size_and_flag.current_chunk_size;

            // free_chunk->size_and_flag.current_chunk_size = (long long int)end_brk - (long long int)free_chunk;
            // next_header(free_chunk)->size_and_flag.pre_chunk_size = free_chunk->size_and_flag.current_chunk_size;

            // free_chunk->prev = NULL;
            // free_chunk->next = NULL;
            // set_chunk_free_flag(allocated_chunk, 0);
            // set_chunk_free_flag(free_chunk, 1);
            // add_list(free_chunk);
            // return (long long int)allocated_chunk + chunk_header_size;
        }
        // return (long long int)free_chunk + chunk_header_size;
    }
}

int hw_free(void *mem)
{
    // printf("free 0x%08lx\n", *((size_t*)mem));
    struct chunk_header *chunk = *((size_t*)mem) - (size_t)chunk_header_size;
    // printf("%d %d free! 0x%08lx\n", sizeof(chunk_header), chunk_header_size, chunk);
    // printf("%d\n",chunk->size_and_flag.current_chunk_size);
    if(chunk->size_and_flag.current_chunk_size > 32768) {
        chunk_header *now = mmap_head->next;
        while (now != chunk && now!=mmap_head) {
            // if(size < now->next->size_and_flag.current_chunk_size)break;
            now = now->next;
        }
        // printf("~~0x%08lx\n",now);
        now->next->prev = now->prev;
        now->prev->next = now->next;
        now->next = NULL;
        now->prev = NULL;

        // printf("%d ++ 0x%08lx\n", chunk->size_and_flag.current_chunk_size, chunk);
        return munmap(chunk,chunk->size_and_flag.current_chunk_size);
    }

    // if (chunk < start_brk || chunk >= end_brk)	//out of range
    // 	return 0;
    // struct chunk_header *ptr = start_brk;
    // while (ptr < chunk)
    // 	ptr = (long long int)ptr + ptr->chunk_size;
    // if (ptr != chunk || chunk_is_free(chunk))
    // 	return 0;

    // set_chunk_free_flag(chunk, 1);
    // add_list(chunk);
    // if (can_merge_next(chunk)) {
    // 	merge_next(chunk);
    // }
    // if (can_merge_next(prev_header(chunk))) {
    // 	merge_next(prev_header(chunk));
    // }
    return 1;
}

void *get_start_sbrk(void)
{
    return start_brk;
    return NULL;
}

// void print_bin(int bin_no)
// {
// 	struct chunk_header *ptr = bin[bin_no].next;
// 	while (ptr != &bin[bin_no]) {
// 		printf("0x%08x--------%lld\n", (long long int)ptr - (long long int)start_brk,
// 		       ptr->chunk_size);
// 		ptr = ptr->next;
// 	}
// 	return;
// }