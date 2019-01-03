#include "lib/hw_malloc.h"
#include "hw4_mm_test.h"

int main(int argc, char *argv[])
{
    init();
    // printf("%d\n",sizeof(long long int));
    char *get_f = malloc(20*sizeof(char));
    char *get_s = malloc(20*sizeof(char));


    // printf("chunk_header size: %ld\n", sizeof(a.size_and_flag));
    // printf("struct chunk_header_info size: %ld\n", sizeof(struct chunk_header));

    while(scanf("%s %s",get_f,get_s)!=EOF) {
        if(strcmp(get_f,"alloc")==0) {
//			printf("start_brk: %p\n", get_start_sbrk());
            size_t bytes =0;
            sscanf(get_s,"%d",&bytes);
            printf("0x%08lx\n", hw_malloc(bytes));
            // if(bytes % 8 ==0) {
            // printf("0x%08lx\n", hw_malloc(bytes) - get_start_sbrk());
            // }
            // hw_malloc(bytes);
        } else if(strcmp(get_f,"free")==0) {
            size_t freeaddress =0;
            sscanf(get_s,"%lx",&freeaddress);
            // printf("free 0x%08lx\n", freeaddress);
            int gf = hw_free(&freeaddress);
            // int memorysize =0;
            // sscanf(get_s,"%x",&memorysize);
            // int gf = hw_free(memorysize + get_start_sbrk());
            printf("%s\n", gf == 0 ? "success" : "fail");
        } else if(strcmp(get_f,"print")==0) {
            if(strcmp(get_s,"mmap_alloc_list")==0) {
                for(chunk_header* itr = mmap_head->next; itr!=mmap_head; itr=itr->next) {
                    printf("0x%08lx--------%d\n", itr, itr->size_and_flag.current_chunk_size);
                }
            }

// 			int key=atoi(&get_s[4]);

// //			printf("start_brk: %p\n", get_start_sbrk());
// 			struct chunk_header *search = malloc(sizeof(struct chunk_header));
// 			TAILQ_FOREACH(search,&bin[key],entry) {
// 				void *a = search;
// 				printf("0x%08lx\n", a - get_start_sbrk());
// 			}
        } else {
            // printf("start_brk: %p\n", get_start_sbrk());
        }
    }
    /*
        printf("chunk_header size: %ld\n", sizeof(struct chunk_header));
        printf("%p\n", hw_malloc(8));
        printf("%s\n", hw_free(NULL) == 1 ? "success" : "fail");
        printf("start_brk: %p\n", get_start_sbrk());
      */
    free(get_f);
    free(get_s);
    return 0;
}

void init()
{
    // chunk_header_info initinfo = {24, 24, 0, 1};
    chunk_header inithead = {NULL, NULL, {sizeof(struct chunk_header), sizeof(struct chunk_header), 0, 1}};
    head = inithead;
    mmap_head = &head;
    head.prev = mmap_head;
    head.next = mmap_head;
    // head.size_and_flag = initinfo;
    // printf("0x%08lx--------%d\n", mmap_head, mmap_head->size_and_flag.current_chunk_size);
    // chunk_header_info init
    // head.size_and_flag->pre_chunk_size = 0;
    // head.size_and_flag->current_chunk_size = 24;
    // head.size_and_flag->allocated_flag = 0;
    // head.size_and_flag->mmap_flag = 1;
    // mmap_head = &head;
}