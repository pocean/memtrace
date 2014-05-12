#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

#define MAX 100000

struct memtrace_type {
    unsigned long addr;
    int flag;
    struct memtrace_type* next;
};

struct memtrace_list_type {
    int count;
    struct memtrace_type* head;
    struct memtrace_type* tail;
};

pthread_key_t keyp;
pthread_once_t init_done = PTHREAD_ONCE_INIT;

int memtrace_save(struct memtrace_list_type* memtrace_list)
{
    FILE* fp;
    struct memtrace_type* p;
    char path[50];
    pthread_t tid = pthread_self();
    sprintf(path, "/home2/pocean/test/memtrace/%u", (unsigned int)tid);
    fp = fopen(path, "a+");
    if (NULL == fp) {
        printf("file open error!\n");
        return 0;
    }
    for (p = memtrace_list->head; p != NULL; p = p->next) {
        if (0 == p->flag)
            fprintf(fp, "load:\t");
        else
            fprintf(fp, "store:\t");
        fprintf(fp, "0x%lx\n", p->addr);
    }
    fclose(fp);
    return 0;
}

int memtrace_free(struct memtrace_list_type* memtrace_list)
{
    struct memtrace_type* p = memtrace_list->head;
    while (NULL != p) {
        memtrace_list->head = p->next;
        free(p);
        p = memtrace_list->head;
    }
    memtrace_list->count = 0;
    memtrace_list->tail = NULL;
    return 0;
}

void memtrace_finish(void* memtrace_list)
{
    printf("zhixingle xi gou!\n");
    memtrace_save((struct memtrace_list_type*)memtrace_list);
    memtrace_free((struct memtrace_list_type*)memtrace_list);
    free(memtrace_list);
    pthread_key_delete(keyp);
}

void memtrace_init(void)
{
    pthread_key_create(&keyp, memtrace_finish);
}

int showtrace(unsigned long addr, int flag)
{
    struct memtrace_type* p;
    struct memtrace_list_type* memtrace_list;

    pthread_once(&init_done, memtrace_init);
    memtrace_list = pthread_getspecific(keyp);
    if (NULL == memtrace_list) {
        memtrace_list = (struct memtrace_list_type*)malloc(sizeof(struct memtrace_list_type));
        memtrace_list->count = 0;
        memtrace_list->head = NULL;
        memtrace_list->tail = NULL;
        pthread_setspecific(keyp, (void*)memtrace_list);
    }
    if (memtrace_list->count == MAX) {
        memtrace_save(memtrace_list);
        memtrace_free(memtrace_list);
    } 
    p = (struct memtrace_type*)malloc(sizeof(struct memtrace_type)*sizeof(char));
    p->addr = addr;
    p->flag = flag;
    p->next = NULL;
    if (NULL == memtrace_list->tail) {
        memtrace_list->tail = p;
        memtrace_list->head = p;
    } else {
        memtrace_list->tail->next = p;
        memtrace_list->tail = p;
    }
    memtrace_list->count++;
    
    return 0;
}
