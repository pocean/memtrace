#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

#define MAX 10

struct memtrace_type {
    unsigned long addr;
    unsigned char flag;
};

struct memtrace_buf_type {
    int pos;
    struct memtrace_type memtrace[MAX];
};

pthread_key_t keyp;
pthread_once_t init_done = PTHREAD_ONCE_INIT;

int memtrace_save(struct memtrace_buf_type* memtrace_buf)
{
    FILE* fp;
    char path[50];
    int wstat;
    pthread_t tid = pthread_self();
    sprintf(path, "/home2/pocean/memtrace/memtrace/%u", (unsigned int)tid);
    fp = fopen(path, "a+");
    if (NULL == fp) {
        printf("file open error!\n");
        return 0;
    }
    wstat = fwrite(memtrace_buf->memtrace, sizeof(struct memtrace_type), memtrace_buf->pos + 1, fp);
    if (wstat != memtrace_buf->pos+1) {
        printf("error in write file!\n");
    }
    fclose(fp);
    return 0;
}

void memtrace_finish(void* memtrace_buf)
{
    printf("zhixingle xi gou!\n");
    memtrace_save((struct memtrace_buf_type*)memtrace_buf);
    if (NULL != memtrace_buf) {
        free(memtrace_buf);
    } 
}

void memtrace_init(void)
{
    pthread_key_create(&keyp, memtrace_finish);
}

int showtrace(unsigned long addr, int flag)
{
    struct memtrace_buf_type* memtrace_buf = NULL;

    pthread_once(&init_done, memtrace_init);
    memtrace_buf = pthread_getspecific(keyp);

    if (NULL == memtrace_buf) {
        memtrace_buf = (struct memtrace_buf_type*)malloc(sizeof(struct memtrace_buf_type));
        memtrace_buf->pos = 0;
        pthread_setspecific(keyp, (void*)memtrace_buf);
    }
    if (memtrace_buf->pos == MAX) {
        memtrace_save(memtrace_buf);
        memtrace_buf->pos = 0;
    } 

    (memtrace_buf->memtrace)[memtrace_buf->pos].addr = addr;
    (memtrace_buf->memtrace)[memtrace_buf->pos].flag = (unsigned char)flag;
    memtrace_buf->pos += 1;

    return 0;
}
