#include <stdio.h> 
#include <math.h>
#include <pthread.h>
#define N 100

int main()
{
    int i,j,k;
    int a[100];
    for(i=0;i<100;i++)a[i]=0;
    for(i=0;i<N;i++)
        for(j=0;j<N;j++)
            a[i]++;
    printf("hello, world%d\n", a[50]);
    //return 0;
    pthread_exit(NULL);
}

