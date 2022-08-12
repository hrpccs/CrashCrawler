#include <stdio.h>
#include <omp.h>
#include <sys/types.h>
void crashtest_3()
{
    #pragma omp parallel for
    for (int i = 0; i < 4; i++)
    {
        printf("My Tid is % 8d\n", gettid());
        int *ptr = (void *)crashtest_3;
        // for (int i = 0; i < 100000000000000; i++);
        printf("attend to write read only mem %p\n", ptr);
        if(i == 3)
            *ptr = 1000;
    }
}
void crashtest_2()
{
    crashtest_3();
}
void crashtest_1()
{
    crashtest_2();
}
int main()
{
    printf("[Segfault] Multiple thread testing\n");
    crashtest_3();
    return 0;
}