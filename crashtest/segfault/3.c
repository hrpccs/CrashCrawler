#include <stdio.h>
#include <omp.h>
#include <sys/types.h>
void crashtest_3()
{
    // #pragma omp parallel for
    int* p = (int*)0xC0000fff;
    *p = 10;
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
    printf("[Segfault] Writing into unallocate area...\n");
    crashtest_3();
    return 0;
}