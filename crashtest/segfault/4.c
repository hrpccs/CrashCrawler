#include <stdio.h>
#include <omp.h>
#include <sys/types.h>
void crashtest_3()
{
    // #pragma omp parallel for
    int *p = NULL;
    *p = 1;
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
    printf("[Segfault] Visiting the NULL pointer\n");
    crashtest_3();
    return 0;
}