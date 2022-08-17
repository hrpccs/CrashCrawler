#include <stdio.h>
#include <omp.h>
#include <sys/types.h>
void crashtest_3()
{
    // #pragma omp parallel for
    char test[1];
    printf("%c", test[10]); 
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
    printf("[Segfault] Visiting out of range\n");
    crashtest_3();
    return 0;
}