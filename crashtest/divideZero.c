#include <stdio.h>
#include <omp.h>
#include <sys/types.h>
void crashtest_3()
{
    // #pragma omp parallel for
    for (int i = 0; i < 4; i++)
    {
        // printf("My Tid is % 8d\n", gettid());
        int b = 0;
        int a = 1/b;
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
    crashtest_3();
    return 0;
}