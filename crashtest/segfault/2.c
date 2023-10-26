#include <stdio.h>
#include <omp.h>
#include <sys/types.h>
int a=1;
void crashtest_3()
{
    // #pragma omp parallel for
    char *c = "hello world";
    c[1] = 'H';
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
    printf("[Segfault] Wrong visit type...\n");
    crashtest_1();
    return 0;
}