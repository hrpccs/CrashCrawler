 #include <stdio.h>
#include <omp.h>
#include <sys/types.h>
void crashtest_3()
{
    // #pragma omp parallel for
    int b = 10;
    for(long i =0;i< 100000000;i++){
        
    }
    printf("%s\n", b); 
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
    printf("[Segfault] Printing the number in string form...\n");
    crashtest_3();
    return 0;
}