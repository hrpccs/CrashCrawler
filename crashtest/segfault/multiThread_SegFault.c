#include <stdio.h>
#include <omp.h>
#include<color.h>
#include <unistd.h>
#include <sys/types.h>
#include <unistd.h>
void crashtest_3()
{
#pragma omp parallel for
    for (int i = 0; i < 4; i++)
    {
        printf("My Tid is % 8d\n", gettid());
        int *ptr = (void *)crashtest_3;
        //for (int i = 0; i < 1000000; i++){
        //    getpid();
        //}
        printf("attend to write read only mem %p\n", ptr);
        if(i == 3)
            *ptr = 1000;
    }
}
void crashtest_2()
{
    printf("crashtest_2\n");
    crashtest_3();
}
void crashtest_1()
{
    printf("crashtest_1\n");
    crashtest_2();
}
int main()
{
    crashtest_1();
    // printf(NONE"Test\n"NONE);
    // printf(LIGHT_BLUE"Test\n"NONE);
    // printf(LIGHT_CYAN"Test\n"NONE);
    // printf(LIGHT_GRAY"Test\n"NONE);
    // printf(LIGHT_GREEN"Test\n"NONE);
    // printf(LIGHT_PURPLE"Test\n"NONE);
    // printf(LIGHT_RED"Test\n"NONE);
    // printf(RED"Test\n"NONE);
    // printf(GREEN"Test\n"NONE);
    // printf(DARY_GRAY"Test\n"NONE);
    // printf(BLUE"Test\n"NONE);
    // printf(CYAN"Test\n"NONE);
    // printf(PURPLE"Test\n"NONE);
    // printf(BROWN"Test\n"NONE);
    // printf(YELLOW"Test\n"NONE);
    // printf(WHITE"Test\n"NONE);
    // printf("Test\n");
    return 0;
}
