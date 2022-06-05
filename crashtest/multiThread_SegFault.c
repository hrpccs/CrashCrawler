#include <stdio.h>
#include <omp.h>
#include<color.h>
#include <sys/types.h>
int main()
{
#pragma omp parallel for
    for (int i = 0; i < 4; i++)
    {
        printf("My Tid is % 8d\n", gettid());
        int *ptr = (void *)main;
        // for (int i = 0; i < 100000000000000; i++);
        printf("attend to write read only mem %p\n", ptr);
        if(i == 3)
            *ptr = 1000;
    }
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