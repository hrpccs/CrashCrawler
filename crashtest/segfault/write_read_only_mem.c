#include <stdio.h>

int main(){
    
    int *ptr = (void*)main;
    printf("attend to write read only mem %p",ptr);
    *ptr = 1000;
    return 0;
}