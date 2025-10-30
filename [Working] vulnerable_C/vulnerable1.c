#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void func(){
    char seceret[8] = "SECERET";
    char buffer[8];
    
    printf("Seceret message : %s\n",seceret);
    
    printf("Input : ");
    gets(buffer);

    if (strcmp(seceret, "COSE354") == 0){
        printf("Please patch this code!");
    } else {
        printf("Try again!");
        exit(1);
    }
}

int main(){
    func();
    return 0;
}