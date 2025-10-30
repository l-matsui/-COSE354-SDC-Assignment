#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void func(){
    char seceret[8] = "SECERET";
    char buffer[8];
    
    printf("Seceret message : %s\n",seceret);
    
    // VULNERABILITY: gets() is vulnerable to Buffer Overflow
    printf("Input : ");
    // gets(buffer);
    // SOLUTION: Replace with safe function fgets()
    if (fgets(buffer, sizeof(buffer), stdin) == NULL) {
        printf("Input Error\n");
        exit(1);
    }

    // VULNERABILITY: strcmp() can cause issues if strings are not properly null-terminated
    // if (strcmp(seceret, "COSE354") == 0){
    // SOLUTION: Use strncmp() with length limit 
    if (strncmp(seceret, "COSE354", sizeof(seceret)) == 0){
        printf("Please patch this code!\n");
    } else {
        printf("Try again!");
        exit(1);
    }
}

int main(){
    func();
    return 0;
}