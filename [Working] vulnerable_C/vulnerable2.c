#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void func1(){
    char buffer[8];
    int i = 0;
    char c;
    
    printf("Enter Input : ");
    
    // VULNERABILITY: No bounds checking in while loop can lead to Buffer Overflow
    // while((c = getchar()) != '\n' && c != EOF) {
    // SOLUTION: Add bounds checking
    while(i < sizeof(buffer) - 1 && (c = getchar()) != '\n' && c != EOF) {
        buffer[i++] = c;
    }
    buffer[i] = '\0';
    
    printf("Input : %s\n", buffer);
}

void func2(){
    char buffer[8];
    char input[10];
    
    printf("Enter Input : ");
    fgets(input, sizeof(input), stdin);
    
    // VULNERABILITY: vulnerable function sprintf() to Buffer Overflow
    // sprintf(buffer, "User input: %s", input);
    // SOLUTION: Use safe function snprintf() instead with bounds checking
    snprintf(buffer, sizeof(buffer), "User input: %s", input);
    
    printf("Input : %s\n", buffer);
}

void func3(){
    char buffer[8];
    char input[10];
    
    printf("Enter Input : ");
    // VULNERABILITY: scanf("%s") without length limit vulnerable to Buffer Overflow
    // scanf("%s",input);
    // SOLUTION: Use scanf() with field width specifier
    scanf("%9s", input);
    
    // VULNERABILITY: vulnerable function strcpy() to Buffer Overflow
    // strcpy(buffer, input);
    // SOLUTION: Use safe function strncpy() with length limit
    strncpy(buffer, input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';
    
    printf("Copied : %s\n", buffer);
}

int main(){
    func1();
    func2();
    func3();
    return 0;
}