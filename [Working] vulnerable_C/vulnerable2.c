#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void func1(){
    char buffer[8];
    int i = 0;
    char c;
    
    printf("Enter Input : ");
    
    while((c = getchar()) != '\n' && c != EOF) {
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
    
    sprintf(buffer, "User input: %s", input);
    
    printf("Input : %s\n", buffer);
}
void func3(){
    char buffer[8];
    char input[10];
    
    printf("Enter Input : ");
    scanf("%s",input);
    
    strcpy(buffer, input);
    
    printf("Copied : %s\n", buffer);
}

int main(){
    func1();
    func2();
    func3();
    return 0;
}