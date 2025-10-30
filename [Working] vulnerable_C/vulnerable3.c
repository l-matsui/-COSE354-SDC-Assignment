#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>

typedef struct {
    uint32_t id;
    uint32_t balance;
} Account;

static void show(const Account *a){
     printf("[Account %" PRIu32 "] balance=%" PRIu32 " cents\n", a->id, a->balance);
}

int deposit(Account *a, uint32_t amount){
    if((int32_t)amount < 0) return -1;
    // VULNERABILITY: unsigned addition can lead to Integer Overflow 
    // a->balance += amount;
    // SOLUTION: check for overflow before addition
    if (a->balance > UINT32_MAX - amount) {
        return -2; // Overflow
    }
    a->balance += amount;
    return 0;
}

int withdraw(Account *a, int32_t amount){
    if (amount <= 0) return -1;
    // VULNERABILITY: unsigned subtraction can lead to Integer Underflow
    // uint32_t new_balance = a->balance - amount;
    // SOLUTION: check for underflow before subtraction
    if (a->balance < (uint32_t)amount) {
        return -2; // Underflow
    }
    uint32_t new_balance = a->balance - amount;
    // now redundant check
    // if (new_balance < 0) return -2;
    a->balance = new_balance;
    return 0; 
}

int adjust(Account *a, int32_t delta){
    // VULNERABILITY: Signed to unsigned conversion can lead to Integer Overflow/Underflow
    // uint32_t new_balance = a->balance + delta;
    if (delta >= 0) {
        // SOLUTION: Check for overflow
        if (a->balance > UINT32_MAX - (uint32_t)delta) {
            return -1; // Overflow
        }
    } else {
        // SOLUTION: Check for underflow  
        if (a->balance < (uint32_t)(-delta)) {
            return -2; // Underflow
        }
    }
    uint32_t new_balance = a->balance + delta;
    a->balance = new_balance;
    return 0;
}

int main(){
    Account a = { .id =1, .balance = 1000 };
    
    a.balance = 4294967290;
    show(&a);
    if(deposit(&a, 10)==0){
        printf("Success!\n");
        show(&a);
    } else {
        printf("Deposit failed - overflow prevented!\n");
    }
    printf("\n");
    
    a.balance = 100;
    show(&a);
    if(withdraw(&a, 500) == 0){
        printf("Success!\n");
        show(&a);
    } else {
        printf("Withdraw failed - underflow prevented!\n");
    }
    printf("\n");

    a.balance = 1000;
    show(&a);
    if(adjust(&a, -2000) == 0){
        printf("Success!\n");
        show(&a);
    } else {
        printf("Adjust failed - underflow prevented!\n");
    }
    
    return 0;
}