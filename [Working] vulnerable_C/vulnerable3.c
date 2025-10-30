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
	  a->balance += amount;
	  return 0;
}

int withdraw(Account *a, int32_t amount){
    if (amount <= 0) return -1;
    uint32_t new_balance = a->balance - amount;
    if (new_balance < 0) return -2;
    a->balance = new_balance;
    return 0; 
}

int adjust(Account *a, int32_t delta){
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
    }
    printf("\n");
    a.balance = 100;
    show(&a);
    if(withdraw(&a, 500) == 0){
        printf("Success!\n");
        show(&a);
    }
    printf("\n");

    a.balance = 1000;
    show(&a);
    if(adjust(&a, -2000) == 0){
        printf("Success!\n");
        show(&a);
    }
    
    return 0;
}