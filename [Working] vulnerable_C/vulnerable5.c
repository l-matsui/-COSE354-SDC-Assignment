#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>

typedef struct {
    int ticket_id;
    int available_seats;
    int total_sold;
    char event_name[50];
    // Add mutex to synchronize threads
    pthread_mutex_t mutex;
} TicketSystem;

TicketSystem concert = {
    .ticket_id = 1,
    .available_seats = 10,
    .total_sold = 0,
    .event_name = "SECURITY Concert",
    // Init mutex
    .mutex = PTHREAD_MUTEX_INITIALIZER
};

typedef struct {
    int user_id;
    char name[20];
} User;


void* book_ticket(void* arg) {
    User *user = (User*)arg;
    
    printf("[%s] Checking availability...\n", user->name);

    // VULNERABILITY: TOCTOU Race Condition
    // if (concert.available_seats > 0) {
    // SOLUTION: Use mutex
    pthread_mutex_lock(&concert.mutex);
    
    if (concert.available_seats > 0) {
        printf("[%s] Found available seat! Processing payment...\n", user->name);
        
        // VULNERABILITY: Critical section without protection
        // usleep(500000); 
        // concert.available_seats--;
        // concert.total_sold++;
        // SOLUTION: Keep this section inside mutex protection
        usleep(500000); // sim payment processing
        
        concert.available_seats--;
        concert.total_sold++;
        
        printf("[%s] ✓ Booking SUCCESS! Remaining seats: %d\n", user->name, concert.available_seats);
    } else {
        printf("[%s] ✗ SOLD OUT!\n", user->name);
    }
    
    // SOLUTION: Release mutex after critical section
    pthread_mutex_unlock(&concert.mutex);
    
    return NULL;
}

void print_info() {
    // SOLUTION: Protect read operations too just because
    pthread_mutex_lock(&concert.mutex);
    printf("Available Seats: %d\n", concert.available_seats);
    printf("Total Sold: %d\n", concert.total_sold);
    pthread_mutex_unlock(&concert.mutex);
}

int main() {
    pthread_t threads[20];
    User users[20];
    
    printf("=== Initial State ===\n");
    print_info();
    
    printf("Starting booking...\n\n");
    
    for (int i = 0; i < 20; i++) {
        users[i].user_id = i + 1;
        snprintf(users[i].name, sizeof(users[i].name), "User%02d", i + 1);
        pthread_create(&threads[i], NULL, book_ticket, &users[i]);
    }
    
    for (int i = 0; i < 20; i++) {
        pthread_join(threads[i], NULL);
    }
    
    printf("\n=== Final State ===\n");
    print_info();
    
    printf("Expected: 10 sold, 0 remaining\n");
    printf("Actual: %d sold, %d remaining\n", concert.total_sold, concert.available_seats);
    
    if (concert.total_sold > 10) {
        printf("\nOversold by %d tickets!\n", concert.total_sold - 10);
    }
    
    // SOLUTION: Destroy mutex when done
    pthread_mutex_destroy(&concert.mutex);
    
    return 0;
}