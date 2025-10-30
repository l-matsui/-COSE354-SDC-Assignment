#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <syslog.h>


void log_user_input(const char *input){
    FILE *f = fopen("log.txt","at");
    if(f){
        fprintf(f, input);
        fprintf(f,"\n");
        fclose(f);
    }
    openlog("log", LOG_PID | LOG_CONS, LOG_USER);
    syslog(LOG_INFO, input);
    closelog();
}

int main(int argc, char *argv[]) {
    if (argc != 2){
        fprintf(stderr, "Usage: %s <message>\n", argv[0]);
        return 1;
    }
    const char *msg = argv[1];
    log_user_input(msg);
    
    return 0;
    
}