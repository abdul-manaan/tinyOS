/*
 * Copyright (c) 2025 Abdul Manan
 * File created: 2025-01-19--18:19:24
 * Last modified: 2025-02-08--23:28:59
 * All rights reserved.
 */


#include "user.h"

void main(void) {
    uint32_t pid = getPID();
    while (1) {
prompt:
        printf("%d > ",pid);
        char cmdline[128];
        for (int i = 0;; i++) {
            char ch = getchar();
            putchar(ch);
            if (i == sizeof(cmdline) - 1) {
                printf("command line too long\n");
                goto prompt;
            } else if (ch == '\r') {
                printf("\n");
                cmdline[i] = '\0';
                break;
            } else {
                cmdline[i] = ch;
            }
        }

        if (strcmp(cmdline, "hello") == 0)
            printf("Hello world from tinyOS shell!\n");
        else if (strcmp(cmdline, "exit") == 0)
            exit();
        else if (strcmp(cmdline, "readfile") == 0) {
            char buf[128];
            int len = readfile("./hello.txt", buf, sizeof(buf));
            buf[len] = '\0';
            printf("%s\n", buf);
        }
        else if (strcmp(cmdline, "writefile") == 0)
            writefile("./hello.txt", "Hello from shell!\n", 19);
        else if (strcmp(cmdline, "help") == 0) {
            printf("Following commands are available: \n");
            printf("\tfreemem \n");
            printf("\thelp \n");
            printf("\treadfile \n");
            printf("\tuptime \n");
            printf("\twritefile \n\n");
        }
        else if (strcmp(cmdline, "freemem") == 0)
            printf("OS has free mem: %d MB\n", freemem()/1024);
        else if (strcmp(cmdline, "uptime") == 0)
            printf("OS Uptime: %d\n", uptime());
        else if (strcmp(cmdline, "fork") == 0)
            printf("Forked PID: %d\n", fork());
        else
            printf("unknown command: %s\n", cmdline);
    }
}