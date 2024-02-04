#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_SIZE 0x1000
#define ARR_SIZE 16

char *strs[ARR_SIZE];

void print_menu(void) {
    puts("1. str\n"
         "2. tok\n"
         "3. del\n"
         "4. exit\n");
}

unsigned long get_num(void) {
    char buf[16];
    read(STDIN_FILENO, buf, sizeof(buf));
    return strtoul(buf, NULL, 10);
}

int get_empty(void) {
    for (int i = 0; i < ARR_SIZE; i++) {
        if (strs[i] == NULL) {
            return i;
        }
    }
    return -1;
}

void do_str(void) {
    int idx = get_empty();
    if (idx == -1) {
        puts("too many!");
        return;
    }
    printf("size? ");
    unsigned long size = get_num();
    if (size > MAX_SIZE) {
        puts("too big!");
        return;
    }
    strs[idx] = malloc(size);
    if (strs[idx] == NULL) {
        puts("no mem!");
        return;
    }
    printf("str? ");
    read(STDIN_FILENO, strs[idx], size);
    printf("stored at %d!\n", idx);
}

void do_tok(void) {
    printf("idx? ");
    unsigned long idx = get_num();
    if (idx >= ARR_SIZE) {
        puts("too big!");
        return;
    }
    char *str = strs[idx];
    if (str == NULL) {
        puts("empty!");
        return;
    }
    printf("delim? ");
    char delim[2];
    read(STDIN_FILENO, delim, sizeof(delim));
    delim[1] = '\0';
    for (char *tok = strtok(str, delim); tok != NULL; tok = strtok(NULL, delim)) {
        puts(tok);
    }
}

void do_del(void) {
    printf("idx? ");
    unsigned long idx = get_num();
    if (idx >= ARR_SIZE) {
        puts("too big!");
        return;
    }
    char *str = strs[idx];
    if (str == NULL) {
        puts("empty!");
        return;
    }
    free(str);
    strs[idx] = NULL;
}

int main(void) {
    setbuf(stdout, NULL);

    while (1) {
        print_menu();
        printf("> ");
        unsigned long choice = get_num();
        switch (choice) {
            case 1:
                do_str();
                break;
            case 2:
                do_tok();
                break;
            case 3:
                do_del();
                break;
            case 4:
                return 0;
            default:
                puts("??");
                break;
        }
    }
}
