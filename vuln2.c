// vuln2.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SIZE 30

/* =========================
 * 1) Dangerous function: gets
 *    -> cpp/dangerous-function-overflow
 * ========================= */
void echo_unsafe(void) {
    char buffer[16];

    // BAD: classic unbounded input into a fixed-size buffer
    gets(buffer);        // should be flagged as "Use of dangerous function"
    printf("You typed: %s\n", buffer);
}

/* =========================
 * 2) Static array overflow
 *    -> cpp/static-buffer-overflow
 * ========================= */
void print_array_bad(char *s) {
    char buf[20];        // smaller than SIZE

    // BAD: third argument uses SIZE (30) instead of sizeof(buf) (20)
    strncpy(buf, s, SIZE);

    // Another bad pattern: loop bound exceeds buf size
    for (int i = 0; i < SIZE; i++) {
        // reading past the end of buf when i >= 20
        putchar(buf[i]);
    }
    putchar('\n');
}

/* =========================
 * 3) Command line injection
 *    -> cpp/command-line-injection
 * ========================= */
void run_command_bad(const char *userName) {
    char command[128] = {0};

    // BAD: unsanitized user input inserted into command string
    // This pattern is adapted from the CodeQL docs for cpp/command-line-injection.
    sprintf(command, "userinfo -v \"%s\"", userName);
    system(command);
}

/* =========================
 * 4) Tainted format string
 *    -> cpp/tainted-format-string
 * ========================= */
void build_command(char *dest, size_t destSize, const char *userInput) {
    // BAD: use user input as the *format string* itself
    // This is what CodeQL already flags in your SARIF.
    sprintf(dest, userInput);
}

void read_name_and_build(void) {
    char name[64];
    char cmd[128];

    if (fgets(name, sizeof(name), stdin) == NULL) {
        return;
    }

    // Remove trailing newline for nicer output; not relevant to the vulnerability
    size_t len = strlen(name);
    if (len > 0 && name[len - 1] == '\n') {
        name[len - 1] = '\0';
    }

    build_command(cmd, sizeof(cmd), name);
    printf("Command string is: %s\n", cmd);
}

/* =========================
 * main: call all the bad examples
 * ========================= */
int main(int argc, char **argv) {
    printf("Demo: dangerous gets()\n");
    echo_unsafe();

    printf("\nDemo: static array overflow\n");
    print_array_bad("This is a long string that will overflow the buffer");

    if (argc > 1) {
        printf("\nDemo: command injection\n");
        run_command_bad(argv[1]);
    }

    printf("\nDemo: tainted format string\n");
    read_name_and_build();

    return 0;
}
