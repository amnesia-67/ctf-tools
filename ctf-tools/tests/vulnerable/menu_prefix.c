/* The overflow is only reachable after a menu choice, to exercise --prefix. */
#include <stdio.h>
#include <stdlib.h>

void vuln(void) {
    char buf[72];
    gets(buf);
}

int main(void) {
    char choice[16];
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("1) overflow\n2) quit");
    if (!fgets(choice, sizeof(choice), stdin)) return 1;
    if (atoi(choice) == 1) vuln();
    else puts("bye");
    return 0;
}
