/* Classic ret2win: an unreachable function the exploit must return into. */
#include <stdio.h>
#include <stdlib.h>

void win(void) {
    puts("flag{ret2win_reached}");
    fflush(stdout);
    _exit(0);
}

void vuln(void) {
    char buf[40];
    puts("say something:");
    gets(buf);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    vuln();
    return 0;
}
