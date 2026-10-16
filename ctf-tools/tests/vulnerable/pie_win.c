/* PIE enabled: addresses need a leak before they can be used. */
#include <stdio.h>

void win(void) { puts("flag{pie_win}"); }

void vuln(void) {
    char buf[56];
    gets(buf);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    vuln();
    return 0;
}
