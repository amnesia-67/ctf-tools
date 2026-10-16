/* Same overflow, but the canary aborts before the return address is used. */
#include <stdio.h>

void win(void) { puts("flag{canary_bypassed}"); }

void vuln(void) {
    char buf[48];
    puts("guarded:");
    gets(buf);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    vuln();
    return 0;
}
