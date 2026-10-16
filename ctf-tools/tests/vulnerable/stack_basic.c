/* Plain stack overflow: 64 byte buffer, gets, no canary, no PIE. */
#include <stdio.h>

void vuln(void) {
    char buf[64];
    puts("input:");
    gets(buf);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    vuln();
    puts("done");
    return 0;
}
