/* A correctly bounded read: there is no overflow here. */
#include <stdio.h>
#include <unistd.h>

void vuln(void) {
    char buf[64];
    read(0, buf, 32);
    printf("got %s", buf);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    vuln();
    return 0;
}
