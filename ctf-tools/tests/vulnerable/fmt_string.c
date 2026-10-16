/* Format string: the input is used as the format argument.  Two rounds, so a
   %n write can be made and then observed. */
#include <stdio.h>

int target = 0;

void vuln(void) {
    char buf[128];
    for (int round = 0; round < 2; round++) {
        if (!fgets(buf, sizeof(buf), stdin)) break;
        printf(buf);
        puts("");
    }
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    vuln();
    printf("target=%#x\n", target);
    if (target == 0xdeadbeef) puts("flag{format_write}");
    return 0;
}
