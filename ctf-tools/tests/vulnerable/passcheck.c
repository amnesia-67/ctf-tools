/* A check that has to be passed before the interesting branch: the kind of
   thing symwin is for. */
#include <stdio.h>
#include <string.h>

void win(void) { puts("flag{symbolic_execution}"); }

int main(void) {
    char buf[32];
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("password:");
    if (!fgets(buf, sizeof(buf), stdin)) return 1;

    if (buf[0] == 'c' && buf[1] == 't' && buf[2] == 'f' &&
        buf[3] == (char)('0' + 7) && buf[4] == 'w' && (buf[5] ^ 0x20) == 'N') {
        win();
    } else {
        puts("no");
    }
    return 0;
}
