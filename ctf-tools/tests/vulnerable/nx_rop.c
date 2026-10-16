/* NX on, no canary, no PIE: a ROP target with useful gadgets. */
#include <stdio.h>
#include <unistd.h>

void gadgets(void) {
    /* pop rdi ; ret and friends, kept alive by the asm block */
    asm volatile(
        ".byte 0x5f, 0xc3\n"   /* pop rdi ; ret  */
        ".byte 0x5e, 0xc3\n"   /* pop rsi ; ret  */
        ".byte 0x5a, 0xc3\n"   /* pop rdx ; ret  */
        ".byte 0x58, 0xc3\n"   /* pop rax ; ret  */
        ".byte 0x0f, 0x05, 0xc3\n" /* syscall ; ret */
    );
}

void vuln(void) {
    char buf[80];
    read(0, buf, 400);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("rop me");
    vuln();
    return 0;
}
