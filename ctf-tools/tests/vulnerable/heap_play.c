/* A small heap workout for heapscope: allocations of known sizes, a tcache
   with a known number of entries, and (with an argument) a double free. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    char *a = malloc(0x18);
    char *b = malloc(0x28);
    char *c = malloc(0x88);
    char *d = malloc(0x108);

    setvbuf(stdout, NULL, _IONBF, 0);
    strcpy(a, "first");
    strcpy(b, "second");
    strcpy(c, "third");
    strcpy(d, "fourth");

    free(a);
    free(b);                 /* two entries in two different tcache bins */

    if (argc > 1 && argv[1][0] == 'd') {
        free(b);             /* double free: tcache key check should catch it */
    }

    if (argc > 1 && argv[1][0] == 'p') {
        /* Tcache poisoning, as an exploit would leave it: two chunks in one
           bin, then the head's forward pointer overwritten with a non-heap
           address.  heapscope should see the bin is no longer sane. */
        char *x = malloc(0x48);
        char *y = malloc(0x48);
        free(x);
        free(y);
        *(unsigned long *)y = 0xdeadbeefUL;
    }

    puts("allocated");
    getchar();               /* hold here so the heap can be inspected */
    free(c);
    free(d);
    return 0;
}
