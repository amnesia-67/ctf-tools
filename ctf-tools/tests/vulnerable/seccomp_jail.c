/* A seccomp sandbox built from a raw BPF filter: execve is killed, the
   open/read/write trio stays allowed.  Used to test seccompview. */
#include <stdio.h>
#include <unistd.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>

static void jail(void) {
    struct sock_filter code[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 4),              /* arch */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 0),              /* nr */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 59, 4, 0),      /* execve  */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 322, 3, 0),     /* execveat */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 56, 2, 0),      /* clone   */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 57, 1, 0),      /* fork    */
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
    };
    struct sock_fprog prog = { .len = sizeof(code) / sizeof(code[0]), .filter = code };

    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
}

void vuln(void) {
    char buf[64];
    gets(buf);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    jail();
    puts("jailed");
    vuln();
    return 0;
}
