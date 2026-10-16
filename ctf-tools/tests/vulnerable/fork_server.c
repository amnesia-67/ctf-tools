/* A forking TCP server with a canary-protected overflow: every connection
   gets a fresh child, but all children share the parent's canary, which is
   what makes a byte-by-byte brute force possible.  Used to test canbrute. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>

static void handle(int fd) {
    char buf[64];
    ssize_t n;

    dup2(fd, 0);
    dup2(fd, 1);
    dup2(fd, 2);
    write(fd, "go\n", 3);
    n = read(fd, buf, 200);          /* overflow: 200 bytes into 64 */
    (void)n;
}

int main(int argc, char **argv) {
    int port = argc > 1 ? atoi(argv[1]) : 9999;
    int server = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    int one = 1;

    signal(SIGCHLD, SIG_IGN);
    setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);

    if (bind(server, (struct sockaddr *)&addr, sizeof(addr)) < 0) { perror("bind"); return 1; }
    listen(server, 16);
    fprintf(stderr, "listening on %d\n", port);
    fflush(stderr);

    for (;;) {
        int client = accept(server, NULL, NULL);
        if (client < 0) continue;
        if (fork() == 0) {
            close(server);
            handle(client);
            /* Written only if handle() returned, i.e. the canary survived. */
            write(client, "ok\n", 3);
            close(client);
            _exit(0);
        }
        close(client);
    }
}
