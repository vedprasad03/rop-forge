// Forking TCP server harness around vulnerable() — Phase 5's leak primitive
// needs two interactions against the *same* address space (leak, then
// strike), and vulnerable() itself only ever calls read() once per process.
// fork() never re-randomizes ASLR, so every child spawned by this one
// long-lived, real-ASLR'd parent shares its exact memory layout — matching
// how real leak-based exploits target persistent/forking network services.
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

void vulnerable(void);

int main(void) {
    // Auto-reap children — this harness never waits on them explicitly.
    signal(SIGCHLD, SIG_IGN);

    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        perror("socket");
        return 1;
    }

    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0; // let the OS pick an ephemeral port

    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return 1;
    }

    socklen_t addr_len = sizeof(addr);
    if (getsockname(listen_fd, (struct sockaddr *)&addr, &addr_len) < 0) {
        perror("getsockname");
        return 1;
    }
    // The one line callers read to learn which port to connect to.
    printf("PORT %d\n", ntohs(addr.sin_port));
    fflush(stdout);

    if (listen(listen_fd, 16) < 0) {
        perror("listen");
        return 1;
    }

    for (;;) {
        int client_fd = accept(listen_fd, NULL, NULL);
        if (client_fd < 0) {
            continue;
        }

        pid_t pid = fork();
        if (pid == 0) {
            close(listen_fd);
            dup2(client_fd, 0);
            dup2(client_fd, 1);
            close(client_fd);
            // stdout is now the client socket, not a tty — glibc defaults
            // to full buffering there, which would hold the leak/echo back
            // even across a crash. Match standalone_main.c's own explicit
            // unbuffering so vulnerable()'s printf() actually reaches the
            // client before the process dies.
            setvbuf(stdout, NULL, _IONBF, 0);
            vulnerable();
            _exit(0);
        }
        close(client_fd);
    }
    return 0;
}
