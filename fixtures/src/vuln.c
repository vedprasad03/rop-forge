#include <stdio.h>
#include <unistd.h>

void vulnerable(void) {
    char buf[64];
    read(0, buf, 256);
    printf("%s\n", buf);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    vulnerable();
    return 0;
}
