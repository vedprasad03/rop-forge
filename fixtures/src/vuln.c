#include <stdio.h>
#include <unistd.h>

void vulnerable(void) {
    char buf[64];
    read(0, buf, 256);
    printf("%s\n", buf);
}
