#include <stdio.h>

void vulnerable(void);

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    vulnerable();
    return 0;
}
