#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* Smoke target: triggers a stack overflow on inputs starting with "CRASH". */
int main(void) {
    char buf[64];
    ssize_t n = read(0, buf, 4096);
    if (n >= 5 && memcmp(buf, "CRASH", 5) == 0) {
        char small[8];
        memcpy(small, buf, (size_t)n);
        return small[0];
    }
    return 0;
}
