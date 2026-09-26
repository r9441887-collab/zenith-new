#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

/* Functions called from the .z side, plus direct libc/libm calls from inside
   C so the mixer must route printf/malloc/strlen/pow to the right soname. */

static int g_counter = 0;

int mixc_increment(void) {
    g_counter++;
    return g_counter;
}

int mixc_roundtrip(int x) {
    return x * 2 + 1;
}

float mixc_power(float base, float exp) {
    return (float)pow((double)base, (double)exp);
}

const char* mixc_greeting(void) {
    static char buf[256];
    strcpy(buf, "hello from C mix");
    return buf;
}

int mixc_stdlib_use(void) {
    char* p = (char*)malloc(16);
    if (!p) return -1;
    memcpy(p, "mix-stdlib", 10);
    int n = (int)strlen(p);
    free(p);
    return n;
}

int mixc_stdio_use(const char* s) {
    printf("C says: %s, counter=%d, pow=%.2f\n", s, mixc_increment(), mixc_power(2.0f, 8.0f));
    fflush(stdout);
    return 0;
}