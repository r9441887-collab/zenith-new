#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>
#include <limits.h>

static int cqsortCmp(const void* a, const void* b) {
    return *(const int*)a - *(const int*)b;
}

/* Plain C std-library exercise. Returns strlen(in) + number of chars printed. */
long stdall_c(const char* in) {
    size_t len = strlen(in);
    int total = (int)len;

    /* stdio via printf/snprintf/sprintf */
    char buf[128];
    snprintf(buf, sizeof(buf), "C got str=%s n=%d f=%.2f\n", in, (int)len, 3.14);
    total += (int)strlen(buf);

    /* atoi / strtol */
    total += atoi("  +7");
    total += (int)strtol("0x10", NULL, 16);

    /* abs / labs */
    total += abs(-5);
    total += (int)(labs(-60000000L) / 1000000);

    /* memcpy/memset/memcmp */
    char m1[16], m2[16];
    memset(m1, 0x41, 8); m1[8] = 0;
    memcpy(m2, m1, 9);
    total += memcmp(m1, m2, 9) == 0 ? 3 : 0;

    /* math.h */
    total += (int)round(2.4) + (int)floor(2.9) + (int)ceil(1.1);

    /* ctype */
    total += isalpha('A') ? 1 : 0;
    total += isdigit('5') ? 1 : 0;
    total += tolower('B') == 'b' ? 1 : 0;

    /* errno */
    errno = 0;
    (void)strtod("x", NULL);
    total += errno != 0 ? 1 : 0;

    /* time */
    time_t t = time(NULL);
    total += t > 0 ? 1 : 0;
    struct tm* tm = localtime(&t);
    total += tm != NULL ? 1 : 0;

    /* qsort */
    int arr[4] = {4, 2, 1, 3};
    qsort(arr, 4, sizeof(int), cqsortCmp);
    total += arr[0] == 1 && arr[3] == 4 ? 1 : 0;

    /* rand */
    total += rand() >= 0 ? 1 : 0;

    printf("C side: %s -> %d bytes incl format overhead = %ld\n", in, total,
           (long)(total + (int)strlen("%d") - 2));

    fflush(stdout);
    return (long)len + 12;
}