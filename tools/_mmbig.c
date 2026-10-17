/* Точная транслитерация /tmp/mm_big.z на C (чистый матмул n=128 x40 раундов).
 * Чекcумма ДОЛЖНА совпадать с selfhost (1257912473520).
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

typedef int64_t zint;

#define MADD(a, b) ((zint)((uint64_t)(a) + (uint64_t)(b)))
#define MMUL(a, b) ((zint)((uint64_t)(a) * (uint64_t)(b)))

static inline void poke32(void *p, zint v) { *(int32_t *)p = (int32_t)v; }
static inline zint peek32(const void *p)   { return (zint)*(const int32_t *)p; }

static void *zalloc(zint n)
{
    void *p = malloc((size_t)n);
    if (!p) abort();
    return p;
}

static zint matmulChecksum(zint n)
{
    zint sz = n * n;
    void *a = zalloc(sz * 4);
    void *b = zalloc(sz * 4);
    void *c = zalloc(sz * 4);
    zint i = 0;
    while (i < sz) {
        poke32((char *)a + i * 4, (i * 7 + 3) % 251);
        poke32((char *)b + i * 4, (i * 13 + 5) % 241);
        poke32((char *)c + i * 4, 0);
        i = i + 1;
    }
    zint r = 0;
    while (r < n) {
        zint cc = 0;
        while (cc < n) {
            zint acc = 0;
            zint k = 0;
            while (k < n) {
                acc = MADD(acc, MMUL(peek32((char *)a + (r * n + k) * 4),
                                     peek32((char *)b + (k * n + cc) * 4)));
                k = k + 1;
            }
            poke32((char *)c + (r * n + cc) * 4, acc);
            cc = cc + 1;
        }
        r = r + 1;
    }
    zint s = 0;
    i = 0;
    while (i < sz) {
        s = MADD(s, peek32((char *)c + i * 4));
        i = i + 1;
    }
    free(a);
    free(b);
    free(c);
    return s;
}

int main(void)
{
    zint total = 0;
    zint round = 0;
    while (round < 40) {
        total = MADD(total, matmulChecksum(128));
        round = round + 1;
    }
    printf("%lld\n", (long long)total);
    return 0;
}
