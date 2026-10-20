/* Точная транслитерация tools/_speedbench.z на C (см. _bench.c по семантике:
 * Zenith int = int64_t, peek32/poke32 = int32_t, wrap через uint64_t,
 * >> = ЛОГИЧЕСКИЙ (как в языке Zenith: 06_операторы.txt), /,% = знаковые idiv).
 * Чекcумма ДОЛЖНА совпадать с selfhost (1631065533).
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

typedef int64_t zint;

#define MADD(a, b) ((zint)((uint64_t)(a) + (uint64_t)(b)))
#define MSUB(a, b) ((zint)((uint64_t)(a) - (uint64_t)(b)))
#define MMUL(a, b) ((zint)((uint64_t)(a) * (uint64_t)(b)))
#define MSHL(a, n) ((zint)((uint64_t)(a) << (n)))

static inline void poke32(void *p, zint v) { *(int32_t *)p = (int32_t)v; }
static inline zint peek32(const void *p)   { return (zint)*(const int32_t *)p; }

static void *zalloc(zint n)
{
    void *p = malloc((size_t)n);
    if (!p) abort();
    return p;
}

static zint mix(zint a, zint b)
{
    zint x = a;
    zint y = b;
    x = (zint)((uint64_t)x ^ (uint64_t)MSHL(x, 13));
    x = (zint)((uint64_t)x ^ (uint64_t)((uint64_t)x >> 7));
    x = (zint)((uint64_t)x ^ (uint64_t)MSHL(x, 17));
    zint s = 0;
    zint i = 0;
    while (i < 64) {
        x = (zint)((uint64_t)x ^ (uint64_t)MSHL(x, 13));
        x = (zint)((uint64_t)x ^ (uint64_t)((uint64_t)x >> 7));
        x = (zint)((uint64_t)x ^ (uint64_t)MSHL(x, 17));
        s = MADD(s, (x & 255) + (x / 7) + (x % 11) + (x * 3) +
                    (x / 8) + (x % 16) + (x * 5));
        s = MADD(s, ((uint64_t)x >> 3) + MSHL(x, 2));
        s = MSUB(s, x / 13);
        i = i + 1;
    }
    return (zint)((uint64_t)s ^ (uint64_t)x);
}

static zint matmul(zint n, zint seed)
{
    zint sz = n * n;
    void *a = zalloc(sz * 4);
    void *b = zalloc(sz * 4);
    void *c = zalloc(sz * 4);
    zint i = 0;
    while (i < sz) {
        poke32((char *)a + i * 4, (i * 7 + seed) % 251);
        poke32((char *)b + i * 4, (i * 13 + seed * 3) % 241);
        poke32((char *)c + i * 4, 0);
        i = i + 1;
    }
    zint acc = 0;
    zint r = 0;
    while (r < n) {
        zint cc = 0;
        while (cc < n) {
            zint k = 0;
            zint sum = 0;
            while (k < n) {
                sum = MADD(sum, MMUL(peek32((char *)a + (r * n + k) * 4),
                                     peek32((char *)b + (k * n + cc) * 4)));
                k = k + 1;
            }
            poke32((char *)c + (r * n + cc) * 4, sum);
            acc = MADD(acc, sum & 65535);
            cc = cc + 1;
        }
        r = r + 1;
    }
    free(a);
    free(b);
    free(c);
    return acc & 2147483647;
}

int main(void)
{
    zint total = 0;
    zint round = 0;
    while (round < 8) {
        total = (zint)(((uint64_t)total +
                        (uint64_t)matmul(56, round + 1) +
                        (uint64_t)mix(round * 2654435761, round + 7)) & 2147483647u);
        round = round + 1;
    }
    printf("%lld\n", (long long)total);
    return 0;
}
