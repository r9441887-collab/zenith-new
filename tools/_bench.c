/* Точная транслитерация tools/_bench.z на C (только синтаксис отличается).
 *
 * Семантика Zenith -> C:
 *   - Zenith int        = int64_t (64-бит знаковый);
 *   - peek32/poke32     = чтение/запись int32_t (как movsxd/трunc в кодогене);
 *   - переполнение +/-/* = усечение по модулю 2^64 -> пересчёт через
 *     uint64_t (в C знаковый overflow — UB, тут wrap определён);
 *   - <<                = сдвиг битов с усечением до 64 (через uint64_t);
 *   - >>                = ЛОГИЧЕСКИЙ (семантика языка Zenith);
 *   - /,%               = знаковые (idiv с усечением к нулю) — как
 *     в генерируемом x86-коде Zenith;
 *   - alloc/free        = malloc/free.
 * Чекcумма ДОЛЖНА совпадать с selfhost-бинарником (1212461888).
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

typedef int64_t zint;

#define MADD(a, b) ((zint)((uint64_t)(a) + (uint64_t)(b)))
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
    zint r = 0;                       /* в _bench.z r — и счетчик строк, и seed чекcуммы */
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
    i = 0;
    while (i < sz) {
        poke32((char *)c + i * 4, peek32((char *)c + i * 4) & 65535);
        i = i + 1;
    }
    i = 0;
    while (i < sz) {
        r = (zint)(((uint64_t)r * 1664525u + 1013904223u +
                    (uint64_t)peek32((char *)c + i * 4)) & 2147483647u);
        i = i + 1;
    }
    free(a);
    free(b);
    free(c);
    return r;
}

static zint hashLoop(zint n)
{
    zint x = 0x12345678;
    zint i = 0;
    zint s = 0;
    while (i < n) {
        x = (zint)((uint64_t)x ^ (uint64_t)MSHL(x, 13));
        x = (zint)((uint64_t)x ^ (uint64_t)((uint64_t)x >> 7));
        x = (zint)((uint64_t)x ^ (uint64_t)MSHL(x, 17));
        x = x & 2147483647;
        s = (zint)(((uint64_t)s + (uint64_t)MMUL(x, i + 1)) & 2147483647u);
        zint y = i * 3;
        zint z = i * 5;
        zint w = (i * 9) & 65535;
        s = (zint)(((uint64_t)s + (uint64_t)(y + z + w) +
                    (uint64_t)(i / 8) + (uint64_t)(i % 8)) & 2147483647u);
        i = i + 1;
    }
    return s;
}

int main(void)
{
    zint total = 0;
    zint round = 0;
    while (round < 6) {
        total = (zint)(((uint64_t)total +
                        (uint64_t)matmulChecksum(24) +
                        (uint64_t)hashLoop(300000)) & 2147483647u);
        round = round + 1;
    }
    printf("%lld\n", (long long)total);
    return 0;
}
