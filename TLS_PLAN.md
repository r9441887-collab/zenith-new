# TLS/HTTPS — план работ (конспект сессии)

## Цель
Свой TLS-стек на чистых сокетах (без SChannel/wininet/крипто-библиотек Windows):
реальное шифрование, совместимое с браузерами. Серверы/БД — HTTP (wininet `http_get` уже есть).
Только `ws2_32.dll` для TCP.

## Состояние
- ✅ Фаза звука (8 builtin, 3 bitdepth, 5 волн, mix, waveOut) — проверено под wine, docs `20_звук.txt`.
- ✅ Задача согласована: вариант «Свой TLS на чистых сокетах».
- ✅ **Blob-инфраструктура готова и проверена** (см. раздел «Сделано»).
- ✅ **Криптоядро**: SHA-256/HMAC/PRF, AES-128/GCM, GHASH, P-256 ECDHE — реализовано и сверено с OpenSSL/NIST.
- 🚧 Осталось: bigint 2048/RSA, X.509 parser, handshake + record layer, codegen_tls.cpp.

## Сделано (проверено!)

### Blob-инфраструктура (tools/)
| Файл | Назначение |
|---|---|
| `tools/gen_tls_blob.sh` | сборка: gcc -ffreestanding -fno-pic → ld (VMA 0) → objcopy -O binary → генерит `src/tls_blob.h` (байты + offsets) |
| `tools/tlsrt.ld` | linker script: .text/.rodata/.data/.bss подряд от VMA 0 |
| `tools/tlsrt.h` | ABI: меняются только registers rdi..r9 (SysV), result в rax |
| `tools/tlsrt.c` | криптоядро (freestanding C, без libc, без red zone) |
| `tools/tlsrt.s` | asm-стабы SysV→Win64 для send/recv/closesocket (уходят в io-таблицу) |
| `tools/blob_smoke.cpp` | host-тест: mappит байты blob→exec память, вызывает entry |
| `tools/blob_direct.cpp` | host-тест: линкует tlsrt.c напрямую |

### Проверено
- SHA-256: пустой + "abc" ✅; полные дивпендещие тесты длин 1..200 ✅
- HMAC-SHA256 RFC 4231 #1 ✅
- TLS 1.2 PRF (P_SHA256) вектор ✅
- AES-128-GCM: NIST SP 800-38D TC1/TC2 + OpenSSL-векторы (AAD/длина: 0/16/64/39/257 байт pt, aad до 40), round-trip ✅
  - GCM_DEC: плохой тег → -1, aad_len > 256 → -2 ✅
- P-256 ECDHE: полный обмен сверен с OpenSSL (priv=0x11…/0x22… → shared `ccfc261f…`), priv=1 → базовая точка G ✅
- Blob layout: RIP-relative ссылки валидны; `blob_smoke` (mmap) и `blob_direct` (прямая линковка) — ALL OK ✅

## Остаток по шагам

### Шаг 1 — отладить blob smoke (mmap crash) ✅
- Причина: рассинхрон `kTlsBlobSize`/offset-таблицы с реальными байтами после регенерации.
- Решено: `gen_tls_blob.sh` обновляет `src/tls_blob.h` целиком (байты + entry/offsets + size).
  `blob_smoke` + `blob_direct` оба проходят; регенерация обязательна после каждой правки `tlsrt.c`.

### Шаг 2 — AES-128 + GHASH + AES-GCM ✅
- В `tlsrt.c`: key expansion, encrypt block, GHASH (GF(2^128), mul), GCM enc/dec + tag.
- Контракт опов: `pkt = [iv:12][aad_len:u16 LE][aad][tag:16]` (`TLS_GCM_PKT_SIZE=286`,
  `TLS_GCM_MAX_AAD=256`); GCM_ENC пишет tag обратно в pkt; GCM_DEC: 0/-1/-2.
- Тест: NIST + OpenSSL-векторы в `blob_smoke`/`blob_direct` ✅

### Шаг 3 — Bigint 2048 + RSA verify
- Позиций-независимый bigint (montgomery modpow), 2048 bit.
- RSA verify PKCS#1 v1.5 SHA-256 (нужен для подписи ServerKeyExchange; + подписи сертов цепочки).
- Тест: сгенерить ssl key/self-signed cert openssl, экспортировать (n,e, sig) в JSON, сверить.

### Шаг 4 — P-256 ECDHE ✅
- Field arith mod p256 (secp256r1), point add/double/smul, keygen, shared secret.
- Скаляры — **big-endian** 32 байта (byte 0 = MSB); координаты точек — affine X|Y по 32.
- Тест: RFC-вектор/openssl pkeyutl — эталон shared `ccfc261f…` для priv 0x11…/0x22… ✅

### Шаг 5 — X.509 DER parser
- parse leaf cert: TBS → subjectPublicKeyInfo (RSA n,e), issuer/subject.
- Extract CA fingerprint hash (SHA-256 of DER) — для пиннинга.

### Шаг 6 — TLS 1.2 handshake (в blob)
- ClientHello → ServerHello → Certificate → ServerKeyExchange → ServerHelloDone.
- Verify ECDSA/RSA подпись SKX по client.random+server.random+params.
- ClientKeyExchange + ChangeCipherSpec + Finished (client/server) — verify_data PRF.
- Cipher: ECDHE-RSA-AES128-GCM-SHA256 (0xC02F).

### Шаг 7 — Record layer (в blob)
- AES-GCM enc/dec records (+ seq numbers, nonce=writerIV||seq).
- App-data: tls_send / tls_recv (buffering через под-записи).
- (CBC+HMAC-MAC режимы — опционально позже.)

### Шаг 8 — Cert/CA hash pinning
- Посчитать SHA-256 левого серта; сравнить с вшитым в blob списком ключевых хэшей CA.
- Default: доверять цепочке/self-signed? Решить политику (или вшитый отпечаток конкретного CA, напр. Let's Encrypt).

### Шаг 9 — Host-side E2E против openssl s_server
- Локальный `openssl s_server` (TLS1.2 ECDHE-RSA-AES128-GCM).
- Smoke test: socket → posix send/recv через io-таблицу → рукопожатие+GET через blob.
- Это проверяет всё без винды.

### Шаг 10 — codegen_tls.cpp (мост в языке)
- `codegen_tls.cpp`: tryTlsCall() для `tls_connect/tls_send/tls_recv/tls_close/tls_last_error`.
- Излучает blob-байты в .text (emitBlob) + `call rel32` в entry.
- io-таблица: скопировать send/recv/closesocket из IAT (externFuncMap→iatRVA) в .data слоты.
- Реестрировать в codegen.cpp (порядок - net_* до text/import обработки), PE импорты ws2_32.
- Обновить DEV_STATE.md build command: + codegen_tls.cpp.

### Шаг 11 — Тесты .z под wine
- https_test.z (уже есть) против локального `openssl s_server` на loopback
  (внешняя сеть под torsocks блокируется: `recvmsg: Отказано в доступе`).
- Если wine-socket снова блок → тестировать на реальном Windows или через localhost-костыль.

### Шаг 12 — docs `21_tls.txt`
- API, ограничения (chain-of-trust/pinning политика), cipher, примеры.

## Ключевые решения/факты (не потерять)
- Blob: ELF PIE → custom ld (VMA 0) → objcopy -O binary. `mingw ld --oformat binary` НЕ работает (PE limit).
- Внутри blob SysV (Linux-ABI). Стабы SysV→Win64 в .s читают fnptr из BSS (io-таблица).
- io-таблица заполняется кодгеном из PE IAT (`externFuncMap {func→{dll,iatRVA}}`).
- Helper emission паттерн: `emitLabel(httpJsonHelperLabel)` + `call rel32` через jmpFixups(=0xE8).
- `tls_*` builtin имена без точек (лексер: только isalnum/_).
- Структуры: `ImportCallFixup{codePos,funcName,dllName}`, `resolveFixups` в codegen_pe.cpp (~1610).
- wine networking блокируется torsocks — тесты сети только loopback или наст. Windows.

## Команды
- Сборка blob: `bash tools/gen_tls_blob.sh`
- Host smoke: `g++ -O2 -std=c++17 -I src tools/blob_smoke.cpp -o /tmp/smoke && /tmp/smoke`
- Direct: `g++ -O2 -std=c++17 -Isrc tools/blob_direct.cpp -o /tmp/direct tools/tlsrt.c tools/tlsrt.s -ffreestanding` (см. шаблон `/tmp/opencode/build_tls.sh`)
- Компилятор: `x86_64-w64-mingw32-g++ -O2 -std=c++17 -w -static src/*.cpp -o build/zenith.exe`
- Тест: `wine build/zenith.exe https_test.z | grep -v torsocks | grep -v err:winediag`