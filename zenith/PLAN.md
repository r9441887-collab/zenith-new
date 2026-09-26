# План: ask-семантика + редиректы + куки + HTTP/HTTPS-сервер на зените

## Решения заказчика (подтверждено в чате)
- **ask**: спрашивать у СЕРВЕРА, не у пользователя. Пользователь пишет точное имя файла (в кавычках).
  - Файл не найден на сервере → 404 → возврат `-5`, ничего не качаем («и всё»).
  - Файл найден → скачиваем «всё, что там было») из листинга папки, НО без выбранного файла.
- **Редиректы**: поддержка минимум до 6 (сейчас 3).
- **Куки**: добавить поддержку.
- **Сервер**: делать на зените (не python!), только `app linux`, и HTTP, и HTTPS.
- Остальное (спид-промпт `http_download_speed`, терминальный y/n) НЕ трогаем.

## Что делать

### 1. Переработка `http_download_ask(url, file)` — Linux-блоб (tools/httpdl.c, op 2)
- url = URL папки (база), file = имя исключаемого файла.
- Шаг A. Probe: `GET <base>/<file>` (или HEAD). Если статус 404 → вернуть `-5`, закрыть.
- Шаг B. `GET <base>/` — листинг (autoindex HTML в стиле python http.server: `<pre><a href="имя">имя</a>`).
- Шаг C. Распарсить `<a href="...">`, отфильтровать сам исключаемый файл и поддиректории (трайл-слеш).
- Шаг D. Каждый остальной файл: `GET <base>/<имя>`, сохранить в cwd под его именем (basename).
- Куки/редиректы должны работать на каждом из запросов.

### 2. Редиректы до 6 + куки (tools/httpdl.c, Linux)
- `HTTP_REDIR_MAX` 3 → 6.
- Cookie jar:
  - хранить пару (name=value) из `Set-Cookie:` (первая часть до `;`);
  - слать `Cookie: n1=v1; n2=v2` на последующие запросы на этот хост (и на redirects в пределах того же хоста);
  - переиспользовать jar между запросами внутри одной операции ask.
- header-парсер: добавить разбор `Set-Cookie`.
- build_request: добавить метод (GET/HEAD) и хук для Cookie-заголовка.

### 3. HTTP/HTTPS-сервер на зените (новый builtin, только `app linux`)
- Имя: `http_server(port)` — HTTP; `http_server(port, cert, key)` — HTTPS (cert.pem/key.pem).
- Блокирующий цикл: bind(0.0.0.0, port) → listen → accept → обработать соединение → закрыть.
- Ответы:
  - HEAD/GET `/` → autoindex HTML (как python http.server).
  - GET `/имя` → файл: `200` + `Content-Length` + тело (для HEAD без тела).
  - Нет файла → `404`.
- Нужны новые syscalls в httpdl.s + httpdl.c:
  - `bind` (NR 49), `listen` (50), `accept` (43), `stat` (4), `getdents64` (217).
- HTTPS: серверный TLS 1.2 handshake (зеркало клиентского), cipher ECDHE-RSA-AES128-GCM-SHA256, P-256:
  - разбор ClientHello, отправка ServerHello + Certificate(свой cert из PEM) + ServerKeyExchange (ECDHE + подпись RSA private) + ServerHelloDone;
  - приём ClientKeyExchange → premaster → master secret → key block (IV/key местами инвертированы относительно клиента);
  - приём CCS + ClientFinished, отправка CCS + ServerFinished;
  - далее рекорды как есть (tls_send/recv_encrypted переиспользуются).
- Новое в tools/tlsrt.c:
  - PEM + base64 декодер (cert.pem → DER; key.pem PKCS#1 и PKCS#8 → n, e, d);
  - `rsa_sign_sha256` через `bi_modpow(exp=d)` (зеркало rsa_verify);
  - `tls_server_handshake(sock)` + новый op `TLS_OP_TLS_ACCEPT`.

### 4. Windows-клиент (WinINet, src/codegen.cpp Win64-блок)
- Редиректы и куки WinINet уже делает по умолчанию — проверяем, ничего не включаем от себя.
- Ask-семантика: переделать op-ветку http_download_ask:
  - probe запрос на `<url><file>` → если HTTP-статус 404 → -5;
  - иначе GET листинга `<url>/`, распарсить autoindex-якоря, скачать каждый файл кроме выбранного.

### 5. Регенерация blob + сборка + тесты
- `bash tools/gen_httpdl_blob.sh` и `bash tools/gen_tls_blob.sh` (обновят src/httpdl_blob.h, src/tls_blob.h).
- Сборка компилятора: `g++ -std=c++17 -O0 -g -I src -o /tmp/opencode/zenith_c src/*.cpp -lpthread`.
- Linux-тесты (в /tmp/opencode/httpdl_test, сервер 127.0.0.1, env -u LD_PRELOAD):
  - сервер-зенит сервит папку; клиент-зенит качает «всё кроме одного файла» — совпадение по файлам;
  - ask 404 (нет исключаемого файла) → -5;
  - редирект (~ 6) и куки: свой мини-сервер или проверка на redirection/cookie endpoint;
  - HTTPS: сервер-зенит с cert.pem/key.pem + клиент-зенит по https (localhost/127).
- Wine-тесты (wdx*.z, `app gui game dx11`, timeout -k 5 20, WINEDEBUG=-all):
  - ask-ветка: файл есть → скачать все кроме него; файла нет → -5;
  - убедиться что halt-фикс (ExitProcess) не сломался.

## Заметки по коду (файлы и места)
- `tools/httpdl.c` — клиент + новый сервер; `tools/httpdl.s` — новые врапперы syscalls.
- `tools/tlsrt.c` — серверный handshake + PEM/RSA private; `tools/tlsrt.h` — op коды.
- `src/codegen_httpdl.cpp` — `tryHttpDlCall` (ops 1..3) + новый `tryHttpSrvCall` / detection.
- `src/codegen.cpp` — Win64-блок http_download* (клиент Windows, WinINet).
- `src/httpdl_blob.h`, `src/tls_blob.h` — генерируются скриптами.
- Документация (`документация/*`) НЕ читать; `include/ztio/*.z` НЕ трогать.
- Тесты в /tmp/opencode/httpdl_test; python-сервер НЕ финал — финал сервер-зенит.