# План (на завтра): новые источники загрузки — GitHub, Microsoft Windows .iso, generic HTML

## Цель
Дать зениту качать из произвольных источников, а не только из autoindex-HTML python-стиля:
1. **GitHub** — Releases-ассеты (в т.ч. *.iso) и содержимое папок репозитория (для ask-семантики «всё, кроме install.iss»).
2. **Microsoft** — официальный Windows .iso (если утром найдём рабочую и нужную версию).
3. **Generic HTML** — извлекать `<a href>`, чтобы один механизм покрывал GitHub-страницы, MSFT-страницы и любые листинги.

Реализация: и в **C** (freestanding-блоб `tools/httpdl.c` + `tools/httpdl.s`, Linux `app linux`), и в **C++** (WinINet-ветка `src/codegen.cpp`, Windows).

## Ключевое архитектурное решение: «адаптеры источников» внутри httpdl.c
Вводим один конвейер: `fetch_listing → next_entry → (filter) → download`.
```
struct src_ops {
    int  (*list)(int kind, const u8* base_url, ...);       // заполняет g_listing (HTML или JSON)
    int  (*next)(int kind, u8* out_name, u64 out_cap);     // по одному имени
    // общий дальше: http_fetch(<base>/<name>) как сегодня
};
```
- kind параметром проходит через `httpdl_entry` (расширяем до op 5/6 — см. ниже).
- Listings наполняют тот же `g_listing[65536]`; парсеры — по одному маленькому модулю.
- Существующий autoindex-парсер (шаг C в `httpdl_ask`) остаётся адаптером `KIND_AUTOINDEX` без изменений — регрессий не будет.

## 1. Адаптер HTML (базовый, покрывает «а ну и html»)
- Обобщить текущий парсер якорей (`s_find_str(g_listing+p, ..., "<a href=\"", 9)`) в `<a ... href="URL">`.
- Oтносительные/рутные ссылки резолвим через обобщённый `resolve_location` (он уже умеет scheme+host+port+path).
- Минимальная декодировка сущностей в href: `&amp;` `&quot;` `&#39;`.
- Отсев: `#`, `?`, якоря с trailing `/` (поддиректории), дубликаты, имена длиннее `MAX_FILE_NAME`.
- Результат: один парсер для python-autoindex, GitHub-страниц, MSFT-страниц.

## 2. GitHub
Два режима (по одному новому зенит-builtin'у каждый):

### 2a. Releases — `http_download_ghreleases(owner, repo, pattern, file)`
- `GET https://api.github.com/repos/{owner}/{repo}/releases/latest` (это HTTPS — зенитов TLS уже есть).
- **Минимальный JSON-парсер в блобе** (без libc, ~200 строк): токенизатор строк/чисел + поверхностный обход ключей `assets[]` → `name`, `browser_download_url`, `size`.
- Фильтр по `pattern` (например `"*.iso"` или `"win11*"`): множественные `*` упростить до префикс/суффикс.
- Скачивание — существующий `http_fetch` (редиректы 6 уже есть; GitHub редиректит на `objects.githubusercontent.com`).
- Rate limit: без токена 60 req/ч на IP — достаточно. Токен/аутентификацию НЕ делаем.

### 2b. Папка репозитория (ask-семантика) — `http_download_ask_gh(owner, repo, branch, path, excl_file)`
- `GET https://api.github.com/repos/{o}/{r}/contents/{path}?ref={branch}` → JSON-массив `[{name, type, download_url}]`.
- Рекурсия в `type:"dir"` (глубина ≤ 4, всего ≤ `MAX_LIST_FILES`).
- Для каждого файла: `download_url` (raw.githubusercontent). Исключение и поведение 404-слyчаев — как в текущем `httpdl_ask` (шаги A–C).
- Install.iss-сценарий заказчика работает: папка в репо + файл исключения.

## 3. Microsoft Windows .iso
- **Шаг 0 (утро, research):** найти рабочую официальную ссылку (Win11 24H2/25H2 consumer x64 и/или Win10). Проверять ТОЛЬКО `software-download.microsoft.com` / прямые `*.iso?t=&e=` signed-ссылки. MDL/зеркала — нет (не официальное).
- **Вариант A (делаем, если ссылка найдена):** встроенный каталог `<версия → URL>` + `http_download_msiso(version[, file])` → op 1 (single big file). Большой файл: перед скачиванием HEAD `Content-Length`, если локальный файл уже равен размеру — пропуск (=== рестарт уже не нужен, но зафиксировать как «вне скоупа, только на будущее»).
- **Вариант B (stretch, если A провалился):** автоматизация MSFT-флоу: GET страницы → cookie jar уже есть → POST выбора эдишена → парсинг `<select>`+`<option>` (адаптер HTML из §1) → извлечь signed iso-URL. JS-токены MSFT могут убить затею — эскалация к Variant A.
- Опционально: SHA-256 в `sha256_one` (tlsrt уже имеет) сверять с автокэш-списком значений — только если заказчик попросит.

## 4. C++-сторона/Windows (WinINet) — дежурный минимум
- `src/codegen.cpp` (~4309): ветки `http_download`/`_ask`/`_speed` на WinINet; редиректы/куки WinINet уже сам.
- Новые builtins на Windows сделать «парсить-и-вернуть»:
  - JSON/HTML-разбор на Windows — использовать существующий рантайм `src/httpjson_rt.cpp` (ZJSN-записи) или встроенный маленький парсер в C++; список правил: не болит.
- Priority: Windows parity **после** Linux-реализации; в план включаем только сигнатуру + тест-заглушку.

## 5. Файлы и места
- `tools/httpdl.c`: адаптеры kind, JSON-парсер, новые entry-op 5 (gh releases) / 6 (gh ask) / 7 (ms iso); расширение `httpdl_entry`.
- `tools/httpdl.s`: новых syscalls не нужно — DNS/TCP/TLS/`getdents64` уже есть.
- `src/codegen_httpdl.cpp`: `isHttpDlName` += 3 имени; `tryHttpDlCall` для новых ops (арность/регистры).
- `src/parser.cpp`: `inferExprType` += новые имена (Int-группа).
- `src/httpdl_blob.h`: регенерация `bash tools/gen_httpdl_blob.sh`.
- (C++) `src/codegen.cpp` WinINet-ветка — если делаем Windows-parity.
- НЕ трогаем: `include/ztio/*.z`, документацию.

## 6. Тесты (check-list на завтра)
1. Регрессия: python-сервер + зенит-сервер (ask found/404, redirect, cookie, HTTPS) — как сегодня.
2. GitHub real: маленький тест-репозиторий (2 файла + install.iss) → `_ask_gh` качает всё, кроме install.iss; releases-ассет скачивается через `_ghreleases`.
3. Generic HTML: страница с `<a href>` НЕ в python-формате → листинг парсится.
4. MSFT: `_msiso("<версия>")` отдаёт файл `>= 3 ГБ` ИЛИ возвращает чёткую ошибку с каталога; если ссылки нет — тест помечается skipped (результат research утра).
5. Сборка компилятора (47 src/*.cpp → build/linux), регенерация blob, оба фронта (C blob / C++ WinINet-stub).

## 7. Риски и открытые вопросы
- MSFT: JS/анти-автоматизация и регионная доступность iso — главный риск; решение — Вариант A (фиксированный каталог).
- GitHub: rate limit 60/ч; смена схемы JSON API (schemaless, но lock на `browser_download_url`).
- Размер блоба: +JSON/HTML адаптер ≈ +4–6 КБ (допустимо).
- Вопросы к заказчику утром: 1) releases или repo-folder или оба? 2) нужна ли Windows-parity или только `app linux`? 3) версия iso («нужная версия» = Win11 24H2?).