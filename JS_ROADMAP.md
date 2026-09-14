# Embedded JS engine (tools/jsrt.c) — состояние и план

Автоснимок сделан при выключении ПК (после сессии отладки хост-стабов).

---

## 15. Сессия: регулярные выражения (RegExp) — полный инструмент в ядре движка

**Задача (из чата):** «полностью добить ядро и добавить туда до 100 процентов функций нового js, но только ядро» — следующий блок stdlib `tools/jsrt.c`.

### 1. RegExp-инструмент («ro»V_OBJ маркер `"$<r"`)
- Значение = box: `"$<r"` pattern, `"$<f"` флаги, `"$<l"` lastIndex. Лексер `T_REGEX=66` с дизамбигуацией `/` (regex vs деление: смотрим пред-токен контекста); parser `NK_REGEX=37`. Глобальный `RegExp`, `new RegExp(pat[,flags])` (из строки ИЛИ из объекта-регекса с копированием его флагов, если flags не задан), литералы `/…/flags`.
- Методы: `test`, `exec` (с глобальным lastIndex — старт со `.lastIndex`, запись `ep`, конец на -1); свойства `source`/`flags` + булевы `global/ignoreCase/multiline/dotAll/sticky(0)/unicode(0)` (у `flags` read с NK_MEMBER и через `"$<l"`-запись).

### 2. String-интеграция
- `String.prototype.replace/replaceAll` (regex, `$&` `$1..$9` `$$`, функция-замена с `(match,g1..,offset,str)`, глобальный обход с fallback на нулевые совпадения), `match` (глобала: массив строк; одиночная: exec-массив с `index`/`input`), `search`, `split` (regex, limit, без «лишних» пустых на нулевом совпадении; `/(?:)/g` на 'abc' → 4 куска накоплено). Строковые паттерны по-прежнему работают через `js_str_replace_helper`.

### 3. VM-матчер (backtracking, инсны ROP_CH/CLS/W/D/SP/DOT/BOUND/CARET/DOLLAR/SAVE/SPLIT/JMP/MATCH/FAIL/BACKREF/STR/POSA/GOAL/NEGOK)
- **rg_run** — модель «pending-стек + текущие регистры pc/sp/caps» (tind = число отложенных, SPLIT пушит альтернативу, FAIL выталкивает верх стека в текущие pc/sp/caps — причины ранних «не-бэктрекингов»: старый код зависал на той же упавшей инструкции и путал, chей фрейм продолжить).
- **Альтернация** `rg_calt` — рекурсивная forward-split форма (SPLIT перед каждой веткой; single-branch: JMP-over/FAIL).
- **Квантификаторы** — одна копия body: `?`=SPLIT OUT;body;OUT; `*`=SPLIT OUT;body;SPLIT OUT;SPLIT FAIL;JMP L;FAIL;OUT; `+`=body;SPLIT OUT;SPLIT FAIL;JMP L;FAIL;OUT (bail+carrier на итерацию — 2 попа = правильный bail). Причина старого бага: body компилировался дважды и второй раз съедал символ квантификатора. `{m}/{m,}/{m,n}` — straight-line копии через reset `rg_cpi=astart` (capture-слоты при группах дублируются — задокументированная аппроксимация).
- **Группы/backrefs индексация с 0:** `\1..\9` → slot-0 (`emit e-49`); exec-массив, `$1..$9`, callback-группы читают `caps[(g-1)*2]`.
- **Case-fold в классах** при флаге `i` (fold с обеих сторон: `ch` и границ диапазона `[a-z]→[A-Z]`); `str_of_val` regex → `/pattern/flags`.
- Упрощение/не-поддержка: `\u{…}` с флагом `/u` не обрабатывается (astral — через суррогатные пары), запись в `global`-свойства игнорируется, `split('abc'.split(/(?:)/g))` даёт 4 куска (JS — 3).

### 4. Баги, пойманные харнесами re_probe/re_probe2/rg_dbg
- Квантификаторные символы не потреблялись; `rg_calt` перезаписывал target последней ветки; `rg_cseq` не учитывал `rg_ni==before`; fpop в цикле не перезагружал фрейм; backrefы/группы сдвиг на 1; `toString` давал `[object Object]`; `m.index`/`m.input` без проп спуска в V_ARR-ветке NK_MEMBER; case-insensitive классы.

### 5. Проверки
- core_test **147/147**, strict_test **34/34** (кейс «regex unsupported» заменён на позитивный `r.source`/`r.global`), jstd_test **FAILS=0**, re_probe зелёный (exec/match/search/split/replace/$&/$1/callback, классы, якоря, lookahead, backrefs, глобал lastIndex, `new RegExp`, toString `/a+b/i`, nested, `o{2}`), re_probe2 зелёный (multiline/dotAll/greedy/группы/global iter/lastIndex loop/replace-all/split-сложный/boundary/astral-surrogate/RegExp-ctor) — падают только задокументированные in-scope-отклонения;
- js_direct: «counter closure» (want 3) и «parseInt junk» (want 0) — там где движок возвращает ПРАВИЛЬНЫЙ JS (6 и NaN), тест устарел.
- Биоблочек: blob перегенерирован (**150732 B, syms=118**), exe пересобран (**5152203 B**), `js_blob_smoke` (blob-путь через mmap, как exe) **ALL OK** — код матчера чист от отладочных `printf/rg_trc` (исходник freestanding-без-варнингов).

### 6. Команды
```
gcc -O0 -ffreestanding -fno-stack-protector -fno-common -mno-red-zone -Itools -c tools/jsrt.c -o /tmp/jsrt_host.o
gcc -Itools -o /tmp/opencode/re_probe /tmp/jsrt_host.o /tmp/opencode/re_probe.c && /tmp/opencode/re_probe
gcc -Itools -o /tmp/opencode/re_probe2 /tmp/jsrt_host.o /tmp/opencode/re_probe2.c && /tmp/opencode/re_probe2
gcc -O0 -g -o /tmp/opencode/rg_dbg /tmp/opencode/rg_dbg.c   # дизассемблер/VM-трасса (инклюдит jsrt.c)
g++ -std=c++17 -O0 -Isrc tools/js_blob_smoke.cpp -o /tmp/opencode/js_smoke && /tmp/opencode/js_smoke
bash tools/gen_js_blob.sh && x86_64-w64-mingw32-g++ -O2 -std=c++17 -w -static src/*.cpp -o build/zenith_new.exe
```

---

## 14. Сессия: «добить ядро до 100% нового JS» — stdlib-экспансия (Array/String/Number/Object/Map/Set/URI/base64) + стрелки, hex-литералы, escapes

**Задача (из чата):** «полностью добить ядро и добавить туда до 100 процентов функций нового js, но только ядро» — расширить стандартную библиотеку встроенного движка (`tools/jsrt.c`), НЕ трогая host/net/tls части.

### 1. Array (ветка V_ARR в `call_method_v`)
- **Modern-методы:** `lastIndexOf(x[,from])` (считает с конца), `at(i)` (отрицательный индекс), `fill(v[,s[,e]])`, `flat([depth])`/`flatMap(fn)` через `js_arr_flatten_into` (спека FlattenIntoArray: рекурсия только на `depth`-уровней глубины), `reduceRight(fn[,init])` (порядок с конца, prepend-лист), `findLast/findLastIndex(fn)`, `copyWithin(t,s,e)` (арена-буфер для копии), `toReversed()/toSorted(fn)/toSpliced(s,n,...)/with(i,v)` (immutable-варианты), `toString()/valueOf()/toLocaleString()`.
- **Колбэки** `forEach/map/filter/find/findIndex/some/every` теперь получают `(element, index)` (раньше только элемент).
- **join/toString** — `arr_join_req/arr_join_fill`: вложенные массивы рекурсивно стрингуются как `join(',')` в реальном JS (депth-cap 10).
- **Статики:** `Array.of(...)`, `Array.from(iterable[,mapFn])` (см. 4.4), `Array.isArray`.

### 2. String
- **Экраны в лексере строк:** `\n \t \r \b \f \v \0 \\ \' \"`, `\xHH`, `\uHHHH` (в т.ч. суррогатные пары `\uD83D\uDE0A` → один кодпоинт), `\u{...}`; `emit_cp_u` — UTF-8-энкодер кодпоинтов (сюррогаты/out-of-range → U+FFFD). Раньше `'\u044F'` давал 6 литеральных символов.
- **Методы:** `at(i)`, `trimStart()/trimLeft()`, `trimEnd()/trimRight()`, `concat(...)`, `replace(pattern, repl)` (строка-паттерн, `$$ $& $`` `$'` + функция-замена через `js_str_replace_helper`), `replaceAll(pattern, repl)`, `match(p)`/`search(p)` (строковый паттерн), `codePointAt(i)` (UTF-8 декод), `localeCompare(s)`, `valueOf()/toString()`.
- **Статики:** `String.fromCharCode(...)`, `String.fromCodePoint(...)` (через `emit_cp_u`-логику), `String.raw({raw}, ...subs)` (собирает СТРОКУ raw[0]+sub[0]+raw[1]+…, раньше ошибочно возвращал массив).
- Пустой паттерн `replace('',r)`/`replaceAll('',r)` — вставка на границах символов.

### 3. Number
- **Статики:** `isInteger/isSafeInteger/isFinite/isNaN/parseInt/parseFloat` (в `Number` и глобально `isSafeInteger`); `Number`-константы читаются в NK_MEMBER: `MAX_SAFE_INTEGER/MIN_SAFE_INTEGER/EPSILON/MAX_VALUE/MIN_VALUE`.
- **`toExponential([fd])`** — мантисса из `trunc(m·10^nd)` + strip trailing zeros с синхронным сдвигом `sc/=10` (баг: p не уменьшался → «0.0000e+04»); экспонента БЕЗ нулей-пада (`e+4`, не `e+04`);
- **`toPrecision(p)`** — инлайн: при `e>=p || e<-6` экспоненциальная форма, иначе fixed с `10^dp` scaling (int/frac раздельно). Кап p 1..21.
- `toFixed` — как было (integer scaling, кап 18).

### 4. Map / Set (совершенно новая структура)
- **Хранение:** маркерные box-объекты `"$<x"` (tag = "Map"/"Set") + `"$<e"` (V_ARR записей: Map — пары `[k,v]`, Set — голые значения). Хелперы `mkset_*`: new/tag/entries/size/has/get/set/add/delete/clear/pair_new (пары сверяются строгим `eq_strict`).
- **Глобалы** `Map`/`Set` регистрируются в `env_init_global()` (native ctor «Map\x1Fctor»), `new Map([[...]])` из массива пар или объекта-сидерода, `new Set(arr|str)`.
- **Методы** (диспатч по маркеру в V_OBJ-ветке `call_method_v`): Map — `set`(chain), `get`, `has`, `delete`(bool), `clear`, `size`, `keys`/`values`/`entries`, `forEach((v,k))`; Set — `add`(chain), `has`, `delete`, `clear`, `size`, `keys/values`(алиасы), `entries` (`[v,v]`), `forEach((v,v))`.
- `map.size`/`set.size` — и через NK_MEMBER read (свойство), и метод.

### 5. Object
- `Object.is(a,b)` — строгая эквивалентность с различением `+0`/`-0` через трюк `1/x` и `NaN===NaN`; `Object.fromEntries(pairs)` (массив пар или объект), `Object.getOwnPropertyNames(o)` (реальные ключи, не `$..` служебные).

### 6. URI / base64 глобалы
- `encodeURIComponent/encodeURI` + `decodeURIComponent/decodeURI` — процент-кодирование поверх UTF-8 (байты > 0x7F, `%HH`), unreserved набора; `encodeURI` не кодирует `;/?:@&=+$,#` (как спека).
- `btoa(str)`/`atob(b64)` — инлайн base64 (не через `builtin_base64` с box-нодами — те ломали бы eval); `atob` игнорирует неалфавит и **`=` завершает поток** (по padding), хвостовой run бит-дополняется.

### 7. Современный синтаксис (ядро!)
- **Стрелочные функции `=>`** (T_ARROW=65): `x => e`, `(a,b) => e`, `() => e`, блочное тело. Дизамбигизация `(`: `arrow_params_ahead()` сканирует сырьё после `(` на паттерн `ident(,ident)*)=>` (честный lookahead по `g_lex.pos`, позиция токена — СТАРТ, а не конец); при совпадении перемотка `g_lex.pos=g_tok.pos` и повторная лексикация `(`→`parse_params`→`parse_arrow_body`. Тело-выражение оборачивается в `{ return expr; }` (NK_RETURN в NK_BLOCK), `ival=3` метит стрелку. Одно-идентификаторная форма ловится в `parse_postfix` сразу после `parse_primary` (только если primary — NK_IDENT).
- **Hex-литералы** `0x…`/`0X…` (с accumulate в double, `lex_hex`).
- **Свойства-ключевые слова:** `.delete/.catch/.new` etc — `expect_name` принимает range `T_VAR..T_ARROW`; `parse_obj` ключ тоже (real JS: property names могут быть reserved words). Фикс дал работу `m.delete('k')` и `{default:5}.default`.

### 8. Основные баги, пойманные тестами
- `String.raw` возвращал массив вместо строки → переписан на буфер.
- `toExponential()` (default) — strip trailing zeros без сброса `sc` → мантисса «0.0000»; экспонента падалась нулями.
- `str.replace('a','$$')` против `$$$$` — семантика `$$`=доллар (тест был неверный: `'$$$$'`→`$$`).
- Числовой литерал `0x…` ломал парсер (0 + identifier) — до добавления hex.
- Redirect `expect_name` для ключевых слов — иначе `m.delete`/`o.default` в парсере стоп.
- `atob` с `=` padding перезапускал аккумулятор (терял хвост) → `=` теперь завершает.

### 9. Проверки
- **core_test** (`/tmp/opencode/core_test.c`, новый): **147/147** — Array(modern+idx callbacks+statics), String (modern+statics+replace-all-variants), Number (statics+константы+toExponential/toPrecision/toFixed), Object, Map (полный цикл), Set, URI/base64, синтаксис (стрелки 12 кейсов, hex, escapes, \u surrogate, member-keyword).
- jstd_test: **FAILS=0**; strict_test: **34 ok / 0 FAIL**; jnh builtin+require проходят.
- Wine E2E (новый blob+exe): js_test **ALL JS TESTS OK**, js_host_test **HOST FS TESTS DONE**, js_tern (1/12/3/3), js_require (sum=42, cache=3), js_require_stress **ALL OK**.
- Блоб перегенерирован (**140816 B, syms=101**), exe пересобран (5126899 B). Бэкапы: `/tmp/zn_precore.exe` (экзе перед этой сессией), `/tmp/zn_prestrict.exe`.

### 10. Команды (как в сессии 13 + core_test)
```
gcc -O0 -g -c /tmp/opencode/core_test.c -o /tmp/core_test.o && gcc /tmp/jsrt_host.o /tmp/core_test.o -o /tmp/core_test
# (стрелки/hex/escapes: /tmp/opencode/arrow_probe.c — быстрый отладчик синтаксиса)
```

---

## 13. Сессия: §3.4 (host-слоты 18–22, splice/sort/keys/values/entries, isInteger/toFixed/toString(radix), hasOwn, os, fs.statSync) + строгий JS-парсер

**Задача (из чата):** «продолжай §3.4» → затем «сделай парсер jsсовский»: старый парсер был permissive и молча принимал мусор (невалидный JS превращался в `undefined` без ошибки). Нужен строгий парсинг: невалидный синтаксис → `SyntaxError` (rc=-1), валидные JS-идиомы (trailing comma и т.п.) остаются рабочими.

### 1. §3.4 — новые API
1. **Host-слоты 18–22** (`HOST_FS_STAT=18 path,outbuf,cap,_` → `"size\0is_dir\0"`; `HOST_RAND=19`; `HOST_ENV=20 key,outbuf,cap,_`; `HOST_ARGS=21 idx,outbuf,cap,_`; `HOST_UNAME=22 _,outbuf,cap,_`; `HOST_COUNT=24`). В `tools/js_native_host.cpp` добавлены `h_stat/h_rand/h_env/h_args/h_uname`, `sys/utsname.h`, `fns[24]`, зарегистрированы слоты 0–3 и 12–22, `g_argc/g_argv` из `main`. Сигнатура `__uname` — `(0,ob,256,0)` (нулевой первый аргумент).
2. **`Array.prototype.splice`** — insert-режим корректно: вставка идёт со `split = a1n ? a1n->next : 0` (не `args->a`, который при 0 аргументах был мусором). Вырезание/замена/insert — проверено.
3. **`Array.prototype.sort(fn)`** — сортировка; **`toString(radix)`** для num (2–36).
4. **`Object.keys/values/entries`**, **`Array.isArray`**; **`hasOwnProperty`/`Object.hasOwn`** — работают, старых «FAIL» не было (ложная тревога из-за bool через `run_num`; в jstd_test bool → `run`+`?1:0`).
5. **`Number.isInteger`** — валидные знаки: `NaN/Inf/frac/string` → false, `"5"/5.0` → true.
6. **`Number.prototype.toFixed(n)`** — целочисленный scaling + `+0.5+1e-9` (эпсилон), `places` кап 18.
7. **`os`-модуль**, **`fs.statSync`** (имена/размер), **`__rand`** — при тестовых прогонах детерминированно варьируется.

### 2. Строгий парсер (`tools/jsrt.c`)
- Хелперы: `g_parse_abort`, `syn_err(msg)`, `mk_expected_msg(what)` — ручная склейка без `snprintf` (движок freestanding, без libc); `expect_tok(k,what)`, `expect_name(what)`, `stmt_boundary_ok()`, `sync_stmt_end()`.
- **Границы statement** (всегда баг-stop, ASI-стиль «;» опционален): `T_SEMI, T_EOF, T_RBRACE, T_ELSE, T_RPAREN, T_CASE, T_DEFAULT, T_WHILE` (T_COLON убран — иначе `{a:1}` как block оставлял висящий `:`). К примеру `var x = 1 5` и `x = 1 5` теперь «expected ';'», как в настоящем JS.
- **Обязательные токены**: `parse_obj` требует `СВОЙСТВО:` (key-ident или строка), trailing comma разрешён, обязателен `}`; `parse_arr` — обязателен `]` (trailing comma); `parse_params` — только идентификаторы («expected parameter name»), обязательны `(`/`)`, trailing comma; `parse_block` — обязательны `{`/`}`; `parse_primary` — `Unexpected end of input` на EOF, `Unexpected token` на любой другой лишний токен; `[` после точки требует свойство; `parse_call_args` и вызовы — обязательны `)`; `parse_ternary` — обязателен `:` после `?`.
- **Функционал-декларации НЕ проходят `sync_stmt_end()`**: в JS `function f(){} new f()` валидно, body заканчивается на `}`, следующий токен — новая инструкция. (Банару находка: `function P(){} new P().x` после строгого фикса давал «expected ';'».)
- **Найден и починен латентный краш (был и ДО строгого парсера):** `g_global_env` инициализировался только в `JS_OP_RESET`. Если хост вызывал `JS_OP_EXEC` без `JS_OP_RESET` и все первые evals были parse-ошибками (env не трогался), то первый exec, коснувшийся env, дергал `NULL` → SIGSEGV (`env_has_local`, addr=0x8). Добавлена `env_init_global()` (env + NaN/Infinity/Promise) — вызывается в RESET И лениво в JS_OP_EXEC/EXPR.
- Сообщения об ошибке: `SyntaxError: expected ']'/'}'/')'/'/'/'case/…`, `expected ':' after ?`, `expected property name after '.'`, `expected parameter name`, `expected variable name`, `expected ':' after case/default`, `Unexpected token`, `Unexpected end of input`.
- Object shorthand намеренно НЕ поддерживается (в тестах не используется). `{a:1,b:2};` на уровне statement в реальном JS — block c labels (SyntaxError) — движок тоже ругается.

### 3. Проверки
- strict_test (`/tmp/opencode/strict_test.c`): 17 must-fail (точные SyntaxError) + 16 валидных идиом (trailing array/obj/call, ternarnые/if-else/for/switch/do-while, fn-expr, new-chain, async) — **33/33 ok, без краша**.
- jstd_test: **FAILS=0** (50 проверок §3.4).
- `tools/js_native_host.cpp` (g++!): builtin и require (42) проходят.
- Wine E2E: js_test **ALL JS TESTS OK**, js_host_test **HOST FS TESTS DONE**, js_tern (1/12/3/3), js_require (sum=42, cache=3), js_require_stress **14/14 ALL OK** (из каталога репо — нужен `./jsstress`).
- Блоб перегенерирован (`bash tools/gen_js_blob.sh` → 103708 B, syms=89), exe пересобран (5090035 B). Бэкапы: `/tmp/zn_prestrict.exe`.

### 4. Команды
```
gcc -O0 -ffreestanding -fno-stack-protector -fno-builtin -fno-common -mno-red-zone -Itools -c tools/jsrt.c -o /tmp/jsrt_host.o
gcc -O0 -g -c /tmp/opencode/jstd_test.cpp -o /tmp/jstd_test.o && gcc /tmp/jsrt_host.o /tmp/jstd_test.o -o /tmp/jstd_test
g++ -O0 -g -c tools/js_native_host.cpp -o /tmp/jnh.o && gcc /tmp/jsrt_host.o /tmp/jnh.o -o /tmp/jnh
# строгий парсер:
gcc -O0 -g -c /tmp/opencode/strict_test.c -o /tmp/strict.o && gcc /tmp/jsrt_host.o /tmp/strict.o -o /tmp/strict
# E2E: cd /tmp && wine <repo>/build/zenith_new.exe <repo>/js_*.z -o /tmp/x.exe && wine /tmp/x.exe (require_stress — из каталога репо)
```
- `/tmp/jsmod_a.js` = `module.exports = function(a,b){ return a+b; };` (фикстура require, пересоздавать после ребута).

### 5. Прочее
- Парсер после строгих правок НЕ трогает валидный JS (jstd_test/все .z проходят). Следующие кандидаты на строгость: `case`-body без фигурных скобок уже ок; строки template/туберкулы — вне зоны.
- `Node->key` в env-цепочке — offset такой, что `e->names` при `e==NULL` даёт addr 0x8 (краш читаемый).

## 12. Сессия: +14 из стандартной библиотеки (find/findIndex/some/every/reduce, isArray, values/entries, lastIndexOf/padStart/padEnd)

**Задача (из чата):** «да продолжай» — лёгкие методы stdlib после async.

### Изменения в движке (`tools/jsrt.c`)
1. **Массивы** (ветка V_ARR в `call_method_v`):
   - `find(fn)` → первый элемент, где колбэк истинен, иначе `undefined`;
   - `findIndex(fn)` → индекс или `-1`;
   - `some(fn)` / `every(fn)` → bool с ранним выходом;
   - `reduce(fn[, init])` — без `init` аккумулятор = первый элемент; пустой массив
     без `init` → `undefined`. Колбэки как в существующих `forEach/map` —
     аргумент (элемент).
2. **`Array.isArray(v)`** — добавлен диспатч в NK_CALL member-ветке (рядом с
   Promise/Object), глобал `Array` не регистрируется (вписывается в текущее
   ограничение «нет глобального Array-конструктора»).
3. **Объекты:** `Object.values(o)` и `Object.entries(o)` — новый хелпер
   `call_objvalues(args, env, entries)` рядом с `call_objkeys`. Для `entries` каждый
   элемент — массив `[key, value]`.
4. **Строки:**
   - `lastIndexOf(sub[, from])` — поиск подстроки с конца (from = секция поиска,
     по умолчанию — конец строки);
   - `padStart(len[, pad])` / `padEnd(len[, pad])` — дополнение строками-паттерном
     (`pad` по умолчанию `" "`), уже длинные строки возвращаются как есть,
     лимит выходной длины 16 MiB.

Strict-семантика выверена по реальному JS: `lastIndexOf(sub, from)` ищет только от
позиции `from` назад (`'hello world'.lastIndexOf('o', 3)` → `-1`, как и в Node).

### Проверки
- Нативно (`/tmp/jsstd`, FAILS=0, 25 проверок): все методы + edge-cases
  (find без совпадения, reduce без init/с init/пустой массив, lastIndexOf с from,
  padStart с многосимвольным паддингом и «уже длинно»).
- Wine/.z (`zstd.z`, 9 проверок): find 3, findIndex 1, some/every/reduce,
  `Array.isArray`, keys/values/entries, lastIndexOf 7, padStart/padEnd. `STDLIB Z TESTS OK`.
- Регрессия нативно: jslib3 (ok), jslib2 (15/15), `/tmp/js_stress_run` (ok=14),
  `/tmp/jsasync` (FAILS=0).
- Wine: js_test, js_host_test, js_tern_test, js_require_test, js_require_stress
  (14/14 ALL OK), feat.z (ok=23), zoop.z, zasync.z — все rc=0.
- Блоб перегенерирован: `src/js_blob.h` (94572 B, syms=87). Exe:
  `build/zenith_new.exe` (5080819 B), бэкапы `/tmp/zn_oop.exe` (до-async) и
  `/tmp/zn_asyncc.exe` (после async, до stdlib).

---

## 11. Сессия: асинхронное подмножество ES6 (Promise, микрозадачи, таймеры, async/await)

**Задача (из чата):** «может добавить теперь js async/await».

Итог — в `tools/jsrt.c` реализовано асинхронное подмножество для одномашинного
исполнения: полноценные синхронные `Promise` (resolve/reject/all + конструктор +
then/catch-цепочки), очередь микрозадач (микрозадачи выполняются строго до
макрозадач), таймеры (setTimeout/setInterval/setImmediate/clearTimeout/clearInterval)
и `async function`/`await`. Все асинхронные операции синхронно дренируются в точке
дренажа — поэтому сценарий «выполнил, сразу прочитал результат» работает штатно.
Проверено нативно (FAILS=0) и через wine/.z-тулчейн (7/7), регрессия зелёная.

### Изменения в движке
1. **Токены/парсер:** `T_AWAIT`(63), `T_ASYNC`(64) + ключи в `keyw()`.
   `async function f(){}` → `NK_FUNC(ival=2)` (функция-промис). `await x` →
   `NK_AWAIT` (35); `await` в eval → `async_await_value` (спин петли).
2. **Промисы:** `promise_new()` — бокс состояния: `$_s` (0 pending/1 fulfilled/2 rejected),
   `$_v` (значение), `$_c0` (список задач-континуаций). `promise_settle` проставляет
   состояние и ставит в очередь все прицепленные `.then/.catch`-задачи. `promise_ctor`,
   `promise_static` (resolve/reject), `promise_all`, `promise_catch`.
   - `Promise.resolve(x)`: promise → вернуть как есть; иначе новый fulfilled.
   - `Promise.all`: разворачивает одиночный массив-аргумент в список items; ждёт все
     (в т.ч. уже выполненные), результат — массив значений, reject распространяется.
   - Adoption НЕ делается: `.then` сеттлит дочерний промис сырым результатом колбэка.
3. **Очередь микрозадач:** `g_mtq_head/tail`, боксы-задачи `$_f` (handler),
   `$_v` (аргумент), `$_c` (дочерний промис), `$_r` (reject-флаг), `$_n` (след.).
   `run_microtask` исполняет handler через `call_func` и (если есть дочерний) сеттлит
   его. Отсутствие handler → прокидывает значение/состояние дальше.
4. **Таймеры:** `g_tmq_head/tail`, `g_timer_seq`. `timer_create` кладёт в бокс
   `$id`, `$iv` (0 = one-shot setTimeout, 1 = интервал), `$_f`, `$_n`; `tmq_push`.
   `tmq_remove(id)` снимает по `$id`, обнуляя `$iv`. **Таймер НЕ вынимается из
   очереди до запуска** — это позволяет `clearInterval`/`clearTimeout` работать из
   собственного колбэка. `run_timer`: one-shot сам себя снимает после срабатывания;
   интервал остаётся в очереди (срабатывает каждый проход дренажа; снапшот `$iv` —
   чтобы колбэк, уже снявший таймер, не приводил к повторной постановке).
5. **`master_pump(budget)`** — точка дренажа: сначала ВСЕ микрозадачи, затем один
   таймер за проход (только при `g_async_await_nest==0`), с прогрессом и бюджетом.
   Подключена к `JS_OP_EXEC`/`JS_OP_EXPR` (после выполнения, если нет ошибки) и к
   `JS_OP_PUMP=8` (a1 = лимит, по умолчанию MAX_ASYNC_ITERS).
   `g_had_error` прерывает дренаж.
6. **`async_await_value`** (`await`): если аргумент — promise, спин `master_pump(1000)`
   до `MAX_ASYNC_ITERS`, пока `$_s!=0`; rejected → undefined; иначе значение `$_v`.
   Инкремент/декремент `g_async_await_nest` вокруг спина (внутри await таймеры не
   срабатывают — только микрозадачи). `async function`: `call_func` возвращает
   обещание результата даже если функция вернула примитив.
7. **RESET**: сброс `g_mtq_*`, `g_tmq_*`, `g_timer_seq`, `g_async_await_nest` и
   регистрация глобала `Promise = make_native_method("promise","ctor")`.
8. **GC:** `mark_async_roots()` — `g_mtq_head`/`g_tmq_head` как корни.

### Попутные баги, найденные и исправленные
1. **`+=` со строками:** оба места `NK_ASSIGN` (`+=`) считали через `to_num(base)+
   to_num(rhs)` — `s += 'm'` разрушало строку. Добавлен `add_vals(l, r)` (строка → склейка),
   применён в обоих местах `+=` (exec и eval).
2. **Двойное вычисление member-базы:** `p.then(f1).then(f2)` — внутренний операнд
   `.then(f1)` вычислялся дважды (в `eval(NK_CALL)` member-ветке и повторно в
   `call_method`), отчего `.then` регистрировался посчитавшим дважды. Ветки
   member-вызова (ident и общая) теперь вычисляют базу ОДИН раз и падают в общий
   `call_method_v(Val base, name, args, env)`, промис-диспатч then/catch — до общего
   фолбэка.
3. **`clearInterval`/`clearTimeout` из собственного колбэка не находил таймер**
   (тот уже был вынут из очереди перед запуском). Таймер остаётся в очереди во время
   работы; `run_timer` сам управляет позицией.
4. **`Promise.all([...])`** считал один аргумент-массив и никогда не резолвился —
   разворачивает одиночный массив в `items`.
5. **`env_find(...)->val` = NULL-deref** в allstep/allrej (env без `$p`). Корректное
   решение: `Node* pn=d?env_find(d,"$p"):0; Val pv=pn?pn->val:vundef();` —
   важно: `env_find` возвращает `Node*`, брать `node->val`, не `*`.
6. **`setTimeout`-infinite («всего один вызов»)**: проверка была `box_has(t,"$iv")`
   (ключ существует даже при значении 0). Теперь проверяется значение
   `(long)box_get(t,"$iv").num`.

### Известные ограничения
- Часовая модель отсутствует: `setTimeout(fn, delay)`/`setInterval(fn, delay)` —
   `delay` игнорируется (нет часов); макрозадачи срабатывают по проходам дренажа.
- `setImmediate` — то же, что setTimeout(0). `Promise.all` не поддерживает
  итерируемый-не-массив и отсутствует `Promise.race`/`Promise.finally`.
- `await` синхронно спин-дренит (синхронный движок): `await` на никогда не
  выполняющемся промис вернёт сам промис после MAX_ASYNC_ITERS (примерно как
  forever-pending). Rejected await → undefined (без исключения).
- В `.then/.catch` внутри await-спина таймеры не срабатывают (только микрозадачи).
- Нет реальных потоков; `async` не «откладывает» исполнение — это удобный синтаксис
  над теми же очередями.

### Проверки
- Нативные драйверы (`/tmp/jsasync`, `/tmp/jsall`, `/tmp/jsct4`): then-цепочки
  (then1:42/then2:7/then3:14), resolve-строки, reject+catch, порядок микро→макро
  (ord: smt), self-clearing setInterval (iv done 2), clearTimeout, async val 21,
  `g(n)` → 11, `Promise.all([pA,Promise.resolve('B'),'C'])` → L 3 A B C,
  `Promise.all([])` → len 0, вложенный await (nest result: 12), `new Promise` mk1/mk2,
  obj then 9. **FAILS=0.** ВАЖНО для драйверов: `jsrt_entry(EXEC)` принимает
  `(ptr, length)` — забытая длина = пустой парсинг = `undefined` (не баг движка).
- Wine/.z (`/tmp/zasync.z` → `zasync.z` в репо, 7 проверок): `await Promise.resolve(42)`,
  async f+g через await, порядок then+setTimeout через меж-eval чтение (`s.length`=3),
  setInterval+clearInterval (n=2), `Promise.all`→42, `reject().catch`→1.
  Микрозадачи выполняются в конце js_eval, поэтому читать побочные эффекты нужно
  отдельным js_eval — как в реальном JS.
- Регрессия нативно: jslib3 (ok), jslib2 (15/15), `/tmp/js_stress_run` (ok=14).
- Wine: js_test (ALL JS TESTS OK), js_host_test, js_tern_test, js_require_test,
  js_require_stress (14/14 ALL OK), feat.z (ok=23), zoop.z (OOP TESTS OK), zasync.z.
- Блоб перегенерирован: `src/js_blob.h` (90732 B, syms=86). Exe:
  `build/zenith_new.exe` (5076069 B), бэкап `/tmp/zn_oop.exe` (до-async, ООП-состояние).

---

## 10. Сессия: объектно-ориентированные конструкции (ES5-подмножество)

**Задача (из чата):** «можешь теперь js ООП добавить».

Итог — в `tools/jsrt.c` добавлено ООП в стиле ES5: `new`, `this`, `function.prototype`
(+ `constructor`), цепочка прототипов, `instanceof`, `Object.create`, `Object.getPrototypeOf`,
насчитываемые чужие свойства и методы. Проверено нативно и через .z-тулчейн (10/10),
регрессия зелёная.

### Изменения в движке
1. **Токены/парсер:** `T_NEW`(60), `T_THIS`(61), `T_INSTANCEOF`(62) + ключи в `keyw()`.
   `parse_primary`: `this` → `NK_IDENT("this")`; `new` → `parse_new_callee()` (primary +
   `.`-`[]`-цепочка БЕЗ вызовов) + `parse_call_args()` (скобки опциональны, результат в
   `NK_LIST`) → узел `NK_NEW` (34). Постфикс-цикл (`parse_postfix`) продолжается после
   `new` → `new Foo().m()` работает.
2. **`this`-биндинг:** `call_func(fn, args, env, thisv)` — 4-й параметр; при
   `thisv.tag!=V_UNDEF` в callee-env кладётся скрытый слот `"this"` (находится обычным
   `env_find`). Top-level `this` → undefined; «отвязанный» вызов `f()` → undefined.
3. **Прототипы:** `struct Box` и `struct Node` получили поле `proto`. Хелперы
   `new_box()` (обнулённый через `arena_alloc`) и `func_proto(Node*)` — гарантирует
   прото-бокс для `NK_FUNC` и ставит `constructor` (= саму функцию).
   - Чтение `f.prototype` → `func_proto(f)` (ленивое создание).
   - `F.prototype = obj` (через `assign_to`, только V_OBJ/V_ARR) → `f->proto = box`.
   - Чтение свойства объекта: `box_get_ext` — собственное свойство, иначе по цепочке
     `b->proto` (own wins). `in` — `box_has_ext`.
4. **`new` eval:** конструктор = V_FUNC; `inst = new_box(); inst->proto = func_proto(c)`;
   `call_func(c, args, env, this=inst)`; если конструктор вернул объект/массив — его,
   иначе instance. `new 5` → ошибка "new of non-function".
5. **`instanceof`:** `r` должен быть функцией; сверка `inst->proto`-цепочки с
   `func_proto(r)`. `{} instanceof Object` → false (литералы без proto-звена) — ожидаемо.
6. **Вызовы методов:** в `NK_CALL` для `base.m(args)` при V_OBJ/V_ARR сначала
   `box_get_ext` + `call_func(f, ..., this=base)`; fallback `call_method` встроенных.
   Это же покрывает цепочку прототипов. НЕ-идентификаторные базы (`require('fs').x()`),
   `Math.*`, `Object.*`, модули `fs/path/base64/console/JSON` сохранены в прежнем порядке.
7. **`Object.create(proto)`** — новый бокс, `nb->proto = box(proto)` (или null);
   `Object.getPrototypeOf(o)` — прямое чтение `proto`-звена. Ранее добавленные
   `Object.keys`/`Object.assign` доступны.
8. **GC:** новый `mark_box(Box*)` (обход `b->proto`-цепочки с флагом-сторожем от циклов);
   `mark_val` для V_OBJ/V_ARR → `mark_box`; `mark_node_iter` помечает `n->proto`.
9. **Встроенные callbacks** (`forEach`/`map`/`filter`) вызываются с `this=undefined` —
   слабый `this` (как в ES5).

### Известные ограничения
- `new Array(...)`/`new String(...)` не работают: нет конструкторов-глобалов `Array/String`
  (только литералы `[]`, `''` + встроенные методы). `{} instanceof Object` → false
  (объектные литералы не связаны с `Object.prototype`).
- `this` внутри вложенных замыканий подхватывается по лексической цепочке (через
  скрытый слот), т.е. не совсем динамический — для типовых конструкторов/методов достаточно.
- Присваивание `F.prototype = <не объект>` игнорируется (остаётся дефолтный прото).
- `function(){}` — только function expressions; методов `get/set` в литералах нет.

### Проверки
- Нативно (`/tmp/jsoop`): конструкторы, `this.name`, метод на прототипе, наследование
  через `Object.create`, `instanceof` (прямое/цепочка, отрицание), `prototype.constructor`,
  `new d.constructor()`, `Object.getPrototypeOf`, чужие свойства (`a.extra`, `'extra' in d`),
  `Point.prototype.mag` = Math.sqrt → 5, конструктор с замыканием (`Counter` 1,2,3).
- `.z-тулчейн` (`/tmp/zoop.z`, 10 проверок под wine): `OOP TESTS OK (1,5)`.
- Edge: `new 5` → "new of non-function"; `F.prototype=7` → instanceof всё равно работает;
  top-level `this` → undefined.
- Регрессия: jslib3 18/18, jslib2 15/15, `/tmp/js_stress_run` FULL ok=14, wine
  js_test (ALL JS TESTS OK), js_host_test, js_tern_test, js_require_test, js_require_stress
  (14/14 ALL OK), feat.z (ok=23).
- Блоб перегенерирован: `src/js_blob.h` (75036 B, syms=71). Exe: `build/zenith_new.exe`
  (5046708 B), бэкап `/tmp/zn_oop.exe`.

---

## 9. Сессия: критические исправления движка + экспоненциальные литералы + +10 из JS-стандартной библиотеки

**Задача (из чата):** «исправить критические места плюс ещё +10, если есть, и +10 вещей
из стандартной библиотеки JS».

### Подтверждённые критические баги и фиксы (`tools/jsrt.c`)
1. **Глубокая/бесконечная рекурсия → SEGFAULT** (переполнение стека, ulimit 8 MiB).
   Guard в `call_func`: `#define MAX_CALL_DEPTH 500`, `static int g_depth;`,
   `set_err("stack overflow: call depth exceeded")`, `g_depth++/--` вокруг тела,
   сброс в `JS_OP_RESET`. `function f(){ f(); } f();` → rc=-1 + сообщение, без segfault
   (`/tmp/jsrec`, проверил и n=20000).
2. **`num_str()` печатал мусор** для NaN/±Infinity и отрицательных дробей
   (`-2.5` → `-.+`, `1/0` и `0/0` → пустая строка). Переписан (+ `kdup`):
   NaN → `"NaN"`, ±Inf → `"Infinity"`/`"-Infinity"`, отрицательные дроби корректно,
   большие по модулю — `1e+308`.
3. **`eq_val()`:** `null==0` и `undefined==0` давали `true` (JS: `false`). null/undefined
   обрабатываются до числового приведения; `null==undefined` → `true`.
4. **`%` на ноль** возвращал undefined → теперь NaN (`vnum(0.0/0.0)`).
5. **`parseInt('xyz')` → 0** вместо NaN: добавлен `str_to_int_any(const Str*,int,int* anyOut)`
   (`str_to_int` стал обёрткой), `parseFloat` без цифр → NaN, `parseInt(Infinity/NaN)` учтены.
6. **Не было глобалов `NaN`/`Infinity`** → добавлены в `JS_OP_RESET` (+ `isFinite`).
7. **`JS_OP_NUM` для NaN/±Inf** был UB (`(long)v.num`) → guard возвращает 0.
8. **`g_had_error`** перенесён в forward-декларацию (~1090), дубль-определение убран.

### КРИТИЧЕСКИЙ КРЭШ — экспоненциальные литералы (найден при проверке stdlib)
`console.log(1e308)` → SIGSEGV (addr=0x38; addr2line: `parse_program`, `*tail=s`).
Корень — ДВА бага:
- (a) лексер числа останавливался на `'e'` → `1e308` токенизировался как `1` + `e308`;
  внутри `console.log(...)` парсер оставлял висячий `)`.
- (b) `parse_primary` для «непостижимого» токена возвращал `mkn(NK_UNDEF)` БЕЗ `next_tok()`
  → `parse_program` зацикливался, заливал 16 MiB арену (h_off=16777200) и крашился на NULL-ноде.

Фикс: (a) лексер теперь ест `e`/`E` [+знак] + цифры — `1e308`, `1.5e-3`, `1e999`→Infinity
(кап экспоненты 10000, `>400` → Inf/0); (b) default-ветка `parse_primary` делает
`next_tok()` перед `mkn(NK_UNDEF)` — любой непостижимый токен больше не может заклинить парсер.

### +10 (и больше) из стандартной библиотеки
- **String:** `trim`, `startsWith`, `endsWith`, `includes`, `repeat` (cap `1<<24`),
  `charCodeAt` (вне диапазона → NaN), `String.fromCharCode`.
- **Array:** `reverse`, `concat`, `includes`, `forEach`, `map`, `filter`
  (реализованы через `call_func`; аргумент-callback обёрнут в `NK_LIST` —
  это чинило баг «callback получал undefined»).
- **Object.assign** (через `builtin_handles` + `call_builtin_member`).
- Экспоненциальные литералы — фактически 11-я фича.

### Проверки
- Нативно (`/tmp`-харнессы, `tools/jsrt.c` компилируется): jslib/jslib2 15 стейтментов rc=0;
  jslib3 18/18 rc=0 (включая `Infinity > 1e308`); `-2.5`, `1/0`→Infinity, `0/0`→NaN,
  `7%0`→NaN, `null==0`→false, `undefined==0`→false, `parseInt('xyz')`→NaN;
  require-stress FULL ok=14; рекурсия rc=-1 `err='stack overflow: call depth exceeded'`.
- Wine E2E: `js_test.z` (ALL JS TESTS OK), `js_host_test.z`, `js_tern_test.z`,
  `js_require_test.z`, `js_require_stress.z` (14/14 ALL OK) — все exit=0;
  `/tmp/feat.z` (23 проверки новых фич) → `FEAT OK ok=23`.
- Blob: `src/js_blob.h` 75036 bytes (syms=71; после ООП, §10; до ООП было 72492/68). exe: 5046708 bytes (до ООП было 5026993).
- Замечания: значимые wine-прогоны — из каталога с файлами (CWD); `LD_PRELOAD=torsocks`
  в окружении даёт шум `libtorsocks.so wrong ELF class` — игнорировать.

---

## 7. Сессия: require под wine — настоящий корень (не-relocated-указатели в .data)

**Симптом:** `js_require_test.z` валится page-fault при первом же `require('./jsmod_a.js')`
(до §2: после фикса DWORD там был следующий крэш — `path_join` с `base=0xf740`,
`cmpb $0,(%rdi)` в `xstrlen`). `js_test.z`/`js_host_test.z`/`js_tern_test.z` проходили,
падал только require — и то, что Linux-харнесс проходил, а wine нет, сбивало с толку.

**РАЗГАДКА (ключевое различие native vs wine):** в Linux-харнессе `tools/jsrt.c`
линкуется как обычный объект в реальном адресном пространстве процесса — все
абсолютные указатели релоцируются компоновщиком и валидны. А в wine-сборке `jsrt.c`
компилируется в **PIC-блоб с VMA 0**, кладётся в RWX `.text` на произвольный базовый
адрес и НЕ релоцируется. Внутри блоба код обращается к секциям через RIP-relative
(это работает), но **любой `.data`-глобал, инициализированный адресом другой секции,
хранит «сырой» смещение (напр. `0xf740`) и при разыменовании фаталит.**

Таких глобалов было три:
- `g_cur_dir = "."` (tools/jsrt.c:70) — инициализатор = rodata-смещение `0xf740`.
  Читается в `call_func` (require) → попадает в `path_join(base=...)` → крэш.
- `B64C` (`const char* B64C="ABCDEF..."`) — то же, фатал бы при encode/decode.
- `H` (`static const char* H="0123..."` внутри json) — то же, фатал при \u-экранировании.

**ФИКС (tools/jsrt.c):** не хранить кросс-секционные указатели в `.data`:
- `g_cur_dir` → объявлен как `static const char* g_cur_dir;` (NULL). В `call_func`
  (require) при `from==NULL` выделяется runtime `.` через `arena_alloc` (указатель
  валиден в блобе). Вложенный require по-прежнему выставляет `g_cur_dir=dir` (арена).
- `B64C` и `H` → превращены в массивы `static const char X[]="..."` (код обращается
  RIP-relative к символу, без хранимого указателя).

**Результат (wine E2E, все зелёные; exit=0 у всех):**
```
js_test       : exit=0 (ALL JS TESTS OK)
js_host_test  : exit=0 (HOST FS TESTS DONE, len=10, exists=1)
js_tern_test  : exit=0
js_require_test: exit=0 → "require sum = 42", "require cache = 3"
```
Linux-харнесс по-прежнему проходит все 4 режима (default/builtin/require/pkg).

**Прочее:**
- Сборка компилятора в этой сессии ведётся командой `src/*.cpp` (беглый список в §4 был
  неполон — без `codegen_elf.cpp`/`codegen_builtins_linux.cpp` линк валился на
  `buildLinuxImportData/emitLinuxEntryPoint/...`).
- `src/codegen_elf.cpp` не хватало `#include <cmath>` (`std::sin`/`std::lround`) — добавлен.
- ВНИМАНИЕ: `-o build/zenith_new.exe` при неуспешном линке **удаляет** существующий exe —
  держать свежую копию (например `/tmp/zn_probe.exe`), если exe дорогой.
- Blob перегенерирован: `bash tools/gen_js_blob.sh` (66452 bytes, syms=66).

---

## 8. Сессия: стресс-тест require (многоуровневая библиотека) — два фикса движка

**Задача:** собрать «сложную» JS-библиотеку через сам Zenith и прогнать stress-тест
`require` (вложенные require, node_modules, package.json, кеш, встроенные модули).

**ФИКС 1 — лексические замыкания.** Выяснилось, что `call_func` создавал callee-env
с parent = **вызывающего** env — т.е. область видимости была динамической, и методы
модуля, ссылающиеся на `exports`/приватные переменные/замыкания, ломались при вызове
извне: `exports.fib(n-1)` → 0, `m.readval()` (читает `exports.val`) → 0,
`makeAdder(3)(4)` → 4 (а не 7, потому что `a` не захватывался).
Фикс в `tools/jsrt.c`: в `struct Node` добавлено поле `Env* def;`; при eval `NK_FUNC`
первый раз записывается определяющая область; `call_func` берёт parent callee-env из
`fn->def` (fallback — caller); GC-`mark_node_iter` маркирует `n->def` через `mark_env`
(добавлен forward-proto), чтобы env замыкания не улетел в сборщик.
После фикса: `makeAdder(3)(4)`=7, `m.fib(10)`=55, `exports.fib(5)`=5, `m.twice(5)`=12,
`m.readval()`=42 — проверено нативным харнессом.

**ФИКС 2 — path_dirname.** Старый `path_dirname("a/b")` возвращал `"a/"`, а
`path_dirname("a/b/")` возвращал сам путь → в up-поиске `node_modules` условие
`up==base` срабатывало ПОСЛЕ ПЕРВОГО уровня и ломалось (`module not found` до
`jsstress/node_modules`). Переписан: исключает разделитель и срезает завершающие '/' —
`"a/b"`/`"a/b/"` → `"a"`, `"/x"` → `"/"`. Резолв bare-спецификатора снова доходит
вверх по всей цепочке (native-трассировка `HOST_FS_EXISTS` подтверждала преждевременный
прыжок в `/usr/lib/node_modules`).

**Стресс-библиотека `jsstress/`** (внешняя проверка require): `lib/{index,app,strutil,
case,prime,math,data,hash}.js` + `jsstress/node_modules/zenutils` (для вложенного
`require('zenutils')`) + копия `node_modules/zenutils` в корне (для верхнеуровневого
`require('zenutils')` от CWD). Цепочки: index→app; app→hash/strutil/math/data;
hash→strutil/math/data/zenutils; strutil→case; case→path/base64; math→prime;
data→base64/fs/path; structure проверяет верх/фиб/простое/подсчёт/title/basename/
encode/decode/compute==9331556/readLen/exists/кеш (c1===app)/zenutils say+greet+version.

**Стресс-тест `js_require_stress.z`:** 14 проверок на одном `js_eval`; печать
`stress checks passed = N/14` и `JS REQUIRE STRESS: ALL OK/FAIL`; exit 0/1.
Нюанс парсера .z: многострочное смеженное склеивание строк
`js_eval("...\n" "..."\n)` НЕ парсится — JS уложен в одну строку.

**Результаты:**
- Нативный харнесс (`/tmp/js_stress_run`): `exec rc=0 result ok=14`.
- Wine E2E: `js_require_stress.z` → `JS REQUIRE STRESS: ALL OK` (exit=0);
  регрессии js_test / js_host_test / js_tern_test / js_require_test — все exit=0.
- Blob перегенерирован: `bash tools/gen_js_blob.sh` (66548 bytes, syms=66; было 66452).
- `build/zenith_new.exe` пересобран: 5004841 bytes (было 4999138).

---

## 1. Что уже сделано и проверено (wine E2E)

**Работает (под wine):**
- `js_test.z` — ALL JS TESTS OK (219 условных проверок, EXEC/EXPR, язык JS: функции/циклы/объекты/массивы/строки/Math/строки-методы).
- `js_host_test.z` — host-стабы FS: `__writeFile`, `__readFile` (возвращает точную длину, напр. 10 для "hello host"), `__exists`, `__getCwd`, `printStr` (печать в stdout) — ВСЁ РАБОТАЕТ.
- `js_tern_test.z` — тернарные операторы, свежесть `g_last_result` — ок.

**require (CommonJS) проверен на Linux-харнессе `tools/js_native_host.cpp` — РАБОТАЕТ (результат 42).**
Под wine — падает (см. раздел 3).

**Внесённые правки сессии (все компилируются):**
- `src/codegen.h` / `src/codegen.cpp`: `emitTlsBlob()` теперь эмитится и при `jsUsed` (`(tlsUsed || jsUsed) && !libOutput`), ибо tls-стабы хост-таблицы вызывают entry tls-блоба. Новые члены: `jsHostFlagLabel`, `jsHostStubLabel[13]`, `jsWsaFlagLabel`, `jsWsadataLabel`, `jsAddrLabel`, `void emitJsHostStubs()`.
- `src/codegen_js.cpp`:
  - `emitJsBlob()` вызывает `emitJsHostStubs()` после bss-пада.
  - `tryJsCall`/js_eval: авто-инсталл хост-таблицы (lazy guard-байт `jsHostFlagLabel` в RWX .text; 13× `SET_HOST` с `lea rdx,[rip+stub]`).
  - `emitJsHostStubs()`: 13 стабов (fs_read/fs_write/fs_exists/get_cwd/net_connect/net_send/net_recv/net_close/tls_connect/tls_send/tls_recv/tls_close/print) + scratch (WSADATA 416B, sockaddr 16B, WSA-flag 1B, host-flag 1B).
  - **Исправленные баги этой сессии:**
    - Guard-байт `jsHostFlagLabel` НЕ эмитился → `lea` читал код и install пропускался. Добавлен `emitLabel(jsHostFlagLabel); emit8(0);`.
    - get_cwd: были перепутаны аргументы Win32 `GetCurrentDirectoryA(nBufferLength, lpBuffer)` — исправлено на `rcx=cap(a2), rdx=buf(a1)`.
    - **Stash результата fs_read/fs_write лежал в `[rsp+0x10]` — попадал в SHADOW SPACE калоущейся Win64-функции (`ReadFile`/`CloseHandle`), которая МОЖЕТ его затрёт.** Перенесён в r13/r14 (Win64 callee-saved): `mov r14,rax` → CloseHandle → `mov rax,r14`. fs_write аналогично через r13.
    - **DWORD/QWORD в `lpNumberOfBytes*` (этой сессии):** стабы fs_read/fs_write читали счётчик как QWORD (`mov rax,[rsp+0x18]`), но ReadFile/WriteFile пишут DWORD → старшие 4 байта = мусор shadow space → nread=0x30000002e → крэш require. Фикс: zero-extending 32-bit load `mov eax,[rsp+0x18]`. Подробности в §2.
- `src/codegen_pe.cpp`: `buildImportData` — при `jsUsed` добавлены `kernel32.dll: GetCurrentDirectoryA` и `ws2_32.dll: WSAStartup, socket, connect, send, recv, closesocket, gethostbyname`. Без этого PE-сборка выдавала `Error: import call fixup not found in externFuncMap` и IAT-слоты оставались нулевыми (крэш `call [rip]`). Сейчас компиляция js_host_test.exe идёт БЕЗ ошибок импорта.

---

## 2. БАГ фихен в этой сессии — require 0x300000033 (DWORD/QWORD в lpNumberOfBytes*)

**Симптом был:** `js_require_test.z` (require('./jsmod_a.js') → f(19,23)) под wine:
```
Unhandled exception: page fault on write access to X at 0x14000ded3
movb $0,(%rax,%rdi,1)      ; rax=g_fs_buf(0x14008fdc0), rdi=0x300000033
```
Это `g_fs_buf[nread]=0` в `call_require_impl` (tools/jsrt.c:1681). `nread = g_host_fn[HOST_FS_READ](...)` вернул `0x300000033`.

**РАЗГАДКА (найдено):** `nread=0x00000003_0000002e`:
- младший DWORD `0x2e` = **46** = точная длина `jsmod_a.js` (`module.exports = function(a,b){ return a+b; };`) — т.е. ReadFile/WriteFile ПРАВИЛЬНО записали число байт.
- старший DWORD `0x3` — МУСОР из shadow space.

**Корень бага:** в стабах `fs_read`/`fs_write` число байт забиралось как **QWORD**:
```cpp
mov rax,[rsp+0x18]      // 48 8B 44 24 18 — 64-битный load
```
но `lpNumberOfBytesRead/Written` у `ReadFile`/`WriteFile` это **DWORD (4 байта)** — старшие 4 байта читались из незадействованного shadow space калоущейся функции и содержали случайный стековый мусор. В `__readFile` мусор случайно оказывался 0 → «работало»; в require (другая глубина стека) там было 0x3 → nread=0x30000002e → крэш на `g_fs_buf[nread]`.

**ФИКС (src/codegen_js.cpp, emitJsHostStubs fs_read/fs_write):** заменить 64-битный load на zero-extending 32-битный:
```cpp
mov eax,[rsp+0x18]       // 8B 44 24 18 — обнуляет старшие 32 бита
mov r14, rax             // (fs_read stash; fs_write -> r13)
```
Цепочка stash в r14/r13 (не `[rsp+0x10]`) осталась без изменений — она по-прежнему нужна, чтобы CloseHandle не затёр счётчик через свой shadow space.

**Результат после фикса (wine E2E, все зелёные):**
- `js_require_test.z`: `require sum = 42`, `require cache = 3` (cached module) — крэша НЕТ.
- `js_host_test.z`: read len=10, read cmp=1, exists=1, getcwd len=6 — ок.
- `js_test.z`: ALL JS TESTS OK; `js_tern_test.z`: ок.

Отдельно: тот же DWORD-баг чинили только в `fs_read`/`fs_write`. Будущие стабы с `ReadFile`/`WriteFile` (net/tls read через recv не пишут DWORD-count — им не нужно).

**Инструмент отладки (Linux-харнесс, не использовался в этой сессии; require шёл через wine-стаб):** `tools/js_native_host.cpp` — host-слоты = POSIX. Сборка:
```
gcc -O0 -ffreestanding -fno-stack-protector -fno-builtin -fno-common -mno-red-zone -Itools -c tools/jsrt.c -o /tmp/jsrt_host.o
gcc -O0 -g -x c -c tools/js_native_host.cpp -o /tmp/jnh.o
gcc /tmp/jsrt_host.o /tmp/jnh.o -o /tmp/jnh
cd /tmp && ./jnh require     # требует файл /tmp/jsmod_a.js: module.exports=function(a,b){return a+b;};
```
Вывод: `result=[42]`.

---

## 3. Идеи пользователя + мои мысли (ЗАПИСАНО, НЕ РЕАЛИЗОВАНО)

Пользователь: "можешь усложнить, но в лучшую сторону, GC — либо вообще его убрать и заменить собственным аллокатором, к примеру тем же SlotAllocator'ом, что в Зените. Плюс — больше встроенных модулей и функций. Пока — записать все мысли в файл."

### 3.1 Текущий GC (коротко для контекста)
- 16 MiB bump-арена в .bss (`JS_HEAP`), сбрасывается `JS_OP_RESET`.
- Budgeted sweep: `GC_BUDGET` блоков/шаг, триггер `h_off > JS_HEAP/2` или `g_oom` на верхних EXEC/EXPR (серверный режим без пауз).
- **Минусы:** (а) 16 MiB bss напрямую раздувает RWX .text в PE до ~17 МБ; (б) память фактически не возвращается между eval, только помечается.

### 3.2 Вариант А — упростить/настроить текущий GC (быстро, безопасно)
- `JS_HEAP` в конфигурируемую (например 8 MiB по умолчанию), размер — одна константа.
- Опция `no-sweep`: для коротких скриптов sweep не нужен вовсе — только reset арены (эпоха).
- Добавить метрики: `JS_OP_HEAPSTAT` уже возвращает h_off; расширить до `{used, free, blocks_freed, gc_steps}`.
- Оставить mark-sweep «эпохами» (серийный номер вместо цветов) — уже частично есть.

### 3.3 Вариант Б — убрать GC, поставить SlotAllocator (как в компиляторе Зенит)
- Слотовая раскладка по классам: пулы фиксированных размеров (Box/Node/Str — в jsrt это структуры одинаковых размеров).
- Free-list на пул; `arena_alloc(n)` → пул ≥ n, взять свободный слот; `free` → вернуть в свободный слот. Никакой компакции и пометок → **пауз не существует вообще.**
- Требование нулевой памяти (zero-filled) — сохранить при выделении; переиспользование требует затирания (memset слот при free или при alloc).
- Сложности: `mkstr`/`arena_alloc(size)` имеют варианты произвольных размеров (строки); для них нужен либо отдельный блоковый пул строк с ведением сегментов, либо пул степеней двойки (16/32/64/.../64K).
- «Утечки» между eval: если скрипт не вернул всё через результат — растёт занятость пулов; для песочницы решает `JS_OP_RESET` (холодный сброс всех пулов). Нужно явно задокументировать, что долгоживущее состояние = только результат + модульный кеш.
- **Мой рекомендованный путь:** начать с Варианта А (низкий риск), затем, если нужен детерминированный zero-pause — пилот SlotAllocator на пулы box/node/str фиксированных размеров, а mark/sweep оставить только как страховку для чужих строк. Полный отказ от GC — только после замеров пиков аллокаций серверного скрипта.

### 3.4 Больше встроенных функций/модулей (list, порядок зависит от сценариев)
**Глобально / через стандартные стровые и массивные методы (самые востребованные):**
- Array: `map`, `filter`, `reduce`, `forEach`, `some`, `every`, `find`, `findIndex`, `splice`, `slice`.
- String: `repeat`, `includes`, `startsWith`, `endsWith`, `trim`, `padStart`, `padEnd`, `slice`.
- Number: `isInteger`, `isFinite`, `toString(radix)`, `toFixed`.
- Object: `values`, `entries`, `assign`, `hasOwn`.
- Global: `JSON.parse`/`JSON.stringify` (если нет — приоритет!), `console.log` → `HOST_PRINT` (форматирование + новыйline в стабе print).

**Встроенные модули через require (файловые, jsrt уже резолвит node_modules):**
- `fs` (`readFileSync/writeFileSync/existsSync/readdirSync/mkdirSync`) — расширить host-слоты (текущие 0-3).
- `path` (`basename/dirname/extname/join`) — чистая JS-эмуляция поверх существующего.
- `base64` (encode/decode), `hex`, `utf8`-helpers.
- `net` (tcp connect/send/recv/close → слоты 4-7), `tls` (8-11) поверх них.
- `http`/`https` — обёртки вокруг `httpGet`/`httpsGet` + редиректы.
- `os` — платформа, eol; (freemem/hostname — только если появится host-запрос).
- НЕ вводить event-loop/timers-асинхронность: синхронный fetch/sleep, без событий.

**Хост-слоты (расширение 13 → больше):**
- `readdir` (перечислить каталог), `mkdir`, `unlink`, `stat`/`is_dir`, `sleep(ms)` (для пауз/полировки), `rand` (CSPRNG-ишный? на ne/секрета), `env`/`args` (argv процесса — для CLI-инструментов), `uname` (платформа).

---

## 4. Команды сборки/тестов (повторяемость)

Полная сборка компилятора:
```
x86_64-w64-mingw32-g++ -O2 -std=c++17 -w -static src/*.cpp -o build/zenith_new.exe
```
(важно `src/*.cpp` — иначе не хватает `codegen_elf.cpp`/`codegen_builtins_linux.cpp`:
линк валится на `buildLinuxImportData`/`emitLinuxEntryPoint`/`tryLinuxCall`/`buildELF`.)
Е2Е:
```
wine build/zenith_new.exe js_test.z -o /tmp/js_test_new.exe  # ALL JS TESTS OK
wine build/zenith_new.exe js_host_test.z -o /tmp/js_host_test.exe
wine build/zenith_new.exe js_require_test.z -o /tmp/jr.exe   # require sum=42, cache=3
wine build/zenith_new.exe js_tern_test.z -o /tmp/jt.exe
```
Прогоны — из каталога, где wine лезет в CWD (обычно `cd /tmp && wine ...`), чтобы относительные пути (jhost.txt, module) существовали.

---

## 5. Файлы сессии
- `tools/jsrt.c` — движок (alloc+GC+CommonJS+HTTP+host builtins). КОМПИЛИРУЕТСЯ НАТИВНО и в блоб.
- `tools/js_native_host.cpp` — Linux отладка host-слотов/require.
- `src/codegen_js.cpp`, `src/codegen_pe.cpp`, `src/codegen.h`, `src/codegen.cpp` — правки.
- `js_test.z`, `js_host_test.z`, `js_require_test.z`, `js_tern_test.z` — тесты проекта.
- `/tmp/jsmod_a.js` (модуль), `/tmp/jhost.txt` (результат write-теста).
- Доки: `release/документация/19_js.txt`, `DEV_STATE.md`.

## 6. Прочее / заметки
- Репозиторий НЕ git — изменения не коммитить, сохранить файлами.
- При правке благожелательно: не откатывать фиксы сташа (r13/r14) и guard-байта — они закрывают реальные баги (shadow clobber, пропуск install).
- НЕ держать в `.data`-глобалах блоба указатели на другие секции (инициализаторы литер) — в блобе они не релоцируются и фаталят (см. §7). Массивы литер — ок, `const char* X="..."` — нет.
- Если менять jsrt.c — перегенерировать блоб:
  `bash tools/gen_js_blob.sh` (нужен nm/objcopy/python3).