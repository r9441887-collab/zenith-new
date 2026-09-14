# СЕССИОННАЯ ЗАПИСКА — npm на встроенном JS-движке (regex)

> Пользователь выключил комп посреди задачи. Это план продолжения.
> Дата: 2026-09-09. Готово уже много: async, stdlib — см. JS_ROADMAP.md §11-12,
> release/документация/19_js.txt.

## Задача
Заставить реальные npm-библиотеки работать на встроенном JS-движке `tools/jsrt.c`.
Установлен проект `npm_demo/` (ms, papaparse, marked@0.3.19, semver) + демо
`npm_demo/demo.js`. Под node всё работает (эталонный вывод: `/tmp/node_out.txt`).

## Текущее состояние
- Движок нативно собирается: gcc -O0 -ffreestanding -fno-stack-protector -fno-ident
  -fno-asynchronous-unwind-tables -fno-builtin -fpic -fno-common -mno-red-zone
  -Itools -c tools/jsrt.c -o /tmp/jsrt_o.o
- Полный `demo.js` на движке: SIGSEGV (rc=139).
- Изолированные require: ms / papaparse / marked → rc=1
  `parse error: unexpected input` на токене `/` (regex-литерал). semver → SIGSEGV
  (разбираться после regex; вероятно `new RegExp(...)` из строк и/или внутренние
  require).
- ПРИЧИНА: парсер движка не умеет regex-литералы `/.../`. Решение: реализовать.
- Бэкапы exe: /tmp/zn_oop.exe (до async), /tmp/zn_asyncc.exe (после async до stdlib).

## ПЛАН РЕАЛИЗАЦИИ MINI-REGEXP в tools/jsrt.c
Всё в одном файле. Ориентиры:
- Токены: `#define T_*` до 64 (блок ~302-349), последний T_AWAIT=64.
  Добавить `#define T_REGEX 65`.
- Лексер `next_tok()` ~375-457, `Token` struct ~351, enum T_* ~294-349.
- Парсер `parse_primary()` ~585-620, Node kinds `NK_*` ~238-270, `eval()` switch.
- `call_method_v` — ветки V_ARR и V_STR (падёж для regex+V_OBJ отсутствует — это
  облом: regex-бокс это V_OBJ, дописывать обработку).
- `call_global` для глобалов (там register 'RegExp').
- RESET/init ~3800+ регистрирует глобалы (там же `make_native_method("promise","ctor")`).

### Шаг 1 — Лексер
1. `#define T_REGEX 65` в блоке токенов; в `Token` добавить поле `u64 fl` (флаги).
2. Глобальный `static int g_regex_ok;` — TRUE если `/` в EXPRESSION-позиции.
3. В `next_tok()` В НАЧАЛЕ (после пропуска ws/комментариев), если c=='/' и
   g_regex_ok и след. символ != '=': сканировать regex-литерал:
   - прочесть `/`, затем паттерн: `\` + след символ проскакивать (2 символа);
     внутри `[...]` символ `/` НЕ закрывает класс; искать закрывающий `\`-free `]`.
   - закрывающий `/`; затем флаги [a-zA-Z]* (i,g,m,s → биты 1,2,4,8; остальные
     игнорировать/ошибка на неизвестных).
   - сохранить паттерн в `t->str` (arena), длину в `t->slen`, флаги в `t->fl`,
     `t->kind=T_REGEX`.
   - Затем ОБЯЗАТЕЛЬНО вычислить g_regex_ok для следующего токена.
   - Раскомментировать/расширить: обычный `/` → T_SLASH (деление).
4. В конце `next_tok()` (перед `return` в каждом case) ставить g_regex_ok:
   - 0 после: T_IDENT, T_NUM, T_STR, T_BACKTICK, T_REGEX, T_RPAREN, T_RBRACK,
     T_RBRACE, T_PLUSPLUS, T_MINUSMINUS, T_INSTANCEOF, T_THIS.
   - 1 после всего остального (операторы, ключевые слова, открывающие скобки,
     T_SEMI, T_COLON, T_COMMA, T_ASSIGN и т.п.).
   - инициализировать g_regex_ok=1 при начале парсинга программы (найти, где
     делается первый next_tok для скрипта).

### Шаг 2 — Парсер
1. `#define NK_REGEX 38` рядом с NK_* (там до 36 + NK_NATIVE 99).
2. `parse_primary()`: `case T_REGEX: { Node*n=mkn(NK_REGEX); n->key=kerndup(g_tok.str);
   n->ival=(int)g_tok.fl; next_tok(); return n; }`
3. `eval()`: `case NK_REGEX:` → `make_regex_box(n->key, n->ival)` (см. Шаг 4).

### Шаг 3 — Матчер/VM (новый блок кода, ~300 строк, вставить перед call_method_v)
AST: `typedef struct RNode { int kind; long c,min,max; int greedy,cap,neg;
u64* r; int nr; RNode*a,*b; } RNode;`
kinds: 1 CHAR, 2 CLS, 3 ANY, 4 CONCAT, 5 ALT, 6 REP, 7 GRP, 8 ANC, 9 EMPTY.
Компиляция паттерна (рекурсивный парсер строки):
- parse_alt → parse_seq ('|' parse_seq)*  → ALT
- parse_seq → parse_rep*
- parse_rep → parse_atom + суффикс `*`(0,MAX,greedy) `+`(1,MAX) `?`(0,1)
  `{n}`,`{n,}`,`{n,m}` (MIN,MAX,greedy; lazy если след `?`)
- parse_atom:
  - `(`: `(?:` → GRP cap=0; `(?!`/`(?=`/`(?<=` — НЕ поддерж. (ошибка компиляции,
    библиотека с lookahead не загрузится — ок); иначе GRP cap=++ncap.
  - `)` конец группы. `[` → CLS: not-флаг `^` в начале, диапазоны lo-hi и одиночные,
    escapes `\d\w\s` ВНУТРИ класса тоже надо (хотя бы `\\`, `\]`, `\-`, `\n\t\r`).
  - `\` escape: d,D,w,W,s,S,b,B,n,t,r,f,v, `\0`, и прочие `\X` = CHAR X.
  - `.` → ANY. `^`,`$` → ANC(1/2). `|` обрабатывается в parse_alt.
  - прочее → CHAR(c).
Флаги: F_I=1, F_G=2, F_M=4, F_S=8 (глобал или field в matcher).
Матчер: бэктрекинг.
```
static long rm(RNode* nd, const u8* s, long n, long pos, long* cap, long* out);
```
- CHAR: pos<n && (fI? ci_eq : eq) → pos+1.
- ANY: pos<n && (fS || s[pos]!='\n') → pos+1.
- CLS: membership (родинг в range, уважать not, ci для одиночных) → pos+1.
- CONCAT: пройти детей по цепочке, вернуть pos или -1.
- ALT: сперва a потом b.
- REP: greedy → для k=max..min c шагом -1: пройти k повторов атома (каждый атом
  матчится и НЕ должен давать pos==pos_на_входе если k ещё можно — защита от пустых
  циклов: если очередной атом дал 0-ширину, уменьшить k и выйти), при успехе идти
  далее; ленивый → наоборот от min..max.
- GRP: если cap>0: cap[cap*2]=pos, после успеха cap[cap*2+1]=новыйpos.
- ANC: ^ → (fM? pos==0||s[pos-1]=='\n' : pos==0); $ → (fM? pos==n||s[pos]=='\n' :
  pos==n); \b → граница слова (isalnum_ по нашим байтам) на pos; \B — отриц.
Поиск первого совпадения: позиции 0..n (если паттерн начинается с ANC(^) — только 0).
Учитывать lastIndex при флаге g (для while((m=/g/.exec(s)))).

### Шаг 4 — Регэксп-бокс и API
- B окс: `"$kind"="regex"`, `"$src"`=паттерн (Val str), `"$fl"`=vnum(флаги),
  `"$rp"`=vnum((u64)RNode*) — кэш скомпиленного AST, `"$last"`=lastIndex.
  `make_regex_box(src, fl)` → new_box + сетнуть ключи. `is_regex(Box*)`.
- `RegExec(regexVal, strVal)` → целевой матч-бокс: элементы [0]=вся, [1]..=группы
  (V_STR; негативный cap→vundef), named-ключи "index" (vnum), "input" (str);
  обновить "$last" (g: конец матча; нет матча: 0). Ошибка компиляции → set_err.
- `RegTest(regexVal, strVal)` → vbool.
- `call_method_v`, в base V_OBJ+is_regex: test, exec, source (→str), flags(→str),
  toString (→ source). СТАВИТЬ ВЫШЕ веток V_ARR/V_STR.
- Глобал `RegExp`: `call_global` case "RegExp": если 1 арг — V_OBJ+is_regex →
  вернуть тот же (или новый из src); иначе new box из строки паттерна + флагов.
  В RESET/init: env_def(глобал,"RegExp",make_native_method("regexp","ctor")) и в
  call_func NK_NATIVE dispatch (~2913) добавить `if(ml==6&&mem_eq(mod,"regexp",6))`
  → ctor: вернуть make_regex_box из args (поддерживает и `new RegExp`).
- String методы (в ветке V_STR call_method_v; есть текущие методы:
  split уже существует строкой в js_str_split — расширить его):
  - `search(re)` → index первого матча (regex или строка через str_find) или -1.
  - `match(re)` → если g: массив всех матчей (V_ARR) или vnull; иначе exec-бокс/vnull.
  - `replace(a,b)`: a строка → заменить ПЕРВОЕ вхождение строковой подстановкой;
    a regex без g → первое; с g → все. b строка: поддержать `$$`,`$&`,`$1..$9`;
    b функция → call_func(f, полный, группы..., offset, исходная строка), результат
    подставить.
  - `split(re)` → regex-версия: резать по матчам (без захвата групп в результат),
    для papaparse важна форма split(/(\r\n|\n|\r)/gm).

### Шаг 5 — Сборка и тесты
1. Нативно: пересобрать /tmp/jsrt_o.o, прогнать существующую регрессию:
   /tmp/jslib3, /tmp/jslib2, /tmp/js_stress_run, /tmp/jsasync, /tmp/jsstd —
   всё должно быть зелёным.
2. Написать нативный тест /tmp/jsregex (как /tmp/jsstd): test/exec/match/
   replace/split/search, группы, квантификаторы, флаги g/i/m/s, классы, \b\d\w\s,
   ленивые кванторы, `RegExp(...)` и `new RegExp(...)`.
3. `npm_demo`: сначала `require('ms')` (эталон node: /tmp/node_out.txt), потом
   papaparse, потом semver (разобрать его SIGSEGV), потом marked@0.3.19 если дойдёт.
   Запуск: `/tmp/jsrun <скрипт>` с CWD=npm_demo.
4. Блоб: `bash tools/gen_js_blob.sh` → src/js_blob.h → собрать exe на mingw:
   x86_64-w64-mingw32-g++ -O2 -std=c++17 -w -static src/*.cpp -o build/zenith_new.exe
   (перед этим скопировать старый в /tmp/zn_xxx.exe).
5. Wine-прогон: js_test, js_host_test, js_tern_test, js_require_test,
   js_require_stress, feat.z, zoop.z, zasync.z, zstd.z — всё rc=0.
6. Доки: JS_ROADMAP.md §13 (regex), release/документация/19_js.txt (regex-раздел).
7. Отчёт пользователю по-русски.

## Критичные грабли (выстрадано)
- EXEC в харнессе: `jsrt_entry(EXEC, ptr, LEN)` — забытая длина = пустой парсинг →
  undefined (ложная тревога jsiv4-6).
- `env_find` возвращает `Node*`, значение — `node->val`; может вернуть NULL.
- Верхнеуровневый require резолвится от `g_cur_dir`/`.` → CWD процесса; раннер
  запускать с CWD=npm_demo.
- Массивы движка: индексы через позицию (arr_set_idx), named-ключи через box_set —
  у матч-бокса "index"/"input" работают.
- Всё аллоцируется из арены, сбрасывается на RESET — кэш AST в "$rp" держать как
  u64 через vnum; живёт пока жив бокс в арене.
- exec для /g-циклов обязан обновлять "$last" (иначе вечный цикл у semver/marked).
- `parse error: unexpected input` для ms = regex-литерал → сначала лексер, потом всё
  остальное.
- Ошибки компиляции regex (lookahead и пр.) — жизнь: не поддерж. → set_err, не
  валить процесс. SIGSEGV semver сейчас, вероятно, из-за `new RegExp` — после
  реализации перепроверить, если не уйдёт — отладить через gitless bisect в
  /tmp/ms_nc.js, /tmp/one.js (пошаговые запуски require).

## Полезные файлы
- tools/jsrt.c — движок (править здесь).
- npm_demo/ — package.json, node_modules, demo.js.
- /tmp/jsrun.cpp — универсальный раннер (читает .js, печатает __JS_RC__ и ошибку).
- /tmp/node_out.txt — эталон node.
- tools/js_native_host.cpp — референс-харнесс (слоты: 0-2 fs, 3 cwd, 12 print,
  13 exec, 14 mkdir, 15 readdir, 16 unlink, 17 sleep).
- tools/gen_js_blob.sh → src/js_blob.h; build/zenith_new.exe.