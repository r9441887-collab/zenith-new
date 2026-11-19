# ЗАВТРА: что делаем (передача между сессиями)

Актуально на **10.10**. План — `PLAN.md`; здесь — короткая передатка
и грабли. Шаги 1–6 старого selfhost-планa **выполнены**.

**Где стоим (конец 11.10, «часть 22»):** директива **«только syscall»
ЗАКРЫТА** — selfhost-кодоген не пушает импорты, `phnum = 2` всегда,
выход через `exit_group`; PT_INTERP/DT_NEEDED/GOT запрещены (ветка
`cgPushElfImport` отвечает ошибкой запрета). **`asm {}`/`asm32 {}` для
слоя 1 закрыты целиком** — включая перенос `validateAsmWidths`
(часть 22). Vulkan работает через
**собственный mini-dlopen в `cgEmitVkLoader` (`src/cg_elf.z`, emit8)**:
открытие `libvulkan.so.1`, mmap каждой PT_LOAD (bias
`0x600000000000 + idx*0x400000`, prot=7), релоки/IFUNC, `applyL ->
stubL` — неразвёрнутый диспетчер из **65 имён** (`st0..st64`), резолвящий
неопределённые символы libvulkan на **собственные стабы libc** (65 стабов:
память/строки, `__vsnprintf_chk`-семейство наивной копией формата,
`opendir`/`fopen`/`readdir` → NULL/−1 — «мир без файлов», `get*id` —
реальные syscall, `__ctype_tolower_loc` — таблица в rdata, `pow` → 0.0;
libc/libm/ld **не грузим вовсе**). `NODE_CAP` selfhost-парсера поднят
131072 → **262144** (тела загрузчика/стабов переполняли AST). vk-смоук
`tools/cgemit/vkrun.z`: статическая self-сборка и эталонная динамическая
печатают `4206592`/`4206831`, rc=0, **stdout побайтово идентичен**
(`cmp`); байтовый паритет `.elf` для vk невозможен по построению (у C++
остаётся `DT_NEEDED libvulkan/libc`) — поэтому в `tools/cgfront_check.py`
новая цель **`cgfront vk` — рантайм-паритет + статичность self**, а
байтовый диф-тест `vkrun.z` идёт в режиме B (`Makefile.linux`,
`CGEMIT_PROGS_B`). Контракт (свежий, 11.10): `timeout 2400 make -f
Makefile.linux test` → **`MAKE_RC=0`, 0 MISMATCH, 244 `OK` + 23 `match`**,
`python3
tools/cgimg_check.py` → 14/14 OK, U+FFFD по `src/*.z` — пусто.
Следующий по списку — **порт оптимизаций** (`selfhost/opt.z`, начат: см.
часть 22) → `.ko`-драйвер + `zenite` → слой 2 с WinPE. Порядок порта — PLAN.md.

Главное правило юнита: **`src/cg_elf.z` и `src/cg_*_blob.z` не UTF-8**
(сырые `0x92` в литералах) — править только bytes-путём
(`errors="surrogateescape"`); `edit`-инструмент уже один раз молча
испортил 455 байт через U+FFFD.

Продолжить ту же сессию ассистента: `./resume.sh`
(`opencode -s ses_ef94d40b7ffeIcSrwTcXyektWT`); часть 22 (asm + грабли
выше) делалась в продолжении (сессия 11.10).

**Правило (05.10): все переписанные `.z`-файлы полностью независимы от
C++.** Ни одного `use`/вызова/константы, которую нельзя разрешить внутри
`.z`-дерева; сборка только `build/linux/zenith` из одних `.z`. Ссылки
`codegen.cpp:NNN` в комментариях — провенанс (откуда портировано), не
зависимость; цифры и маски переносятся в `.z` буквально, и после удаления
C++-файла («Правило чистки» PLAN.md) тесты обязаны остаться зелёными.
Эталон `zenith --obj --no-opt` в `tools/cgemit_check.py` — верификационный
костыль, живёт только в тесте. Подробно — PLAN.md, «Полная независимость
от C++».

---

## Сделано 04.10 — шаг 2 (PLAN.md) ЗАКРЫТ

**`src/main.z` — полный порт `src/main.cpp`, кроме `--ir`.** Бинарник
`build/linux/zenith-z`.

- Сборка: `make -f Makefile.linux zdriver` (objcopy-переименование
  `zenith_obj_init` → `zenith_zmain_init`, `-Wl,-init,zenith_zmain_init`).
- Мост: `src/zffi.h` + `src/zffi.cpp` (временный плоский C ABI,
  `zprog*` = `Program*`, opaque).
- Портировано: `cmdNew`, `cmdBuild` (~455 строк), `cmdWatch` +
  `collectSourceFiles` + `watchRefresh/Rebuild/Relaunch`, `--cc/--cxx`
  (mix через `zffi_mix*` + `static mix::MixContext* g_mix`),
  `zffi_optimize(..., buildMode)`, `printVersion`, `printUsage`, `main`.
- **Паритет байт-в-байт** (stdout/stderr/rc, для сборок и бинарник) по:
  no-args/`--help`/`--version`/badcmd/missing-file, `-o`, `--obj`, `--iso`,
  `--bugfind`, `--no-opt`, `-2r`, `-g`, `new` (все варианты + ошибки),
  `build` (все пути workspace.zen), `build --lib`, `--cc`/`--cxx` смесь,
  `--watch` (все пути ошибок + happy path на проекте из `zenith new`).
- **Единственное отличие** — строка `--ir` в usage (намеренно:
  `zenith-z --ir` → `Error: --ir is not available here: the IR pipeline
  is being rewritten`, rc=1).
- `make -f Makefile.linux test` зелёный (bugfind 35, irbugfind 33,
  JS LINUX HOST ALL OK, test-front 15/15).

---

## Сделано 04.10 (вторая половина) — шаг 3: выражения + проверка паритета

**Ядро `codegen.z` (на тот момент единый файл, ~6191 строк; сейчас разбито
на модули — см. следующий раздел). Портировано в этот заход** (порядок
`codegen.cpp`, номера строк — там же):

- `emitUnaryExpr` (414), `emitFloatMathCall` (786), `emitStructAddrR10` (1245),
  `emitStructRegs` (1291), `emitAddrOfExpr` (1406), `emitFloatExpr` (1912),
  `exprContainsCall`/`exprHasArrayAccess`/`cgMemberPath`,
  `emitExprKeepAlive*` (2110/2129/2145, `int& keepReg` → глобальный
  `cgKeepReg: int`);
- **`emitBinaryExpr` целиком** (2155–2759) — разбит на
  `cgEmitBinaryInt` / `cgEmitBinaryFloat` + диспетчер `cgEmitBinaryExpr`
  (float-сравнения, `%of`, `&&`, `||` — в диспетчере);
- `emitFtoiExpr` (2759), **`emitExpr` (2777) со всеми ветками**, включая
  `emitArrayAcc` (2890) и N_STRING-пул с `cgStrFix*`/`cgKoStrFix*`;
- **`emitStmt` (6233) — только `N_RETURN`** (новое: `cgCurFuncRetType`,
  `cgFuncEndLabel`);
- `cgEmitCallExpr` — **заглушка**: работает `ftoi`, весь остальной вызов
  (инлайн-билтины `arena/pool/slot/peek/poke/http/net…` → `tryKOCall`/
  `tryLinuxCall`/… (codegen.cpp:5506–5614) → generic ABI-путь) даёт
  `cgErrSet`. **Это следующий большой кусок.**

**Проверка — дифференциальный тест против C++ (вместо Python-модели):**
`tools/cgemit_check.py` генерит `src/_cgemit.z`, парсит программу тем же
selfhost-парсером, проигрывает ветку `N_RETURN` через `cgEmitStmt`, рядом
собирает ту же программу `zenith --obj --no-opt` и ищет байты `.z` как
**подстроку** в функции из `objdump .o`.

- Программы: `tools/cgemit/expr{1,2,3}.z` — **43/43 функции байт-в-байт**.
- Запуск: `make -f Makefile.linux test-cgemit` (добавлен в `test`); полный
  `make -f Makefile.linux test` зелёный (bugfind 35, irbugfind 33, JS, 15/15,
  cgemit 43/43).
- Старые FNV-хеши `src/_cgtest.z` не изменились:
  `5349884057702756315` / `4141289819001028584`.

**Грабли этого этапа:**
- **`--no-opt` обязателен**: оптимизатор правит AST (`x * 2` → сдвиг,
  свёртка констант) — без него байты легитимно разъезжаются.
- `app console` пишет `pbInit/pbFlush` в **stderr**; харнесс читается оттуда.
- `pbNum` печатает `0` для отрицательных → FNV-хеш иногда как `0`; сверяем
  только hex-байты.
- `ptr<ptr<T>>` не парсится ни C++, ни selfhost — вложенный указатель
  оборачивать в структуру.
- Правоскрестный `a + (b + (...))` выдерживает максимум 4 уровня; на 5-м
  `allocReg` кончается — **обе стороны дают одну и ту же ошибку**,
  `register allocation failed: expression too deep (all 6 GP registers in
  use)`. `.z` при этом продолжает эмитить мусор до конца цикла (ветка
  `N_IDENT` не проверяет `allocReg() < 0`) — сообщение и rc совпадают.
- `%of`: C++ — свой `fprintf("Error: percent base must be an integer
  expression")` + `exit(1)`; в `.z` сделан `cgErrSetPlain`/`cgErrIsPlain`,
  **вывод драйвером (main.z) ещё не подключён**.
- Отладочная ветка `ZT_CALLDEBUG` в `isFloatExpr` не переносилась.

---

## Сделано 04.10 (третья часть) — ядро разбито на модули + сужение объёма

**Два решения пользователя (через question()), оба записаны в `PLAN.md`:**

1. **«Ядро сейчас + бэкенды отдельно».** Уже портированный кусок
   `codegen.cpp` разбить на логические модули **сейчас**, а каждый файл
   бэкенда класть **своим модулем** по мере порта — не дописывать в ядро.
2. **«Сначала только Linux/x86 путь»** — `codegen.cpp` + `codegen_elf.cpp` +
   `codegen_ko.cpp` + хвост `try*Call` для `app linux`; остальные бэкенды
   (PE/arm64/stm32/wasm/dx11/…) — **следующим слоем**.
   *Причина изменения записи «в .z должно быть всё»:* инвентаризация даёт
   43 145 строк `codegen*.cpp`, тащить их все в один шаг нелогично, пока
   `zenith-z` ещё не собирает проекты. Конечная цель не отменяется —
   меняется порядок; внутри слоя 1 полнота сохраняется.

**Разбивка.** Единый `src/codegen.z` разрезан на линейную цепочку
(всего 6269 строк):

| файл | строк | что |
|---|---:|---|
| `src/cg_zast.z` | 342 | раскладка ZAST, `cgBind`, чтение узлов/строк, сравнение строк, слот ошибок, `cgWordSize` |
| `src/cg_emit.z` | 2355 | байтовый эмиттер: буфер, регистры, x86/SSE, метки/фикстуры, `cgSpillBase`, адресные примитивы, таблицы фикстур |
| `src/cg_type.z` | 976 | типы, раскладки структур, таблица переменных, кадр, `cgExprType`/`cgIsFloatExpr`/`structValueQwords` |
| `src/cg_expr.z` | 2572 | ход по AST: эмиттеры выражений, `cgEmitExpr`, `cgEmitStmt`, пул строк |
| `src/codegen.z` | 24 | фасад: `use cg_expr` — **`use codegen` в драйверах не меняется** |

```
codegen → cg_expr → cg_type → cg_emit → cg_zast
```

**Причина строго линейной цепочки:** `parseRun` не дедуплицирует
подключённые модули, diamond-`use` даёт `Duplicate function '<name>'`
**при rc=0** (проверено отдельным экспериментом). Поэтому каждый модуль
`use`-ится ровно один раз во всём дереве. Рёбра настоящие:
`expr→type` (запросы типов), `type→emit` (`cgSpillBase` пишет
`cgSetupFunc`), `emit→zast` (`cgStrPtr`/`cgErrSet`/`H_*`).

**Перемещения, без которых цепочка не складывается:** `cgStrIs` и
`cgStrIdsEq` → в `cg_zast` (их вызывает сам ридер `cgStrEqId`);
`cgWordSize` → в `cg_zast` (его пишет `cgBind`, иначе цикл);
`cgBind` остался в `cg_zast`.

**Записать надолго:** перекрёстные присваивания между модулями в `.z`
работают (`var` из нижнего модуля можно писать из верхнего) — проверено;
а вот **константа, используемая только в мёртвых функциях, не даёт
ошибки** «undefined variable»: первый вариант разбивки потерял строки
22–91 (`H_*`/`N_*`) и это прошло молча. Состав модулей проверять
**покрытием строк**, а не только зелёными тестами.

**Проверка после разбивки:** `make -f Makefile.linux test` зелёный
(bugfind 35, irbugfind 33, JS, front 15/15, **cgemit 43/43**), FNV-хеши
`src/_cgtest.z` не изменились, `src/_cgdrv.z` (сплайс вместе с
`selfhost/ast.z`, дубликаты `H_*`/`N_*`) отрабатывает.

---


## Ранее 04.10 — шаг 3 начат: `src/codegen.z` (первая половина)

**Создан `src/codegen.z` (на тот момент ~2255 строк, модуль — без `app`/`main`,
подключается драйвером через `use codegen`). В нём:**

1. **ZAST-ридер** — `cgBind/cgH/cgNodeAddr/cgTag/cgLine/cgF/cgSetF`,
   `cgStrPtr/cgStrLen/cgSide/cgListLen/cgListAt/cgStrEqId`,
   константы `H_*`/`N_*`/`CG_NODE_BYTES=72`. Смещения: заголовок 256 байт,
   узлы `nodeCount*72`, strtab, side (`H_SIDEWORDS*4`), sigs — как в
   `selfhost/ast.z azBuild`.
2. **Буфер кода** — `cgEnsure` (рост x2, `alloc`+`cgCopyBytes`+`free`),
   `emit8/16/32/64`, `cgReset/cgCodePtr`.
3. **Регистры** — `allocReg/freeReg/findFreeRegOtherThan/allocXmmReg/freeXmmReg`,
   пул `{0,1,2,3,6,7}` закодирован как `i<4 ? i : i+2`.
4. **x86/x86-64 примитивы** — `emitMovReg`, `emitMovRegImm`, BP load/store
   (6 вариантов), `emitAdd/Sub/Imul` (спец-кейсы перенесены **дословно** —
   они дают другие байты, чем общая формула!), `emitAnd/Or/Xor`, `newLabel`.
5. **Ошибки** — вместо C++ `throw`: `cgErrSet/cgHasErr/cgErrText/cgErrClear`
   (main.z будет печатать `Codegen error: <msg>`).
6. **SSE float** — `emitMovssXmm(+Imm)`, `sseRR`, add/sub/mul/div/ucomiss/cvt*/
   sqrt/andps/minss/maxss/xorps/roundss; `emitMovssXmmImmFloat` разложен на
   `emitMovssXmmImmInt(bits)` (в `.z` нет битового приведения float→int).
7. **Метки/фикстуры** — `emitJcc` по strId, `emitJccLit` по литералу,
   `cgApplyFixups`, `spillRegs`/`reloadRegs`, disp8-помощники.
8. **Типы и раскладки** — `TK_*` (TypeKind), тип = 6 слов
   `[kind, structName, isPtr, addrSpace, arraySize, fnSigId]` и передаётся
   указателем (`cgFAddr`); `cgStrIdsEq` (по содержимому, `azStr` не
   дедуплицирует); `cgComputeStructLayouts` (8 проходов, = codegen.cpp:7538),
   `cgStructTypeSize` (=1179), `cgArrayElemStride` (=1376);
   таблица переменных `cgVarClear/cgVarFind/cgVarPut`;
   `cgAllocStmts` (= `allocateBlockVars` 7589) и `cgSetupFunc`
   (верх `emitFunction`: параметры/`locals`/`spillBase`/`frameSize`).

9. **Типы выражений** — `cgStrIs`/`cgStrEqZ` (без NUL!), scratch-кольцо
   `cgTyMake`/`cgTyCopy` (C++ возвращает `Type` по значению), `cgIsFuncPtr`,
   `cgSigRet`, `cgFuncRetType`, `cgExprType` (=1306), `cgCallCalleeKind`
   (=1497), `cgIsFloatExpr` (=1080), `cgStructValueQwords` (=1199).

10. **Адресные примитивы и фикстуры** — `emitLeaRegFromBP` (=1536),
    `emitLoadFromAddr` (=1553), `emitLoadFromAddrR10` (=1651),
    `emitGlobalLeaReg` (=1742, пишет в `cgGlobalFixups` + `cgGlobalsRVA`);
    таблицы фикстур `cgFuncRefFixups`/`cgGlobalFixups`/`cgCallFixups`
    (заполняются здесь, патчит контейнер), `cgFuncOffsetPut/Find`
    (= `funcOffsets`), `cgIsUserFunc` (=1415, `f11` = isExtern).

**Проверка: `src/_cgdrv.z`** (`use ../selfhost/parser` + `use codegen`) —
парсит строку-источник через `parseRun`, `cgBind(parseOutPtr(), parseOutLen())`
и печатает раскладки. Сверено с расчётом по C++: `Point`=16, `Rect`=48,
поле `v`(vec3) @36; для `func f(a: int, b: float, c: Point)` →
`paramBytes=32`, `a=-32 b=-24 c=-16`, `locals=180`, `spillBase=140`,
`frame=200`, `x=-40 y=-44 r=-92 i=-100 z=-108 w=-116 t=-124 u=-132`.

Типы выражений (на `func g(q: float)`, `p: Point`, `r: Rect`): `p.x > 0` →
Bool, `p2: Point = p` → Struct + `qwords=2`, `r.v` → Vec3 + `qwords=2`,
`r.w` → Float + `isF=1`, `q + 1.5` → Float; `locals=172 spillBase=132
frame=184`.

**Проверка: `src/_cgtest.z`** (`app linux` + `use codegen`) печатает две
FNV-1a хеш-суммы эмиченных байтов:

- 64-битный прогон: `5349884057702756315`, 68 байт
- 32-битный прогон: `4141289819001028584`, 62 байта

Обе суммы совпали с **независимой** Python-моделью формул из `codegen.cpp`
(см. геш-скрипт в сессии) — то есть эмит байт-в-байт верен и в 64-, и в
32-битной ветке.

**Грабли этого дня (порта codegen.z):**
- Лексер не принимает беззнаковый литерал `0xCBF29CE484222325` (> int64 max)
  → «Unexpected token 'end' at top level», которое выглядит как сломанный
  баланс `end`. Писать значение, влезающее в int64.
- `mem_copy` есть не у всех бэкендов (Linux его не эмитит) → своя
  `cgCopyBytes(dst, src, n)` циклом.
- `-o /tmp/x` для `app linux` даёт файл `/tmp/x.elf` (бэкенд добавляет `.elf`).
- **ZAST-строки НЕ NUL-терминированы** (`[u32 len][bytes]`, вплотную к
  следующей — `ast.z azStr`). «Дочитать до 0» нельзя: сравнения только через
  `cgStrLen`. Симптом: `exprType` для `p2: Point = p` даёт Void, `p.x > 0`
  даёт Int вместо Bool.
- `selfhost/lexer.z lxBAppendNum` печатает `'0'` для **любого** `v <= 0` —
  `pbNum` не умеет отрицательных (в харнессе печатаем `-pbNum(абс)`).
- `use`-резолвер ищет модуль в `baseDir`, `baseDir/include`, `include`,
  `cwd`, `cwd/include` и рядом с бинарём (до 3 уровней вверх); отсюда
  `use ../selfhost/parser` в `src/_cgdrv.z`. `use`-дубликаты `H_*`/`N_*`
  между двумя модулями при сплайсе не ошибка, но значения обязаны совпадать.
- `vec2`/`vec3`/`color` парсер принимает только при `gAppType==1`, то есть
  источник обязан начинаться с `app gui dx tool` (без `dx`/`sr`/`vulkan`
  остаётся `gRenderType=0` → `gAppType=8` и «type is only available in GUI»).
- `codegen.cpp` не давать «упрощать»: спец-кейсы `emitAdd/Sub/Imul` дают
  другие байты, чем общая формула (оба варианта корректны, но байты разные).

## Сделано 05.10 — `cgEmitCallExpr` (generic ABI-путь) + mask-паритет

**Портировано** (`src/cg_expr.z`, всё по `codegen.cpp:5616..6201`):
- `cgStructArgInfo` (5622) → модульные выходы `cgSaIs/cgSaGlobal/cgSaOff/cgSaSlots`;
- `cgSpillPlacedArgs` (5687) / `cgRestorePlacedArgs` (5721) / `cgPlaceQword`
  (5775) → модульные `cgSpillBytes/cgPlacedGP/cgPlacedXmm`;
- расчёт `totalSlots`/`stackAlloc` (5645..5671), выставление аргументов
  (6005..6089), косвенный вызов по указателю на функцию (6091..6118),
  extern-вызов и прямой `E8` (6141..6191), teardown и `cvttss2si` для
  float-возврата (6187..6201);
- `cgEmitIdentName` — N_IDENT вынесен по имени (C++ строит временный
  `IdentExpr` для func-ptr калли, в `.z` нет аллокатора AST);
- `cgKoDriverFlag` — драйверский флаг: под `--obj` C++ принудительно ставит
  `koDriver=true` (main.cpp:1407), в ZAST остаётся только бит `app … driver`;
- `cgPushElfImport` (`src/cg_emit.z`) — таблица `ElfImportFixup`.

**Найдено и починено (причина — важно):** `cgPlacedGP/cgPlacedXmm/cgSpillBytes`
в C++ — *локальные* переменные каждой инвокации ветки CallExpr. В `.z` они
модульные (иначе `cgPlaceQword` и спилл-хелперы их не видят), и вложенный
вызов в аргументе (`f(a, g(x))`) затирал внешний: ломались и push/pop, и
`stackOff` для стековых аргументов. Решение — обёртка
`cgEmitCallExpr → cgEmitCallBody` с save/restore этих трёх значений
(даёт ровно семантику C++-локалей). Проверено: до починки `t03/t06/t11`
были MISMATCH, после — 20/20.

**Ограничение проверки (причина, а не лень):** rel32 вызова считается от
абсолютных смещений всего буфера, а харнесс эмитит по одной функции в свежий
буфер (проолога нет — `emitFunction` ещё не портирован), поэтому совпасть он
не может. Харнесс печатает `mask=<позиции 4-байтовых релок>`, Python
сравнивает **все остальные байты точно** (`find_masked` в
`tools/cgemit_check.py`). Точный rel32 проверим после `emitFunction`, когда
весь TU ляжет в один буфер. Список масок: `cgCallFix*`, `cgFuncRef*`,
`cgGlobalFix*`, `cgStrFix*`, `cgKoStrFix*`, `cgElfImp*`, `cgImpCall*`,
`cgHeapFix*`, `cgNetFix*`.

**Диспетчер `try*Call` (5506..5614) НЕ портирован.** Вместо него — страж:
если калли не `extern func` и не нет-extern Zenith-функция и не косвенный
callee → `cgErrSet` (громко, без молчаливо неверного `E8` к несуществующему
символу). *Причина отложенного порта:* `try*` зовут `emitExpr`, а `emitExpr`
зовёт диспетчер — цикл, а `use`-цикл в `.z` запрещён («include cycle»);
варианты — держать в `cg_expr.z` либо инвертировать ребро через
`ptr<func(…)>`-hook (синтаксис работает, проверено). Решение — при первом
портированном `try*`.

**Ещё две дыры в ZAST/`.z` (зафиксированы, не молчаливые):**
- виртуальный диспетч (`codegen.cpp:5890..6003`) невозможен — `selfhost/ast.z
  azBuild` не кладёт в ZAST `isVirtual`/`vtable`;
- C/C++ mixing (`mixCtx`, 6127) — construct драйвера `--cxx`, в selfhost нет;
- `linuxSonameFor` (syslibs.cpp) — хост-проба через `.dynsym`/`dlsym`, нужна
  только вне `--obj`; пока soname = `f12` (`from "…"`), таблица
  `cgElfImpSoname` ждёт link-слой.

**Тест:** `tools/cgemit/call1.z` — 20 функций (0..8 арг, вложенные вызовы →
спилл/восстановление, float-возврат, struct-by-value 2 и 6 слотов,
косвенный вызов). Итог: **63/63** функции байт-в-байт во всех четырёх
программах; `make -f Makefile.linux test` — зелёный; `_cgtest.z` — эталонные
хеши `5349884057702756315` / `4141289819001028584` не изменились.

**Грабль:** поле структуры требует `var x: int` (без `var` парсер падает
с «Expected 'end' after struct»).

---

## Сделано 05.10 (вторая половина) — инлайн-билтины 3016..5505 почти закрыты

**Портировано в `src/cg_expr.z` (порядок `codegen.cpp`):**
`ftoi` (3017), `alloc`/`free` (3022/3076, гейт `cgKoDriver()==0` + хелпер
`cgEmitHeapBump` — хвост lambda 3093..3120, отдельной функцией, т.к. не
трогает `regsUsed`), `arenaCreate/Alloc/Reset/Destroy` (3121..3248),
`poolCreate/Alloc/Free/Reset/Destroy` (3249..3377),
`slotCreate/Spawn/Kill/GetI64/SetI64/GetF32/SetF32/Count/Reset/Destroy`
(3378..3739), `sleep` (3740), `pause` (3786),
**`print` (3856..4414, `&& !isLinux`)**, `Create:File` (4415..4505),
`peek`/`poke` + 8/16/32-битные (4506..4648),
**`http_download`/`_ask`/`_speed` (4650..5029)**, `http_get` (5030),
`http_last_error` (5236).

**`http_json` (5260..5505) — ГОТОВ 05.10 (следующий раздел).** Инлайн-билтины
3016..5505 закрыты целиком. Остался диспетчер `try*Call`.

**Таблицы в `src/cg_emit.z`:** `cgHeapFix*` (сброс + mask-цикл в `pbMask`),
`cgNetFix*` (`CG_NET_*` константы), `cgImpCall*` (список таблиц в PLAN.md
п.16), `cgStrPoolRaw[256]` + `cgStringPoolRawIdx(lit)` (пул сырых строк
для `"\r\n"`, `"{"`, `"  "` и т.п. — в ZAST они не лежат),
`var cgHttpGetUsed`.

**Mode B в `tools/cgemit_check.py`:** `-b` → `MODE_B_FLAGS`
(`cgObjOutput=0`, `cgKoDriverFlag=0`), эталон — обычный ELF exe
(`buildKO` отклоняет heap/net-fixups, поэтому `--obj` тут невозможен).
Эталон теперь умеет и не-ELF: `pe_text_bytes()` + `ref_image()` пробуют
`stem+'.elf'/'.efi'/'.bin'/stem` (PE читается как секция `.text`, flat
`app bare`/`app bios` — как есть). В `Makefile.linux` второй цикл по
`tools/cgemit/*_b.z`.

**Грабль — `app console` ≠ AppType::Console:** `parseAppType()`
(`selfhost/parser.z:2587`) ставит `gAppType = 8` и для `console`, и для
`linux`, и для `gui tool`; `AppType::Console (=0)` не выставляет никто.
А `isLinux` выставляется ровно по `appType == Linux` (`codegen.cpp:8575`),
поэтому **`print` (и `http_download*`) в `app console` не достижимы, и в
`--obj` — тем более** (`main.cpp:1407` требует `appType == Linux`).
Харнесс `cgIsLinux`/`cgSysvAbi` выводит из `cgH(H_APPTYPE) == 8`; чтобы
открыть `!isLinux`-ветку, в исходнике нужен appType ≠ 8 —
`app gui dx11 tool` (→ PE, проверено).

**Грабль — ручной rel8 в `print`:** C++ пишет
`int jnePos2 = code.size(); emit8(0); …; code[jnePos2] = size - jnePos2 - 1`.
В `.z` — `var jnePos2 = cgCodeLen; emit8(0); …;
poke8(cgCode + jnePos2, cgCodeLen - jnePos2 - 1)`; адрес берётся **на момент
патча**, потому что `cgEnsure` может переложить буфер.

**`http_download*` — гамма CloseHandle разная (не копировать вслепую):**
`statusFailed`/`createFailed` закрывают только hUrl+hInternet (rbx — это ещё
путь, а не хэндл), `urlFailed` — только hInternet, `readFailed`/`writeFailed`
— hUrl+hInternet+hFile. Промпт — модульная `cgDlAsk(textIdx, textLen,
yesLabel, noLabel, declined)` (лямбда `emitAsk` codegen.cpp:4687; `noLabel < 0`
→ `mov eax,1; jmp declined`), длины строк даны байтами: 31 и 51.

**Грабль — `;` не является разделителем операторов в `.z`, и `zenith`
возвращает rc=0 при лексической ошибке.** Симптом: 177 строк
`emit8(0x48); emit8(0x83); …` «скомпилировались», `build()` в
`cgemit_check.py` не падал (returncode 0), и паритет смотрелся на
полупарсенной программе. Лечится двумя вещами: (а) в `.z` — одна операция
на строку (`;` допустим только внутри строкового литерала); (б)
`cgemit_check.py build()` теперь считает любую диагностическую строку
(`Lexer error`, `Parser error`, `Unexpected token`, `Error…`) фатальной,
как для нашей сборки, так и для эталонной. Тот же грабль для `//` — в `.z`
комментарий только `#`.

**Тест:** `tools/cgemit/print1_b.z` (5 функций) и
`tools/cgemit/httddl1_b.z` (`app gui dx11 tool`, 4 функции: `http_download`,
`_ask`, `_speed`, `… + 1`) — 9/9 байт-в-байт; итог сьюта **132/132**
(110 mode A + 22 mode B: `heap1_b` 9, `net1_b` 4, `httddl1_b` 4,
`print1_b` 5); `make -f Makefile.linux test` — зелёный.

---

## Сделано 05.10 (третья часть) — `http_json` + `buildHttpJsonHelper`

Последний блокирующий кусок из раздела выше закрыт. Подробности —
`PLAN.md` п.17; здесь только передатка.

- **Новый модуль `src/cg_httpjson.z` (1053 строки)** — полный порт
  `src/httpjson_rt.cpp` (энкодеры `HJ`, `hjPutStr`, `hjEmitBoundaryChecks`,
  `hjEmitFindTag`, `cgBuildHttpJsonHelper`, `cgEmitHttpJsonHelperCall`).
  Мёртвый `emitCopyFromBodyEsc` (0 вызовов в C++) не портирован.
- Ветка `http_json` (5260..5505) — в `src/cg_expr.z`, вызов
  `cgEmitHttpJsonHelperCall()` на строке 6006.
- **`use`-цепочка стала:** `codegen → cg_expr → cg_type → cg_httpjson →
  cg_emit → cg_zast` (в `cg_type.z` добавлен `use cg_httpjson`). Всё ещё
  линейная цепочка, каждый модуль ровно один раз.
- **Баг в порте (починен):** `hjPutStr`, 2-байтовый кусок — `B8 <2 байта>`
  вместо `mov eax, imm32` (4 байта). Добавлены два `emit8(0)`.
- **Баг в C++-эталоне (починен):** `src/httpjson_rt.cpp:269` — комментарий
  `// \\` заканчивался `\`, line splicing съедал строку 270
  (`alu_imm_reg(0, R_RBP, 2)`), и эталон не сдвигал курсор после `\\`.
  Правка `// \\ backslash`. **Правило: в C++ `//`-комментариях не оставлять
  `\` последним символом строки.** Проверка:
  `g++ -std=c++17 -E src/httpjson_rt.cpp | grep -A1 5C5C`.
- **Грабль:** `make golden` обязателен после любой правки `selfhost/*.z` —
  `test-front` сравнивает `@NNNN` (номера строк) и падает молча на устаревшем
  золоте даже при неизменном содержимом дампа.
- **Тест:** `tools/cgemit/httjson_b.z` (1 функция) → 1/1 байт-в-байт;
  итог сьюта **133/133** (110 mode A + 23 mode B), `make -f Makefile.linux
  test` зелёный (rc=0). Инлайн-билтины 3016–5505 — **ГОТОВЫ**.

## Сделано 05.10 (четвёртая часть) — слой 1 Linux: состояние + `buildLinuxImportData`

Начат перенос `src/codegen_elf.cpp` (1345 строк). Подробности — `PLAN.md`
п.18; здесь только передатка.

- **Новый модуль `src/cg_elf.z`** (сначала назывался `codegen_elf.z` —
  переименован под конвенцию `cg_*`): константы ELF64, образ файла
  (`cgImg*`/`cgImgPut8..64`), `cgAlignUp`, пустой `cgDetectLinuxNeed`,
  `cgComputeSectionRVAs`, `cgPoolPtr`/`cgPoolLen`, `cgAddRdataStr`,
  `cgPutAbsPtr` и **`cgBuildLinuxImportData`** (codegen_elf.cpp:120..509,
  весь: пул строк, GUI class name, re-space `.data`, heap/net/sound/tls/js
  слоты, vk/wl/vkSurface, глобалы, heap-fixup'и).
- **Состояние в `src/cg_emit.z`** (рядом с `cgCode`): 97 слотов `*RVA` из
  `codegen.h` (имена с префиксом `cg`), `cgVkSurfaceProcsStrRVA[40]`,
  буферы `.rdata`/`.data` (`cgRData`/`cgData` + `Ensure/Push/Fill`),
  `cgStringOffsets[4096]`, `cgEntryPointCodeOffset`, `cgGlobalsSize`,
  таблица `cgGo*` (аналог `globalOffsets`, ключ — ZAST strId), 9 флагов
  `*Used`.
- **`use`-цепочка получила верхний слой:**
  `codegen → cg_elf → cg_expr → cg_type → cg_httpjson → cg_emit → cg_zast`.
  Ребро `cg_elf → cg_expr` **настоящее** (пул строк и фикстуры — в
  `cg_expr.z`). Ранее рассмотренный вариант «elf между httpjson и emit»
  отвергнут: там ребро `httpjson → elf` было бы структурным, а линейная
  цепочка не даёт подключить соседа вторым `use` (parseRun не дедуплицирует
  и печатает «Duplicate function»).
- **`src/_cgtest.z`: смоук ELF-слоя с ассертами.** Привязывает минимальный
  ZAST (`parseRun` + `cgBind`), потому что `buildLinuxImportData` читает
  `H_APPTYPE`/`H_GLOBALS` (без привязки — segfault на `peek32(0)`).
  Проверяемая раскладка: `.text @0x1000`, `.rdata @0x2000`, `.data @0x3000`;
  `"hello\0"` → `cgRDataLen=16`, `.data=24`, `cgStringRVA=0x2000`,
  `heapOffset=0x3000`, `heapFreeHead=0x3008`, `randSeed=0x3010`,
  `heapArea=0x3018`. Ассерты проверены негативным прогоном (16→17 печатает
  FAIL) — не разворачиваются оптимизатором в константу.
- **Грабли:** рост буфера из `cap=0` через `cap *= 2` — вечный цикл (нужен
  стартовый 65536, как в `cgEnsure`); строки в пуле двух родов (ZAST strId
  vs сырой `.z`-литерал — разрешаются `cgPoolPtr/cgPoolLen`); `floor`/`sin`
  в `.z` работают только в float-позиции, `int(x)`-каста нет — неявное
  присваивание `var a: int = <float>` есть; `writeDQ`/`hasNl` в C++ мёртвые
  и не перенесены; `emitShaderModules` — заглушка.
- **Тест:** `make -f Makefile.linux test` зелёный (rc=0), **133/133 байт-в-байт**;
  `src/_cgtest.z` выходит с 0.

---

### 05.10 — `fixupSectionRVAs` и весь `cgEmitStmt` (кроме `N_ASM`)

**`fixupSectionRVAs` (codegen_elf.cpp:583) → `cgFixupSectionRVAs()` в
`src/cg_elf.z:226.** Рядом хелперы `cgRdDW:206` / `cgWrDW` / `cgRdDQ` /
`cgWrDQ:221` (поставлены сразу после `cgComputeSectionRVAs`).
- Ранний выход при `dRdata==0 && dData==0`.
- **Порядок веток heapFixups: старое окно `.data` проверяется ПЕРВЫМ** —
  окна старого и нового layout перекрываются, порядок влияет на результат.
- Скалярные сдвиги: `stringRVA += dRdata`; `classNameRVA`/`fontRVA` при
  `appType==1`; `fontCyrRVA` при `==2`; все `*RVA += dData`;
  `win32GlobalsRVA` при `appType==1||2`.
- **Не перенесено (на Linux всегда пусто, оставлен комментарий):**
  дескрипторы импорта `importDescCount`/`importDataSize`/`externFuncMap` и
  `embeddedDLLs`/`embeddedLEAFixups` — это PE-ветки, в образе их нет.
- **14 новых скалярных RVA-полей** добавлено в `src/cg_emit.z` после
  `var cgHttpDlUsed` (теперь `grep -c "var cg"` = 178): `win32GlobalsRVA`,
  `netStatusRVA/netStatusLenRVA/netBytesReadRVA/netLenRVA/netErrRVA/
  netHdrLenRVA`, `fontRVA/fontCyrRVA`, `embeddedFullPathRVA/embeddedHFileRVA/
  embeddedHModuleRVA/embeddedWrittenRVA` — все дефолт 0 (сверено с
  `codegen.h:485,523..529,835..836,878..881`).

**`emitStmt` (codegen.cpp:6233..~6700) → `cgEmitStmt` в `src/cg_expr.z`.**
Покрыто 11 из 12 веток: `N_RETURN` (осталась без изменений), `N_EXPRSTMT`,
`N_VARDECL`, `N_ASSIGN` (индекс / путь полей / плоское), `N_PTRASSIGN`,
`N_IF`, `N_WHILE`, `N_LOOP`, `N_SWITCH`, `N_BREAK`, `N_CONTINUE`, `N_FOR`.
**Не портирован только `N_ASM`** (`emitAsmInstr`, :6753) — осталось
`cgErrSet("emitStmt: statement kind is not ported to codegen.z yet")`.

Разметка ZAST-узлов **сверена по `selfhost/parser.z`** (источник истины,
а не догадка):
- `N_EXPRSTMT` f0=expr; `N_BREAK`/`N_CONTINUE` — полей нет.
- `N_IF` f0=cond, f1/f2=then(start,len), f3/f4=else(start,len);
  **`else if` хранится как список с одним дочерним `N_IF` в f3/f4**
  (parser.z:1544).
- `N_WHILE` f0=cond, f1/f2=body; `N_LOOP` f0/f1=body (:1596/:1626).
- `N_FOR` f0=name, f1=start, f2=end, f3=step (**0 ⇒ step=1**), f4/f5=body
  (:1714).
- `N_SWITCH` f0=cond, f1=caseListStart, f2=caseListLen, **stride 3**:
  `[cond(0=default), bodyStart, bodyLen]` (:1670).
- `N_ASSIGN` f0=name, f1/f2=memberPath(start,len), f3=indexExpr (**0=нет**),
  f4=value (`buildAssign` :1418).
- `N_PTRASSIGN` f0=ptr, f1=value — создаётся и для `*p = v`, и для `&x = v`
  (:1421/:1476/:1948).
- `N_VARDECL` f0=name, f1..f6=Type, f7=init, f8=arraySize, f9=isConst (:1345).
- `N_ASM` f0=wordSize + список инструкций (:1782).

**Новое в модулях** (инвентарь найден/добавлен):
- `src/cg_expr.z`: `cgEmitBlock(start,len)`, `cgSwitchLabels[4096]`,
  `cgAddrToR10(chain)` (≡ лямбда из C++: `4C 8B C0|(2<<3)|(a&7)` =
  `mov r10,a`, пропуск при `a==10`).
- `src/cg_emit.z`: `CG_BRK_MAX=128`, `cgBreakStack`/`cgContStack` + push/pop
  + `cgLabelStacksReset()` (второй вызов — в начале `cgSetupFunc`).
- `src/cg_type.z`: `cgClassIdFind(name)` (пары в `H_CLASSIDS`, -1 если нет);
  `cgAllocStmts` (= `allocateBlockVars`, :385) и `cgSetupFunc` (:474) уже
  были — это верх `emitFunction`.
- `src/cg_zast.z`: **арена синтетических узлов** `cgSynthInit` /
  `cgSynthReset` / `cgSynthNew` (вызывается последней строкой `cgBind`).
- Уже существовали и понадобились: `emit8/emit32/emitJmp/emitJcc/emitJccRaw/
  newLabel/allocReg/freeReg/freeXmmReg/spillRegs/emitStoreToBP[64]/
  emitFloatStoreToBP/emitMovRegImm/emitAdd/emitMovReg/emitMovssXmm/emitLeaR10FromBP/
  emitLoadR10FromBP64/emitStoreToAddrR10/emitStore32ToAddrR10/
  emitFloatStoreToR10` (`cg_emit.z`), `cgEmitExpr/cgEmitBinaryExpr/
  cgIsFloatExpr/cgEmitFloatExpr/cgEmitStructRegs/cgStructValueQwords/
  cgStructTypeSize/cgExprHasArrayAccess/cgExprContainsCall/
  cgEmitExprKeepAlive[R10]/cgEmitFloatExprKeepAliveR10/cgEmitAddrOfExpr/
  cgMemberPath` (`cg_expr.z`), `cgSetF/cgTag/cgF` (`cg_zast.z:191`).

**Грабли, на которые наступили:**
- **Отрицательный node id ломает `cgF()`/`cgSetF()`.** Синтетические узлы
  висят на адресе `cgNodeBase + k*72`; если `k < 0`, то запись
  `cgSetF(member, 0, chain)` кладёт в поле узла отрицательное число через
  `poke32` (u32), а `peek32` читает его уже без знака → следующий
  `cgTag()` уезжает на `peek32(nodeBase + 4.29e9*72)` → **SIGSEGV**.
  Ловится не сразу: падение выглядит как сбой внутри `exprType()` первого
  посещения member-assign. Фикс: арену аллоцировать через `alloc()` **на
  каждой привязке и ПОСЛЕ блоба** (аллокатор монотонный ⇒ `arena >=
  nodeBase` ⇒ `k = ceil((arena - nodeBase)/72) >= 0`) и держать
  `+1` узла в размере арены под выравнивание вверх (смещение ≤71).
- `emitJcc` в `.z` принимает **ZAST strId**, литерала `"=="` для него нет →
  в switch использован `emitJccRaw(0x84, label)` (эквивалент C++
  `emitJcc("==")` = `0F 84` + jmpFixup + rel32 0).
- **Закон лояльности соблюдён:** воспроизведены даже подозрительные
  байты C++ — двойной restore `guardR10` в member-assign и `F3 0F 11/10
  <(x&7)<<3> 0x24` в store/load float `*p =`.
- **`cgFixReset()` НЕ обнуляет `cgFixN`** (таблица jmp-фикстур) — в
  смоуке надо `cgFixN = 0` руками, как делает `cgPerFuncReset` в
  `_cgemit.z:66`. Сам по себе цикл защищён (`cgFixPush` на 0..8192
  ставит `cgErrSet`), поэтому это не было причиной падения — но обязательно
  для честности прогона.
- Локализация segfault через временные `println`-маркеры в `cgEmitStmt`
  → `cgEmitBlock` → `exprType`: 901..953 (цикл по statement'ам),
  960..964 (цикл по пути полей). Маркеры удалены, правок в их виде не осталось.

### 05.10 (часть 2) — `populateGlobalVarInfos` и весь `emitFunction`

**`populateGlobalVarInfos` (codegen.cpp:1788) → `cgPopulateGlobalVarInfos()`
в `src/cg_type.z`** (рядом с таблицей `cgVar*`), плюс `cgGoFind(name)` в
`src/cg_emit.z` — аналог `globalOffsets.find` для пары
`cgGoName/cgGoOff/cgGoN`, которую уже заполняет `cgBuildLinuxImportData`.
Вызывается из `cgSetupFunc()` **сразу после `cgVarClear()` и до разкладки
параметров** — ровно та позиция, где `emitFunction` (7657) делает это в C++
(`varInfos.clear()` → globals → params → `allocateBlockVars`). Отсюда
**глобалы регистрируются**: `cgVarPut(..., isGlobal=1)` теперь реально
вызывается, `cgViGlobal[i]` = 1, плоские присваивания в глобалы перестали
падать с `undefined variable '<name>'`.

**`emitFunction` (codegen.cpp:7645) → `cgEmitFunction(fid)` в `src/cg_expr.z`.**
Полный: `funcOffsets` (`cgFuncOffsetPut`), вызов `cgSetupFunc`, сброс
регистров, `funcEndLabel = newLabel()`, пролог (`push rbp; push rbx;
mov rbp,rsp; sub rsp,frameSize`), копии параметров — отдельные циклы на
каждый параметр: регистровые слоты (`maxReg = sysvAbi ? 6 : 4`, float →
`emitFloatStoreToBP`, SysV `rdi/rsi/rdx/rcx/r8/r9`, Win64 `rcx/rdx/r8/r9`)
и стековые (`srcOff = sysvAbi ? 24+(slot-6)*8 : 24+slot*8`, float через
`movss`, остальное через `mov rax`), тело, `emitLabel(funcEndLabel)`,
эпилог (`add rsp,frameSize; pop rbx; pop rbp; ret`). Ветка `emitDebugInfo`
не портируется (см. выше). `ZT_DUMP` (`:7773`) пока не портиран — вместо
него паритет берёт `tools/cgemit_check.py`.

**Паритет поднят с «подстроки возврата» до целой функции.** Харнесс
`src/_cgemit.z` (шаблон в `tools/cgemit_check.py`) теперь зовёт
`cgEmitFunction(fid)` целиком, а не только последний `N_RETURN`:
сравниваются пролог + копии параметров + **все** statement'ы тела + эпилог.
Это заодно включило ветку `emitJmp(funcEndLabel)` у `N_RETURN` (она
появляется только когда `funcEndLabel >= 0`, т.е. только внутри
`emitFunction`).

**Новый тест `tools/cgemit/stmt1.z` (13 функций, байт-в-байт)** — первая
программа с контролем потока: `if/else/else-if`, `while` +
`continue`/`break`, вложенный `for`, `loop`, `switch/case/default`,
индексное/через путь полей/через указатель присваивание, объявления
`int/float/bool/array/struct`, вызовы. Раньше таких не было вообще:
`expr*.z`/`builtin*.z`/`call1.z` — почти один `return <expr>`.

**Смоук `src/_cgtest.z` переписан на `cgEmitFunction(sfid)`** (пролог +
параметры + тело + эпилог вместо голого тела) и стал **жёстким ассертом**:
`len=547`, `h=8500926884890685652`. Важная грабля: **`func main -> int`,
вернувший ненулевое значение, НЕ валит процесс** — `emitLinuxEntryPoint`
выходит с 0 в любом случае, поэтому **все** ветки FAIL в `_cgtest.z`
переписаны на `exit(1)` (иначе регрессия печатала бы FAIL и всё равно
проходила бы). Это проверено негативным прогоном (`NEG_RC=2`, затем
`POS_RC=0`). Новая цель `test-cgtest` в `Makefile.linux` входит в `make test`
и гоняет смоук; раньше `_cgtest` в сьют вообще не входил.
Рядом ранее добавлен блок `fixupSectionRVAs`: сдвиг на `cgCodeLen=0x1800`
при `heapArea=0x3018` → базы `rdata=0x3000/data=0x4000`,
`stringRVA=0x3000`, `heapOffset=0x4000`, `heapFreeHead=0x4008`,
`randSeed=0x4010`, `heapArea=0x4018`, `heapFixTarget[0]==0x4018`.

**Тест:** `make -f Makefile.linux test` зелёный (`MAKE_RC=0`), **17 групп
byte-identical = 146 функций** (было 16/133 — прирост `stmt1.z`);
`src/_cgtest.z` собирается (`BUILD_RC=0`, warning только об unused
`lexErrorCount`) и выходит с `CGTEST_RC=0`.

---

**Дальше** (порядок `codegen.cpp`, места теперь такие: выражения и операторы —
`src/cg_expr.z`, байтовые примитивы — `src/cg_emit.z`, типы —
`src/cg_type.z`, бэкенды — **новые файлы**: `src/codegen_elf.z`,
`src/codegen_ko.z` …):

1. ~~`cgEmitCallExpr`: `http_json` (5260–5505) + `buildHttpJsonHelper`~~ —
   **ГОТОВО 05.10** (см. раздел выше). Дальше — диспетчер `try*Call`
   (5506–5614, порядок для `app linux` см. PLAN.md) — **решить инверсию
   зависимости через `ptr<func(…)>`-hook или держать в `cg_expr.z`**
   (причина в разделе 05.10). Инлайн-билтины 3016–5505 — **ГОТОВЫ**.
   Generic ABI-путь (5619–6202) — **ГОТОВ**.
2. ~~Остальные ветки `cgEmitStmt`~~ — **ГОТОВО 05.10** (кроме `N_ASM`,
   см. раздел выше). Осталась одна ветка `N_ASM` → в п.3 (`emitAsmInstr`).
3. `emitAsmInstr`/`emitAsm16Instr` (это и есть единственная недостающая
   ветка `cgEmitStmt`).
4. ~~`populateGlobalVarInfos` + `globalOffsets`~~ — **ГОТОВО 05.10**
   (`cgPopulateGlobalVarInfos` в `cg_type.z` + `cgGoFind` в `cg_emit.z`;
   `globalOffsets` = `cgGoName/cgGoOff/cgGoN`, как и раньше заполняет
   `cgBuildLinuxImportData`). См. раздел выше.
5. ~~`emitFunction`~~ — **ГОТОВО 05.10** (`cgEmitFunction` в `cg_expr.z`,
   паритет целых функций). Дальше `emitEntryPoint` (630), `generateWide`
   (8565).
6. **`src/cg_elf.z` НАЧАТ 05.10** (константы/образ/буферы +
   `buildLinuxImportData`, **`fixupSectionRVAs` ГОТОВО 05.10**, **весь
   entry-point кластер ГОТОВО 05.10 (часть 3)**: `emitLinuxEntryPoint`,
   `emitLinuxExitSyscall`, `emitLinuxExitViaLibc`, `emitLinuxLibInit`,
   `emitStartupRelocator`, `emitMixCrt0Call`).
   `resolveFixups` (codegen_pe.cpp:394) уже есть как `cgResolveFixups`
   (`cg_emit.z:2046`), `resolveJmpFixups` (:446) уже есть как
   `cgApplyFixups` (`cg_emit.z:1989`). Осталось: `buildELF`
   (codegen_elf.cpp:631..1039, заголовок :919..948), `buildELFLib`
   (:1040), `emitShaderModules` (codegen_shader.cpp), затем
   `collectStrings`/`generateWide` (8565) и `src/codegen_ko.z`, хвост
   `try*Call` для `app linux` — **слой 1 целиком**; только после этого
   (и удаления `.cpp` по «Правилу чистки») — слой 2, остальные бэкенды.
   **Про паритет контейнера:** харнесс эмитит целую функцию (пролог + тело
   + эпилог), а **с 05.10 (часть 3) — и весь TU одним буфером** в режиме
   B (пас `_text`: все функции + `cgEmitLinuxEntryPoint`, затем
   `cgResolveFixups` + `cgApplyFixups`). `call rel32` и меточные переходы
   при этом проверяются уже **без маски**; маскируются только слоты,
   которые заполняет контейнер (LEA на глобал/строку, GOT, heap, KO,
   сеть). Режим A (`--obj`) по-прежнему по одной функции: его референс —
   `.o`, где вход даёт ещё не портированный `emitKOEntry`.
7. **`syslibs.cpp` (DSO-проба `linuxSonameFor`)** — сейчас возвращается
   задокументированный фоллбэк `"libc.so.6"`; проба поставщика символа
   (`LinuxSolibProbe`) не портирована и не блокирует entry point (таблица
   импортов, которую она питает, непуста только у программ с `extern`).
8. Подключить вывод `cgErrSetPlain` в `main.z`, переключить драйвер с
   `zffi_codegen` на `.z`-бэкенд и убрать extern.
9. **Порядок после ядра (указание пользователя 05.10):** закончить порт —
   и только затем **собирать под Linux «драйверы и модули, а точнее
   динамические библиотеки»**: это `buildELFLib` (codegen_elf.cpp:1040)
   + `emitLinuxLibInit` (`:610`) → образ `.so`/`ET_DYN` c `DT_INIT`,
   экспортируемой таблицей `exportEntries` и `emitStartupRelocator`,
   плюс режим модуля ядра `koDriver` (`buildKO`, codegen_ko.cpp). После
   этого — **слой 2, начиная с WinPE** (`codegen_pe.cpp`: PE32+ контейнер,
   `buildPE`, импорт/экспорт, `resolveFixups`/`resolveJmpFixups` уже
   лежат в PE-файле и были указаны выше как общие).

---

**Требование (указание пользователя):** в `.z` должно быть **всё**, что в
`codegen.cpp`, плюс весь `codegen_elf.cpp` (он = контейнер ELF **и**
Linux-бэкенд), плюс связанные файлы, **включая `codegen_vulkan.cpp`**.
Ничего «потом» не откладывать. Полная инвентаризация и состав первого
бэкенда — в `PLAN.md` (раздел «Объём (инвентаризация 04.10)»).

**Уточнение 04.10 (вопрос пользователю, ответ записан в PLAN.md):**
конечная цель та же, но порядок — **слоями**. Сейчас делается ядро
(модули `cg_*` + фасад) и **слой 1 = только Linux/x86**
(`codegen.cpp` + `codegen_elf.cpp` + `codegen_ko.cpp` + хвост `try*Call`
для `app linux`); бэкенды PE/arm64/stm32/wasm/dx11/… — слой 2, потом.
*Причина сужения:* 43 145 строк `codegen*.cpp` в один шаг нелогично тащить,
пока `zenith-z` ещё не собирает проекты. Отмены «ничего не откладывать»
нет — меняется порядок; внутри слоя 1 полнота сохраняется (vulkan, wayland,
net, sound, builtins, ko, dwarf — все входят).

Кратко: `src/codegen*.cpp` = **43 145 строк**; первый бэкенд (x86-64 ELF)
= `codegen.cpp` (8844) + `codegen_elf.cpp` (1345) + `codegen_vulkan.cpp` +
`wl_*` + `net*` + `sound` + `builtins*` + `ko` + `dwarf` + `disasm` +
`httpdl` + `tls` + `js` + `sw` + `shader`.

Порядок вызовов `try*Call` для `app linux` — `codegen.cpp:5506–5614`
(см. PLAN.md).

Драйвер при этом продолжает вызывать бэкенд через `zffi_codegen`, пока
`codegen.z` не соберётся; после — main.z переключается и extern убирается.

**Разбивка на 2 сессии** — только когда бэкендов станет больше одного
(см. PLAN.md «Разбивка на 2 параллельных сессии»).

---

### 05.10 (часть 3) — весь Linux entry-point кластер + чек целого TU

Портированы все `emitLinux*` из `codegen_elf.cpp:518..630` в `src/cg_elf.z`
(конец файла, сразу после `cgEmitShaderModules`), плюс одна сборка из
`codegen.cpp:1803` — `cgEmitGlobalInit()` был дописан в конец
`src/cg_expr.z` в предыдущем шаге.

**`src/cg_elf.z` (в порядке появления в C++):**

- `cgEmitMixCrt0Call()` ← `mix.cpp:1453`. `mixCtx` — конструкция
  `--cxx`-драйвера, в чистых Zenith-программах её нет, поэтому заведён
  `var cgMixHasAny: int = 0`, и функция — задокументированный no-op;
  места вызова (entry / libInit / PE-entry) остаются транскрибируемыми
  байт-в-байт на будущее.
- `cgEmitStartupRelocator()` ← `:625`. На Linux GOT-слоты OS-импортов
  заполняет сам динамический линковщик до `_start` (PT_INTERP/PT_DYNAMIC/
  .rela из `buildELF`), поэтому как и в C++ — ранний выход при
  `cgElfImpN == 0`, тело пустое. Нужен для равномерности кадра.
- `cgEmitLinuxExitSyscall()` ← `:577` — `B8 E7000000 / 31FF / 0F05`.
- `cgEmitLinuxExitViaLibc() -> int` ← `:593` — `FF 15 <GOT exit>` +
  `EB FE`. Возвращает 1, если путь эмитирован; условие как в C++:
  `cgElfImpN == 0` (статически слинкованный образ держит сырой syscall,
  иначе ради `exit` пришлось бы тянуть DT_NEEDED). rdi уже держит код
  выхода. Имя и soname заводятся через `cgStrSynth`.
- `cgEmitLinuxLibInit()` ← `:610` — `DT_INIT` образа `.so`:
  `cgEntryPointCodeOffset = cgCodeLen` + `cgEmitGlobalInit()` +
  `cgEmitMixCrt0Call()` + `C3`. Минус `_exit` — это работа `_start`.
- `cgEmitLinuxEntryPoint()` ← `:518` — сам `_start`. Порядок байтов
  воспроизведён полностью: `cgEntryPointCodeOffset`; при `cgWlUsed != 0`
  сброс envp в `wlEnvRVA` (`48 8B 04 24`, `48 8D 8C C4 10 00 00 00`,
  `48 8D 15 <rel32>` c `cgPushGlobalFix(..., cgWlEnvRVA)` **до**
  `emit32(0)`, `48 89 0A`); `cgEmitStartupRelocator()`; выбор entry —
  сначала `"main"` по `cgStrEqId(cgFoName[i], "main")`, иначе первый
  не-extern из `H_FUNCS` (`cgF(fid, 11) == 0`); `cgEmitGlobalInit()`;
  `cgEmitMixCrt0Call()` + `E8` + `cgPushCallFix`; `31 FF`; либо путь
  libc, либо `B8 E7000000 / 0F 05`; финально `F4 / EB FE`.

**`src/cg_zast.z` — синтетические `strId` (`cgStrSynth`).** ZAST strId —
это ОФФСЕТ от `cgStrBase` на `u32 len + bytes`, а не индекс в закрытой
таблице: `cgStrPtr/cgStrLen/cgStrIs/cgStrIdsEq/cgStrEqZ` — чистая
адресная арифметика. Поэтому строку, которой в разобранной программе НЕТ
(`"exit"`, soname для `.dynstr`, `"$mixcrt0"`), можно завести отдельным
буфером и вернуть `buf - cgStrBase` — читатели её не отличат от настоящей,
**правок в читателей не нужно**. Реализовано: `var cgStrSynBuf/cgStrSynLen`,
`cgStrSynthInit()` (вызывается из `cgBind` **сразу после** `cgSynthInit()`),
`cgStrSynth(lit)` с интернированием linear-scan'ом. Два правила те же, что
у синтетических узлов: буфер аллоцируем **после** блоба (аллокатор
монотонный → адрес > `cgStrBase` → id неотрицательный; отрицательный уехал
бы в `peek32(cgStrBase - X)` на чужую память), и лейаут копирует strtab
(`u32 len`, затем `len` байт, без выравнивания).

**`src/cg_emit.z` — `cgLinuxSonameFor(sym) -> int`.** Полная версия
(`syslibs.cpp:94`) делает DSO-пробу поставщика символа и возвращает
`"libc.so.6"`, когда проба ничего не нашла; здесь возвращается этот
фоллбэк — проба остаётся отдельным юнитом (см. «Дальше», п.9). Функция
лежит в **ядре**, а не в `cg_elf.z`, потому что generic-путь extern-вызова
(`codegen.cpp:6168`) зовёт её тоже. Возвращает ZAST strId.

**Дефект паритета закрыт:** `src/cg_expr.z` (ветка SysV extern-вызова)
раньше передавала `dllId` в `cgPushElfImport` безусловно, а C++ делает
`importDll.empty() ? mix::linuxSonameFor(call->name) : importDll`. В
`selfhost/parser.z:747` `azSet(id, 12, dll)` вызывается **только** при
`from "..."`, т.е. без него `dllId == 0` и в `.dynstr` уезжал пустой
soname. Исправлено: `var soname = dllId; if soname == 0 { soname =
cgLinuxSonameFor(name) }`. Байты не менялись — исправились только
метаданные фикстур.

**Харнесс поднят до целого TU.** В `tools/cgemit_check.py`:
- `pbMaskWhole()` — маска, в которой **нет** `cgCallFix*`/`cgFuncRef*`
  (их чинит `cgResolveFixups()`), и остаются только слоты, которые ещё
  заполнит `buildELF`/`buildPE`: rip-relative LEA на глобал/строку,
  GOT-слоты `elfImportFixups`, heap, KO, сеть.
- плейсхолдер `@WHOLE@` в шаблоне: режим B получает пас whole-TU
  (`cgPerFuncReset()` → `cgFuncOffsetsReset()` → все не-extern функции в
  порядке объявления → **`cgEmitLinuxEntryPoint()` только если
  `cgIsLinux != 0`** → `cgResolveFixups()` → `cgApplyFixups(0)` → строка
  `_text`), режим A — пусто (там референс — `.o`: вход даёт ещё не
  портированный `emitKOObjInit`/`emitKOEntry`, а `ref_blob` вообще не
  собирается). Для не-Linux-цели буфер останавливается на последней
  функции и всё равно ложится **префиксом** `.text` — `find_masked` это
  принимает.
- Это снимает маскуровку с `call rel32` и меточных переходов: раньше они
  проверялись только внутри маски, теперь — байт-в-байт.

**Баг, найденный этим чеком:** `cgHttpJsonHelperEmitted`
(`src/cg_httpjson.z:542`) — флажок «врезать `http_json`-хелпер ровно раз
на переводный блок» (`codegen.h:521`). Вторая эмиссия того же блока
(второй проход харнуса) видела `== 1` и пропускала хелпер: 600 байт
вместо 3232. В C++ такого состояния между проходами не бывает — там один
проход на TU. Исправлено в `cgPerFuncReset()` шаблона
(`cgHttpJsonHelperEmitted = 0`, `cgHttpJsonHelperLabel = -1`): режим
«функция за функцией» трактуется как независимые TU (иначе вторая функция
с `http_json` вообще не совпала бы), а whole-TU пас ресетит один раз
перед циклом — ровно то, что `generateWide` делает для настоящего
бэкенда.

**Проверка.** `make -f Makefile.linux test` — `MAKE_RC=0`, **17 групп /
151 функция байт-в-байт** (было 146: +5 строк `_text`). Среди них
`_text` для `heap1_b.z` и `net1_b.z` (`app linux`) — то есть **сам
`emitLinuxEntryPoint`, `emitGlobalInit` и путь `exit` через libc
провалидированы против C++ по-байтово**, включая меточные переходы и
`call rel32` без маски. `codegen-smoke src/_cgtest.z: OK`.

---
### 05.10 (часть 4) — `collectStrings` (первая половина generateWide)

Портированы `collectExprStrings`, `collectStmtStrings`, `collectStrings`
(`codegen_pe.cpp:169..340`) в `src/cg_expr.z`, сразу за пулом строк
(`cgPushStrFix`). Плюс константы `CG_RT_DX11=1`/`CG_RT_VULKAN=2` в
`src/cg_zast.z` (`ast.h:12`).

**Зачем:** `generateWide` зовёт `collectStrings()` ДО
`buildImportData`/`computeSectionRVAs`. LEA-фикстуры индексируют пул по
`stringOffsets`, а сама эмиссия функций добавляет в пул собственные строки
уже **после** построения `stringOffsets` — поэтому пул обязан быть заполнен
заранее.

**Разметка ZAST, использованная в обходе** (сверена с `cgEmitStmt`/
`cgAllocStmts`/`parseSwitch`):

| узел | поля |
|---|---|
| `N_RETURN` | f0 = value |
| `N_EXPRSTMT` | f0 = expr |
| `N_ASSIGN` | f0=name, f1=pathStart, f2=pathLen, f3=indexExpr, **f4 = value** |
| `N_VARDECL` | f7 = init, f8 = arraySize, f9 = isConst |
| `N_IF` | f0 = cond, f1/f2 = then, f3/f4 = else |
| `N_WHILE` | f0 = cond, f1/f2 = body |
| `N_LOOP` | f0/f1 = body |
| `N_SWITCH` | f0 = cond, f1 = casesStart, f2 = casesLen; запись кейса = **[cond, bodyStart, bodyLen]**, stride 3 (`selfhost/parser.z:1695`), у `case:` cond = 0 |
| `N_FOR` | f0 = name, f1 = start, f2 = end, f3 = step, f4/f5 = body |
| `N_STRING` | f0 = strId |
| `N_BINARY` | f0 = left, f1 = right |
| `N_CALL` | f0 = name, f2 = argsStart, f3 = argsLen (`cgCallArgc`/`cgCallArg`) |
| `N_MEMBER` | f0 = object, f1 = member |
| `N_ARRAYACC` | f0 = array, f1 = index |

**Порядок обхода = порядок C++** (он задаёт номера в пуLE): If — cond,
then, else; For — start, end, step, body; Switch — cond, затем каждый кейс
(cond, body). Служебная `cgCollectBlockStrings(start, len)` = цикл по side
-списку (в ZAST блока как узла нет — блок И есть side-список).

**Замеченные особенности эталона, воспроизведённые намеренно:**
- `N_PTRASSIGN` в `collectStmtStrings` **нет** (в C++ это отдельный
  `PtrAssignStmt`, ветки dynamic_cast для него в цепочке не объявлено) —
  литерал в `*p = "s"` в пул **не попадает**. Иначе поехали бы все
  номера дальше.
- То же для `N_ASM` (`AsmStmt`).
- `AssignStmt` собирает **только `value`**; `indexExpr` (индекс в
  `a[i] = v`) ходит отдельно — по нему бродит `detectNetwork*`, а не
  `collectStrings`.
- `CallExpr` обходит **только аргументы**, имя функции не трогает.

**DX11-пре-добавление (`codegen_pe.cpp:300`) не портировано** — 16 байт
IID, четыре строки шейдерных билтинов (`"main"`, `"vs_5_0"`, `"ps_5_0"`,
`"POSITION"`) и пути `dxDiagPath(kDxDiagFiles[i])` из
`codegen_dx11_shaders.cpp` (слой 2). Вместо тихого расхождения —
**громкий `cgErrSet`**, когда `cgH(H_RENDERTYPE) == CG_RT_DX11`: иначе
LEA-цели молча уехали бы в мусор.

**Проверка.** Новый блок в `src/_cgtest.z`: программа, задевающая все
ветки (`var`/`=`/`print`/`if-else`/`while`/`loop`/`for`/`switch` с
`case`+`case:`/`ptr`-присваивание + extern + глобал), затем
`cgCollectStrings()` и ассерт `cgStrPoolN == 12` плюс `zsChk(i, lit)` на
каждый элемент: `f1..f11` (в порядке обхода) и `g1` (глобал последним).
Литерал `f12` из `*p = "f12"` в пул не попал — это и проверяется счётчиком.
Негативный прогон: подстановка `!= 12` → `NEG_RC=1`, откат → `POS_RC=0`.
`make -f Makefile.linux test` — `MAKE_RC=0`, **17 групп / 151 функция
байт-в-байт**, `codegen-smoke src/_cgtest.z: OK`.

---
## 05.10 (часть 5) — `buildELF` + `generateWide` (Linux-ветка)

Последний кусок первой половины `generateWide`: после `collectStrings` /
`computeSectionRVAs` / `buildLinuxImportData` / эмита функций и entry
`fixupSectionRVAs` → `resolveFixups` → `applyFixups` → **`buildELF()`**,
который складывает ELF в `cgImg` (C++ писал файл сразу).

### Что портировано (`src/cg_elf.z`, конец файла)

| Блок | C++ | Назначение |
|---|---|---|
| `cgImgPadTo` / `cgImgAppendStr` | `out.resize`/`insert` | рост буфера образа |
| `cgCheckFixupOverlaps` | `codegen_pe.cpp:350..392` | слияние ключей `(pos<<4)\|list`, shell sort, диагностика |
| `cgOvListN` / `cgOvListPos` | — | 10 списков фикстур: call, funcRef, jmp, str, importCall, heap, global, net, elfImport, js |
| `cgElTmp`/`cgElW` + `cgElPut8/16/32/64` | `put16/32/64` | временный буфер `.dynstr`/`.dynsym`/`.rela`/`.hash` |
| `cgGot*`, `cgEl*` (soname/sym/strOff/idx) | `got`, `dynstr`, `symIdx`, `strOff` | состояние динамической секции |
| `cgElfHash` | `elf_hash` (`codegen_elf.cpp:777`) | SysV DT_HASH |
| `cgElfPatchDisp` | `patchDisp` | `disp32 = targetRVA - (textRVA + codePos + 4)` |
| **`cgBuildELF()`** | `codegen_elf.cpp:631..1040` | GOT → `.dynstr` → `.dynsym` → `.rela` → `.hash` → layout → ehdr/phdrs → сборка файла → `kZenithMagic` |
| **`cgFreshState()`** | `codegen.h:477..484, 840..843` | сброс всех членов `Codegen` перед generate (реентерабельность) |
| **`cgGenerateWide()`** | `codegen.cpp:8565..8829` | Linux-ветка целиком |

`cgGenerateWide()` вызывается из `src/_cgimg.z`; в `src/_cgtest.z` его
**не** вносят (иначе харнесс начинает собирать целые образы).

### Три бага, найденных сверкой

1. **Shell sort в `cgCheckFixupOverlaps`** — вместо `break` стоял
   `j = 0`: цикл выходил с `j == 0`, и `cgOvItem[j] = v` затирал нулевой
   элемент. Массив превращался в мусор → ложное
   «overlapping fixups in ELF». Лечится флагом `done`
   (`while j >= gap && done == 0`), т.к. писать `break` внутри
   `while` в этом юните не стали.
2. **GOT: удвоенный прирост.** В C++ слоты считает
   `slotRVA = dataRVA + data.size() + got.size()`, где `got` —
   **отдельный** вектор, вставляемый в `data` уже после цикла, т.е.
   `data.size()` внутри цикла константа. Порт делал
   `cgDataFill(0, 8)` **внутри** цикла → база росла на 8 за итерацию, и
   i-й слот получал `dataBase + 2*i*8`: первый совпадал, дальше всё
   уезжало (+8 на каждый слот). Симптом — единичное расхождение
   `r_offset` во второй записи `.rela`. Лечится заморозкой базы:
   `var gotBase: int = cgDataLen` до цикла.
3. **`--no-opt` обязателен.** Сверяться надо с эталоном, запущенным с
   `--no-opt`: `optimizer.cpp` в selfhost-драйвере ещё не портирован, а
   эталонный проход убирает неиспользуемые глобалы (`gname` + её литерал
   в `.rdata`) и меняет `dataSize` (48 вместо 56) — расхождение выглядело
   как баг `buildELF`, хотя это был проход оптимизатора.

### Тест

- `src/_cgimg.z` — драйвер: два `.z`-исходника влиталах
  (`app linux` **динамическая**: extern `puts`, глобалы, строки,
  `while`/`if-else`/`for`; и **статическая**: рекурсивный `fib`),
  `parseRun` → `cgBind` → `cgGenerateWide()` → `cgImgLen` + FNV-64
  всего образа. Linux-билтины (`print`/`alloc`/…) в исходниках
  **намеренно не используются** — их диспетчер ещё не портирован
  (см. ниже).
- `tools/cgimg_check.py` вынимает литалы из `_cgimg.z`, компилирует их
  эталоном с `--no-opt`, считает `len` + FNV-64 (тот же `cgFNV`, что в
  `cgemit_check.py:251`, печать знаковая) и сравнивает с выводом драйвера.
- `make -f Makefile.linux test-cgimg` (добавлен в `test`).

**Проверка:** `make -f Makefile.linux test` зелёный (`MAKE_RC=0`),
**17 групп / 151 функция байт-в-байт**, `codegen-smoke src/_cgtest.z: OK`,
`codegen-image src/_cgimg.z: OK` (imgA 12722 байт / imgB 8222 байт —
совпали со ссылкой).

### Грабли (новые)

- **`print(x)` в selfhost — это `println`**: метка и число всегда идут
  разными строками, собирать «ключ значение» в одну строку нельзя;
  `print(intPtr)` печатает **число**, а не строку по указателю (для
  строки нужен литерал). Отсюда формат вывода `imgA len=\n12722`.
- **Дамп образа в файл невозможен**: `zffi_writeFile(path, content)`
  NUL-terminated, а ELF полон нулей. Диагностика шла построчным
  выводом: `e_phoff`/`p_flags`/`p_filesz`/`p_memsz` каждого phdr, затем
  `u32`-слоты с отступа 0x3000 (LOAD2) и 64-байтовые чанковые хеши —
  этого хватило, чтобы сузить расхождение до одного `r_offset`.
- `pow2()` в `.z` нет — степени собираются накоплением (`m = m * 256`).
- `else if` в `.z` есть (не `elif`): цепочки `cgOvListN`/`cgOvListPos`
  и выбор бакета в `.hash` переведены на `else if`.
- `cgPerFuncReset()` существует **только в шаблоне харнесса**; в
  `cgGenerateWide()` его быть не должно — `cgFreshState()` уже обнулил
  `cgCodeLen` и таблицы фикстур, а между ним и первой функцией никто
  не пишет в `.text`.
- `detect*Usage()` в C++ **не вызывается откуда-либо ещё** — флаги
  (`cgWlUsed`, `cgHttpGetUsed`, …) остаются 0. Для программ без тех
  билтинов это совпадает с эталоном; когда появятся `tryLinux*Call`,
  эти детекторы станут отдельным юнитом.
- **Следующий блокер по прогону:** `cg_expr.z:7135` отвечает
  «call to a non-user function: backend builtin dispatch
  (codegen.cpp:5506) is not ported» на **любой** вызов системного
  билтина в `app linux`. Это `codegen_builtins_linux.cpp` (814 строк,
  `tryLinuxCall` + `tryLinuxGUICall`), затем
  `codegen_net_linux.cpp` (569), `codegen_wl_linux.cpp` (443),
  `codegen_gui.cpp`/`codegen_vulkan.cpp`. До этого порта selfhost
  собирает только программы без `print`/`alloc`/выхода в ОС.

---
## 05.10 (часть 6) — ДИРЕКТИВА НА ЗАВТРА + `tryLinuxCall` (частично)

### Директива пользователя (05.10, вечер): selfhost → ТОЛЬКО СИСКОЛЛЫ

**Переписать всё в selfhost так, чтобы генерируемые программы работали
исключительно на сырых системных вызовах** — без libc, без динамического
загрузчика, без `PT_INTERP`/`DT_NEEDED`/GOT-резолва. Начать завтра.

Что это задевает в `.z` (список к отработке, порядок по убыванию цены):

1. **`src/cg_expr.z` — extern-путь.** `cgEmitCallBody` для `f11 == 1`
   (extern) делает `cgPushElfImport(cgCodeLen, name, soname)` → GOT-слот →
   `PT_INTERP`/`PT_DYNAMIC`. При «только сисколлы» extern-вызов либо
   **запрещается** (громкий `cgErrSet`), либо эмитится как прямой
   syscall-биндинг (как уже делает `print`/`alloc`). Пока extern даёт
   `puts`/`exit` через libc — это и есть главный «нельзя».
2. **`src/cg_elf.z` — `cgBuildELF`.** Ветка `if cgElfImpN > 0` (interp,
   dynstr/dynsym/rela/hash, PT_DYNAMIC) становится недостижимой →
   `phnum = 2` всегда, `imgA`-сценарий (динамический) перестаёт
   существовать. `cgBuildLinuxImportData` остаётся (heap-слоты и
   `randSeed` в `.data` — это не libc).
3. **`emitLinuxExitViaLibc`** (`src/cg_elf.z:860`) — убрать из траектории,
   оставить только `emitLinuxExitSyscall`.
4. **`tools/cgemit/*.z`** — тесты, которые дёргают extern, перевести на
   syscall-эквиваленты.

Сейчас `make -f Makefile.linux test` **зелёный** — директива ещё НЕ
применена, чтобы не ломать паритет, пока идёт разметка (и чтобы два
параллельных агента имели рабочую базу).

### Два параллельных агента: `src/` — их зона, `selfhost`/`*.z` — моя

| Зона | Файлы | Кто |
|---|---|---|
| C++ эталон и драйвер | `src/*.cpp`, `src/*.h` | **агенты 1 и 2** |
| selfhost-бэкенд | `src/*.z` (кроме `main.z`, см. ниже) | **я** |
| тесты/доки | `tools/cg*.py`, `Makefile.linux`, `NEXT.md`, `PLAN.md` | **я** |

**Контракт между нами:**
- Единственная общая проверка — `timeout 1800 make -f Makefile.linux test`
  → `MAKE_RC=0`, **17 групп / 151 функция байт-в-байт**, плюс
  `codegen-smoke src/_cgtest.z: OK` и `codegen-image src/_cgimg.z: OK`.
  Зелёное = база цела; красное = чинит тот, кто последним трогал.
- Если агенты меняют кодоген C++ (`codegen*.cpp`), **эталонные хеши** в
  `src/_cgtest.z` (`h64`/`h32`, `cgStrPoolN == 12`) и вывод
  `tools/cgimg_check.py` (len+FNV64 двух образов) надо пересчитать —
  я это сделаю по их правке, они должны пинговать в `NEXT.md`.
- `src/main.z` — общий: драйвер selfhost. Правки согласовывать, чтобы
  сплайс `use`-цепочки не разъехался.
- Порядок `use` линейный: `codegen → cg_elf → cg_expr → cg_type →
  cg_httpjson → cg_emit → cg_zast` — новые модули добавлять только в
  конец.

### `tryLinuxCall` — начат сегодня, остановлен на середине

**Что уже в `src/cg_expr.z` (в конце файла):**
- `cgLinWsys(fd, nr)` (`mov edi,fd; mov eax,nr; syscall`) и
  `cgLinWriteOneByte(fd)`.
- `cgTryLinuxCall(c) -> int` — **ветка печати целиком**
  (`codegen_builtins_linux.cpp:28..254`): `print/printLn/println/
  eprint/eprintLn/eprintln`, ветки **string** (strlen-скан + `write`) и
  **int** (знак, div/10, запись назад в буфер на `[rsp]`), завершающий
  `"\n"`, `cgRegsUsed = 1`, `cgXmmUsed = 0`, результат в `cgLinResReg`.
- Ветка **float** (`:102..186`) и `sleep`/`halt`/`exit`/`mem*`
  (`:256..479`) — **не портированы**: float даёт конкретный
  `cgErrSet("print(float): ... not ported")`, остальное — возврат 0,
  из-за чего срабатывает прежняя общая ошибка.
- Точка включения — `cgEmitCallBody` там, где стояла
  «backend builtin dispatch not ported»: сначала
  `if cgIsLinux == 1 && cgTryLinuxCall(c) == 1 → return cgLinResReg`,
  иначе старая ошибка.

**Критичное открытие про харнесс (не наступить завтра):**
- **Режим A** (`cgemit_check.py` без `-b`) форсит
  `cgObjOutput = 1; cgKoDriverFlag = 1` → в C++ `prog.koDriver == true` →
  диспетчер `codegen.cpp:5510` зовёт **`tryKOCall`**, а не `tryLinuxCall`.
  Поэтому режим A для печати **не годится**: он сверяет ветку
  `codegen_builtins_linux.cpp:496`, которую я не трогал.
- **Режим B** (`-b`, `cgObjOutput = 0`) — это и есть настоящий
  `tryLinuxCall`. Тест лежит в **`tools/cgemit_wip/linprint_b.z`**
  (намеренно **вне** `tools/cgemit/`, иначе `wildcard *_b.z` подхватит
  его и уронит `make test`).

**Результат прогона `python3 tools/cgemit_check.py -b tools/cgemit/linprint_b.z`
— ПОЛНЫЙ ПАРИТЕТ, `--- 9/9 functions byte-identical` (включая `_text`).**
`lp01` строка, `lp02..lp05`/`lp08` `print(int)`, `lp06`/`lp07` `eprint*` — все OK.
Тест переименован из `tools/cgemit_wip/` обратно в **`tools/cgemit/linprint_b.z`**,
иначе wildcard его не видит.

**Найденный баг (в «Грабли»), единственный, из-за которого падали `lp02..lp08`:**
`emitJcc(cond: int, label: int)` принимает **id строковой таблицы**, а не
указатель на литерал. Пять моих вызовов `emitJcc("=="/"!="/">=", …)` внутри
`cgTryLinuxCall` молча проваливались в `else → 0x84` (JE). Для `"=="` это
случайно верно (поэтому `lp01`/`lp06` проходили), для `"!="` (0x85) и
`">="'` (0x8D) — нет. Эталон выдавал `0f8d2c000000`, мы `0f842c000000`:
**разница ровно в одном байте на условном переходе**, всё остальное
совпадало. Лечение — `emitJccLit(...)` (та же таблица, но сравнение через
`cgLitEq` на NUL-литералы), как уже делалось в `cg_emit.z:2181..2186`.

**Итог юнита «05.10 (часть 6)»:** ветка печати `tryLinuxCall` закрыта
(строки + int + eprint*, 9/9). Остаются: float-ветка (`:102..186`),
`sleep`/`halt`/`exit`/`mem*` (`:256..479`), `tryKOCall` (режим A).
Проверка базы: `make -f Makefile.linux test` → `MAKE_RC=0`,
**18 групп / 160 функций** байт-в-байт.

---
## 05.10 (часть 7) — `tryLinuxCall` ЗАКРЫТ: float, halt, exit, mem*

**Проверка:** `python3 tools/cgemit_check.py -b tools/cgemit/linprint_b.z`
→ **`16/16 functions byte-identical`** (включая `_text`, 2898 байт).
**База:** `timeout 1800 make -f Makefile.linux test` → **`MAKE_RC=0`,
18 групп / 167 функций байт-в-байт** + `codegen-smoke src/_cgtest.z: OK` +
`codegen-image src/_cgimg.z: OK` + 15 `front-end … match`.

### Что до портировано в `src/cg_expr.z`

| Ветка C++ | Что в `.z` | Тест |
|---|---|---|
| print float, `codegen_builtins_linux.cpp:94..184` | `cgTryLinuxCall`, ветка `cgIsFloatExpr` — знак (`movd eax,xmm0` + `test 0x80000000`), `cvttss2si`, цифры назад от `r8=rsp+48`, `'.'`, 6 знаков дробной (`mulss 10`, `cvttss2si`) | `lp09` `print(3.5)` = 425, `lp10` `print(f)` = 415 |
| `halt`, `:299..305` | `cgEmitLinuxExitSyscall()` | `lp12` = 35 |
| `exit`/`exit_process`, `:306..325` | `emitMovReg(7, r)`/`xor edi,edi` + `cgEmitLinuxExitViaLibc()`, иначе `mov eax,231; syscall` | `lp13` = 44, `lp14` = 55 |
| `memNew`, `:336..402` | бамп-хил-прогон как в arm `alloc` (`cg_expr.z:3258`) **плюс** `rep stosb` по `rbx = totalSize` | `lp15` = 348, reloc-masked 28 |
| `memDel`, `:403..423` | `lea rax,[rcx-16]` + `freeHead` | там же |
| `memByte`/`memQ`/`memByteW`/`memQw`, `:425..479` | хелперы `cgLinMemRead(c, size)` / `cgLinMemWrite(c, size)` (лямбды из C++) | там же |

**`sleep` в `cgTryLinuxCall` намеренно НЕ портирован — он мёртв и там, и
здесь:** общий arm `sleep` из `codegen.cpp:3740` перенесён в `cgEmitCallBody`
(`src/cg_expr.z:3440`) и возвращает раньше, чем диспетчер доходит до
`tryLinuxCall`. Проверено по порядку arm'ов: перед диспетчером
(`codegen.cpp:5501`) есть только `sleep` (3740) и `print` с `!isLinux`
(3856); `alloc`/`free` — `codegen.cpp:3022` и `codegen_builtins.cpp:11`,
`mem*`/`halt` для Linux — только из `tryLinuxCall`
(`tryBuiltinCall` ограничен `Console`/`GUI`, `codegen.cpp:5543`).

**Квирк (паритет сохранён):** `eprint*` всегда помечает аргумент строковым
(`if (isErr) isStringArg = true`), поэтому `eprintln(float)` уходит в
strlen-ветку и печатает **указатель**: `lp11 len=139` против `lp09 len=425`.

### НОВАЯ ГРАБЛЬ: переполнение токенного капа selfhost-лексера

- Симптом при компиляции `src/_cgtest.z`:
  `Lexer error: too many tokens (the selfhost lexer's per-file cap was hit)`.
  Причём это **не** отдельный файл: `expandUseDirectives` (main.cpp:1371)
  склеивает всю `use`-цепочку в **один буфер** и зовёт `parseRun` один раз,
  так что «per-file cap» = размер всего сплайса
  (`selfhost/parser + ast + lower + lexer` + весь `src/cg_*` + сам драйвер
  ≈ 130k токенов).
- **Попало ровно на добавке float/halt/exit/mem* (~600 строк эмиссии).**
- Фикс: `selfhost/lexer.z`
  `const TOK_CAP: int = 131072` → **`524288`** и `var gToks: [524288]Tok`
  (≈37 МБ BSS; `Tok` = 9 полей × 8 байт).
- **Обязательный порядок пересборки** (кап живёт в объекте, а не в `.o`:
  stage-компилятор собирается из `tools/parseobj.o`):
  1. `make -f Makefile.linux bootstrap-parseobj bootstrap-lexobj`
     — пересобрать `tools/parseobj.o` и `tools/lexobj.o` (им можно, они
     компилируют только `selfhost/*`, они маленькие);
  2. `make -f Makefile.linux` — пересобрать `build/linux/parseobj.o`
     stage-компилятором и слинковать `$(BIN)`;
  3. **`make -f Makefile.linux golden`** — иначе `test-front` падает на
     `selfhost/golden/*.dump` (`global TOK_CAP: int = (num 131072)` vs
     `(num 524288)`); после `golden` — 15 `front-end … match`.
- `selfhost/ast.z` имеет свой `NODE_CAP = 131072` — он **не** тронут
  (узлов меньше токенов); если упрётся следующим, фикс тот же.

---
## 05.10 (часть 8) — `tryKOCall` ЗАКРЫТ: printk, ring-0, kernel API

**Проверка:** `python3 tools/cgemit_check.py tools/cgemit/ko1.z` →
**`20/20 functions byte-identical`**.
**База:** `timeout 1800 make -f Makefile.linux test` → **`MAKE_RC=0`,
19 групп / 187 функций байт-в-байт** + `codegen-smoke src/_cgtest.z: OK` +
`codegen-image src/_cgimg.z: OK` + 15 `front-end … match`.

### Инфраструктура, добавленная перед ветками (`src/cg_expr.z`)

- `cgKoExtCallN/Pos/Sym`, `cgKoDataFixN/Pos/Sym` — аналоги
  `KOExtCallFixup`/`KODataFixup` из `codegen.h:316..331`. Хранят
  **указатель на NUL-литерал** (`"_printk"`, `"jiffies"`, …), а не strId и не
  индекс `cgStrPool`: кладь их в пул рдаты значило бы лишний байт в `.rdata`,
  которого у эталона нет. `cgPushKoExtCall`/`cgPushKoDataFix` лезут в
  лимит (1024/256) молча — как и C++ с `reserve`.
- `cgStrFixups` уже были (`cgKoStrFix*`, `cg_expr.z:2138`), трогать не надо.
- Хелперы: `cgKoLoadFmt(idx)` (obj → `lea rdi,[rip+disp32]` + `cgPushStrFix`;
  настоящий `.ko` → `mov rdi,imm32` + `koStrFixups`), `cgKoCall(sym)`
  (`E8 00000000` + fixup), `cgKoPeek(c,size)`/`cgKoPoke(c,size)`.
- **Диспетчер (`cgEmitCallBody`):** KO-ветка поставлена **перед**
  `tryLinuxCall`, зеркалируя `codegen.cpp:5510..5518`:
  `if cgKoDriver() == 1 && cgTryKOCall(c) == 1 → return cgLinResReg`,
  иначе `if cgTryLinuxCall(c) == 1 → …`.

### Что портировано (`cgTryKOCall`, эталон `codegen_builtins_linux.cpp:493..814`)

| Ветка C++ | Тест `ko1.z` |
|---|---|
| print/printLn/println → `_printk`, `:496..550` (строка / int / строковая переменная; float — жёсткая ошибка) | ko01..ko06 |
| `rdtsc`, `:559` | ko10 |
| `io_delay`, `:575` | ko11 |
| `outb`, `:591` / `inb`, `:614` | ko12, ko13 |
| `peek8/16/32/64`, `:636..652` / `poke*`, `:653..674` | ko14, ko15 |
| `kalloc`/`alloc`, `:702` / `kfree`/`free`, `:722` | ko20, ko21 |
| `kzalloc`, `:739` | ko22 |
| `ktime_ms`, `:768` / `ktime_ns`, `:785` / `jiffies`, `:797` | ko23..ko25 |
| fall-through в `tryLinuxCall` (порядок диспетчера) | ko30 `halt`, ko31 `exit` |

**Нюансы паритета:**
- `--obj` (режим A) меняет **только loadFmt** (lea вместо sign-ext) и
  `kalloc`→`malloc` / `kfree`→`free`; **`kzalloc` ветки `objOutput` не имеет**
  и всегда эмитит `mov esi, 0xCC0; call __kmalloc_noprof` — из-за этого
  и всплыл баг ниже.
- `peek*`/`poke*` в обеих сторонах **мёртвы**: generic-армы
  (`codegen.cpp:4543` и `cg_expr.z:3440`) идут раньше диспетчера и не имеют
  гварда `koDriver`. Портированы «в лоб» ради полноты, паритет не меняют.
- `sleep` в `cgTryKOCall` **не портирован** — он и так недостижим (см. часть 7).

### ГРАБЛЬ: десятичная запись hex-константы (поймал тест, не глаз)

- `emit32(0xCC0)` я записал как `emit32(2240)` (0xCC0 = **3264**). Единственное
  расхождение в первом прогоне `ko1.z`: `ko22 MISMATCH len=91`,
  байт **25: `.z 0x08` vs `c++ 0x0C`** (`mov esi, 0x8C0` против `0xCC0`).
- `kalloc` того же `0xCC0` это **не поймал** — в режиме `--obj` он уходит в
  `koCall("malloc")` и `mov esi` вообще не эмитится; поймала только
  `kzalloc`, у которой obj-ветки нет.
- Фикс: константы переписаны **в hex как в C++** (`emit32(0xCC0)`,
  `emit32(0x80)`); `.z` hex-литералы поддерживаются (`emit32(0x80000000)`
  встречался и раньше). Дальше — только так.

---

## 05.10 (часть 9) — Vulkan закрыт: `detectVkUsage` + `tryLinuxVulkanCall`

Директива №6 (портировать `codegen_vulkan.cpp`, 398 строк). **Обе половинки
закрыты**, тест `vk1_b.z` 11/11, общий контракт теперь **20 групп / 198
функций**.

### Что портировано

**1. Detect-обход (`src/cg_elf.z`, перед `cgDetectLinuxNeed`-хуком)**
— эталон `codegen_vulkan.cpp:39..102`:

- `cgDetectVkExpr(e)`, `cgDetectVkBlock(start, len)`, `cgDetectVkStmt(s)`,
  `cgDetectVkUsage()`, заглушка `cgDetectVkSurfaceUsage()`.
- `cgDetectVkExpr` бьёт по N_CALL (`cgStrHasPrefix(cgF(e,0), "vk_")`),
  N_UNARY → f0, N_BINARY → f0+f1, N_MEMBER/N_ARRAYACC → f0.
  **Обход дословно по C++: в нём НЕТ Assign и Switch** — значит
  `a = vk_foo()` флаг не ставит, и это паритет, а не баг.
- Ранний `return` при `cgVkUsed != 0` эквивалентен C++ `break`.
- В `generateWide` оба detect зовутся **перед** `cgBuildLinuxImportData()`
  (как `codegen.cpp:8645..8656`); перенесены только vk и vk-WSI,
  остальные `detect*Usage` ещё стабы.
- Хелпер `cgStrHasPrefix(id, lit)` добавлен в `src/cg_zast.z` рядом с
  `cgStrEqZ` (C++ `name.rfind("vk_", 0) == 0`) с проверкой `cgStrLen(id) < n`.

**2. Эмиттер (`src/cg_expr.z`, в конце файла)** — `cgTryLinuxVulkanCall`,
эталон `:103..399`; рядом заглушка `cgTryLinuxGUICall → 0`
(`codegen_builtins_linux.cpp:19`), чтобы диспетчер зеркалил C++ ровно.

- Хелперы вместо лямбд: `cgVkLeaRip(r, rva)`, `cgVkCallRipImport(symLit)`,
  `cgVkCallRipSlot(slotRva)`, `cgVkFinish(vkExit)`, `cgVkSetNeg1()`,
  `cgVkGuard(wantReg)`, `cgVkMovToR12/R13/R14(src)`,
  `cgVkResolveTableFn(idx, strRva)`.
- Метка `vkExit` вместо `goto emitRestore`: ветка кодирует `cgVkFinish`
  (6 байт pop + `emitJmp(vkExit)`), а общий выход после `if/else if/...`
  снимает регистры и возвращает `cgLinResReg`. Ранние `return 0` по arity
  стоят **до каких-либо emit'ов** — инвариант C++.
- Все9 веток перенесены: `vk_api_version` (0x403000 = 4206592 = VK_API_VERSION_1_3,
  **без** `spillRegs`, с избыточной парой `emitJmp(done); emitLabel(done)` —
  повторено буквально), `vk_instance_version`, `vk_instance_create`
  (+4× `resolveTableFn`, fail → `setNeg1`), `vk_destroy_instance`,
  `vk_gpu_count`, `gpu-семейство` (`vk_gpu_name/api/vendor/device`).
- Диспетчер расширен до четырёх зелёных веток; Net/HttpDl/WL/Shader по-прежнему
  уходят в существующий `cgErrSet`.

### Два источника адресов (главное отличие от всего, что портирано раньше)

1. `cgVkCallRipImport` → динамический импорт через GOT
   (`FF 15`, `cgPushElfImport(pos, cgStrSynth(sym), cgStrSynth("libvulkan.so.1"))`)
   — требует режима B (plain ELF, `PT_INTERP` + `DT_NEEDED`);
   **поэтому тест `vk1_b.z`, а не `vk1.z`**: в режиме A (`--obj`, koDriver)
   такого пути нет.
2. `cgVkCallRipSlot` → `FF 15` по слоту `.data` fn-table, RVA которого уже
   финальный, поэтому C++ считает disp прямо при эмиссии и **ничего не пушит**.

### ГРАБЛЬ (поймал тест): незамаскированная фикстура

- Первый прогон: **3/11**, `vk04 MISMATCH len=84` — расходились ровно 4 байта:
  `.z ff15 dcefffff` vs `c++ ff15 7a1e0000` (disp вызова по fn-table).
- Причина не в арифметике: пер-функциональный прогон харнесса **не вызывает
  `buildLinuxImportData`**, т.е. `cgVkFnTableRVA = 0`, а `pbMask()` умеет
  прятать только те позиции, что записаны в списки фикстур (`cgGlobalFixN`,
  `cgElfImpN`, …). `callRipSlot` их не писал → слот сравнивался вживую и
  заведомо не мог совпасть. То же било в `vk05..vk10` и в whole-TU `_text`
  (422/1692).
- Фикс: `cgVkCallRipSlot` дополнительно делает
  `cgPushGlobalFix(pos, slotRva)`. Это **не меняет байты**: `buildELF`
  (`codegen_elf.cpp:1237 patchDisp` / `cg_elf.z:1385 cgElfPatchDisp`) перепишет
  те же 4 байта той же формулой `rva - (textRVA + pos + 4)`, а маска их
  оставит дикими и в per-функциональном, и в `_text` прогоне.
- Урок для следующих портов: **любой 4-байтовый слот, чьё значение зависит
  от раскладки, обязан попасть в список фикстур**, иначе харнесс его не
  замаскирует. `call rel32`/`funcRef` — уже в списках; lea — `globalFixups`;
  GOT — `elfImportFixups`; дырка — только у косвенных вызовов по
  заранее известному RVA.

### Тест

- `tools/cgemit/vk1_b.z` — **10 функций + whole-TU = 11/11 byte-identical**
  (режим B; файл подхватился wildcard'ом `CGEMIT_PROGS_B` автоматически).
- `timeout 1800 make -f Makefile.linux test` → **`MAKE_RC=0`,
  20 групп / 198 функций байт-в-байт, 0 MISMATCH**, 15 `front-end … match`,
  `codegen-smoke OK`, `codegen-image OK`.

---
## 05.10 (часть 10) — `.so` и `.ko` в selfhost: `cgBuildELFLib` + `cgBuildKO`

Директива №5 («динамические `.so` и `.ko` — текущий юнит: в селфхомт
сделай полностью»). **Оба контейнера закрыты, байт-в-байт.** Контракт
расширен: `cgimg` теперь **5 контейнеров**, а не 2. Группы `test-cgemit`
остались **20 / 198 функций**, `MAKE_RC=0`.

### Тест (главное)

`src/_cgimg.z` + `tools/cgimg_check.py` гоняют пять веток `generateWide`:

| # | контейнер | флаг в харнессе | эталонная команда |
|---|-----------|-----------------|-------------------|
| img1/img2 | `ET_EXEC` `.elf` | mode 0 | `zenith --no-opt` |
| img3 | `ET_DYN` `.so` | mode 1 → `cgLibOutput` | `zenith --no-opt --lib` |
| img4 | `ET_REL` `.o` | mode 2 → `cgObjOutput` + koDriver | `zenith --no-opt --obj` |
| img5 | `ET_REL` `.ko` | mode 3 → koDriver | `zenith --no-opt`, исходник `app linux driver` |

```
cgimg img1: len=12722 h=-5641253020446905413 OK
cgimg img2: len=8222  h=-9025955912980698765 OK
cgimg img3: len=12578 h=-4439412511535050810 OK
cgimg img4: len=1448  h=1716989825771336410  OK
cgimg img5: len=1552  h=-6140340754373555650 OK
codegen-image src/_cgimg.z: OK
```

**Где берётся эталон для img4/img5.** `buildKO` для `--obj` пишет ET_REL
**прямо в выходной файл и возвращается** (`codegen_ko.cpp:669..682`) —
дерева ядра и gcc не нужно. Для driver-режима ET_REL пишется в
`$TMPDIR/zenith_ko_<seq>/<stem>.o` **до** modpost/gcc/ld, а в конце
`buildKO` делает `fs::remove_all(tmp)` (`:824`). Чтобы файл пережил
успешную ссылку, `cgimg_check.py` подставляет в `PATH` стенд-ин gcc
(`/tmp/zenith_fake_gcc/gcc`, `exit 1`): первый же вызов gcc падает,
`remove_all` не выполняется, а валидный ET_REL уже на диске. `koSeq` —
`static`-счётчик процесса, у свежего `zenith` он всегда 1.

### Что портировано

**1. Константы (`src/cg_elf.z`, сразу после `CG_STT_OBJECT`)**
— `CG_ET_REL`, `CG_SHT_*`, `CG_SHF_*`, `CG_SHN_UNDEF/ABS`,
`CG_STB_LOCAL`, `CG_STT_NOTYPE/SECTION/FILE`,
`CG_R_X86_64_PC32/PLT32/32S` (значения C++ перенесены буквально).

**2. Трамплины (`src/cg_elf.z`, после `cgEmitLinuxEntryPoint`)** —
`cgEmitKOEntry` (`codegen_ko.cpp:134`) и `cgEmitKOObjInit` (`:170`), плюс
хелперы `cgKoFoName(lit)` (скан `cgFoName[]`) и `cgFirstUserFuncName()`.
`cgEmitLinuxLibInit` уже был (портирован раньше, `:610`).

**3. `cgCollectExportEntries`** — `codegen.cpp:8675..8682`: порядок
declaration order не-extern функций, `rva = textRVA + funcOffsets[name]`.

**4. `cgBuildELFLib`** — `codegen_elf.cpp:1040..1345`, **побайтно совпал
с первого прогона**: phnum=3, нет `PT_INTERP`, `e_entry=0`, VAs
base-relative (без `LOAD_BASE`), `.dynstr` = NUL + sonames + импорты +
**export-имена** (дедуп `cgElStrOffFind`), `.dynsym` = null + UND-импорты
(`st_size=8`) + определённые экспорты (`st_shndx=1`), `.hash` по всем
dynsym с именем из imports, потом exports, `DT_INIT = textRVA +
cgEntryPointCodeOffset`, heap-snap по `dataRVA+dataSize+dynBlobSize`,
**`cgCheckFixupOverlaps()` не зовём** (C++ не зовёт), хвост магии =
`sizeof(kZenithMagic)` = **6** (`codegen.h:11`, `uint8_t[6]`).

**5. `cgBuildKO`** — `codegen_ko.cpp:207..682`: отбраковка
userspace-only билтинов → `cgApplyFixups(0)` → ро с дедупом
(перестройка `cgStringOffsets`) → modinfo → symtab (0 NULL, 1 `zenith.z`
FILE/ABS, 2/3/4 SECTION, user-функции в declaration order, `zenith_obj_init`
**или** `init_module`+`cleanup_module`, `_printk` + `und` + koNeeded) →
rela-массивы → сортировка по `r_offset` → strtab → shstrtab →
сериализация → layout → section headers.

Порядок symtab и состав koNeeded зеркалят C++: koNeeded собирается из
`cgKoExtCallSym[]` + `cgKoDataFixSym[]` (дедуп `cgLitEq`), стирается
`_printk`, `jiffies` запоминается отдельно, затем в **фиксированном
порядке** `__kmalloc_noprof`, `kfree`, `ktime_get_boot_fast_ns`; для
`--obj` дополнительно `malloc`, `free`; `jiffies` пушится последним;
остаток → `Error: kernel symbol '…' is referenced but not in the KO import
table.`

**6. Рефакторинг `cgGenerateWide`** — дословно по `codegen.cpp:8672..8831`:
ветки `lib → emitLinuxLibInit + exportEntries` / `koDriver → emitKOObjInit
или emitKOEntry` / обычный `emitLinuxEntryPoint + emitStartupRelocator`;
затем `fixupSectionRVAs()`, и **только потом** `if (koDriver) { buildKO();
return; }` — в KO-ветке `resolveFixups()/resolveJmpFixups()` НЕ зовутся, их
делает сам `buildKO`. В конце `libOutput ? cgBuildELFLib() : cgBuildELF()`.

**7. `cgFreshState`** — сброс `cgKoInit/Size`, `cgKoCleanup/Size`,
`cgKoSymN`, `cgKoRelaN`, `cgKoFirstGlobal`, `cgExportN`. **`cgLibOutput`,
`cgObjOutput`, `cgKoDriverFlag` не трогаем — это входы**, их выставляет
харнесс/заголовок `ZAST`.

### ИЗВЕСТНЫЕ ОТКЛОНЕНИЯ (зафиксировать, не «чинить»)

1. **Порядок `std::unordered_set<std::string>` в `--obj` не воспроизведён.**
   C++ собирает undefined-имена в `unordered_set` (`codegen_ko.cpp:365..373`);
   порядок итерации hash-зависимый (MurmurHash64A × бакеты × growth policy)
   — brute-force не сошёлся, воспроизводить не стоит. В `.z` — **порядок
   первого появления** (callFixups → funcRefFixups, дедуп содержимым).
   Контейнеры с ≥2 undefined extern-символами в `--obj` **не гоняются в
   тесте**: img4/img5 extern-функций не имеют вовсе. Одиночный extern даёт
   одиночный `und` (порядок определён), пустой — пустой.
2. **Shell-часть `buildKO` не портирована** (`codegen_ko.cpp:684..826`:
   modpost → gcc `.mod.c` → gcc `module-common.c` → `ld -r`). Обоснование:
   selfhost-кодоген не имеет I/O вообще (даже `.elf` — это `cgImg`), а
   `src/main.z` отдаёт итоговую сборку C++-бэкенду через `zffi_codegen`.
   Граница юнита: **в `cgImg` контейнер уже готов и побайтно верен**.
   То же для `--lib`: `buildELFLib` заканчивается `cgImg`, запись файла —
   задача драйвера.

### ГРАБЛИ

- **Сортировка вставками портила данные.** Первый вариант выглядел
  рабочим (`while b >= 0 … else b = -1; off[b+1] = kOff`), но ветка `else`
  записывала `kOff` в **index 0** и затирала отсортированную голову:
  5 relas → `[237,75,230,230,237]` вместо `[59,75,223,230,237]`
  (readelf показал структуру идентичной — расходились **только** `r_offset`
  первых relas). Фикс: `while b > 0 && moved == 1` + `off[b] = kOff`,
  `moved` вместо `break` (в `.z` `break` нет).
- **`.z` `print()` всегда пишет перевод строки**, в том числе по `int`;
  `print(n)` → строка `n`, а не склейка. Метки в тесте передаются как
  `string`-параметры: параметр, объявленный `int`, ловит литерал как
  указатель и печатает **адрес** (`4810069`), а не строку.
- **`kZenithMagic` — это `uint8_t[6]`** (`codegen.h:11`), а не
  NUL-строка: хвост `.so` = ровно 6 байт `"Zenith"`, как в `cgBuildELF`.
- **`--obj` возвращает ДО проверки дерева ядра** (`codegen_ko.cpp:669`),
  driver-режим — после (`:695`). Поэтому img4 не требует linux-headers,
  а img5 требует.
- `fs::temp_directory_path()` = `$TMPDIR`; `cgimg_check.py` явно ставит
  `TMPDIR=/tmp` и чистит `/tmp/zenith_ko_1` перед прогоном, чтобы не
  подхватить протухший `.o`.
- Разбор вывода драйвера: в `.z` ключ печатается **тремя** `print`
  (`"P"`, `k`, `"="`), поэтому `tools/ko_diff.py` парсит токены, а не
  строки. Префиксные FNV-хеши обратимы (`b = (h_k * p^-1) ^ h_{k-1}`) —
  по ним восстанавливаются все байты кроме последнего.

### Инструменты, оставшиеся в дереве

- `src/_cgdbg.z` + `tools/ko_diff.py` — печатают префиксный FNV-64 для
  каждой позиции `cgImg` и по нему **восстанавливают байты**; сравнение с
  эталоном находит **первый отличающийся байт**. Пользоваться при любом
  будущем расхождении `.o`/`.ko`, руками байты не искать.
- `tools/cgimg_check.py` — 5 контейнеров, `ref_container(i, …)` →
  **с части 11 шесть** (см. ниже).

### Тест

- `python3 tools/cgimg_check.py` → 5/5 OK.
- `timeout 1800 make -f Makefile.linux test` → **`MAKE_RC=0`,
  20 групп / 198 функций байт-в-байт, 0 MISMATCH**, 15 `front-end … match`,
  `codegen-smoke OK`, `codegen-image OK`.

---
## 05.10 (часть 11) — `tryLinuxNetCall` ЗАКРЫТ: сеть в selfhost

### Что портировано

**1. `detectNetSock*` → `src/cg_elf.z`** (эталон `codegen_net.cpp:36..99`):

- `cgDetectNetSockExpr(id)` — только Call/Binary/Member/ArrayAccess,
  **Unary пропускается** (в C++ та же асимметрия);
- `cgDetectNetSockBlock(st, len)`;
- `cgDetectNetSockStmt(id)` — Return/ExprStmt/Assign(f3,f4)/VarDecl(f7)/
  If/While/Loop/Switch(cond f0, caseList f1/f2, запись в side = `[cond,
  bodyStart, bodyLen]`, stride 3 через `cgSide`)/For(f1,f2,f3 + block f4,f5);
- `cgDetectNetSockUsage()` — обходит и глобалы (f7 init), и функции; extern
  (`N_FUNC && f11 != 0`) пропускает.
- Вызов в `cgGenerateWide` — **перед** `cgDetectVkUsage()`,
  `cgDetectVkSurfaceUsage()` и `cgBuildLinuxImportData()` (порядок как в
  `codegen.cpp:8645..8656`). Комментарий над вызовом обновлён.
- `cgFreshState()`: добавлен **`cgNetSocksUsed = 0`** — это **выход**
  детекта, а не вход харнесса: свежий объект в C++ даёт `false`, а после
  прошлого вызова он оставался бы `true` и `cgBuildLinuxImportData` отложил
  бы четыре слота `.data` под чужую программу.

**2. `cgTryLinuxNetCall` + хелперы → конец `src/cg_expr.z`**
(эталон `codegen_net_linux.cpp:31..569`):

`cgNetSvc` (`B8 imm32; 0F 05`), `cgNetStoreErr`, `cgNetHostBuild`,
`cgNetStorePortAddr`, `cgNetStoreListenAddr`, `cgNetOctet`, `cgNetFinish`,
**`cgNetFinishRestoreR11`** и сама `cgTryLinuxNetCall(c) -> int`.

Всё переиспользует вынесенные ранее из Vulkan-порта **общие** хелперы:
`cgVkLeaRip(r, rva)` (= C++ `leaRip`, пушит `cgPushGlobalFix`), `cgVkGuard(r)`
(= `guard`), `cgVkMovToR12(r)` (= `movToR12`), `cgVkSetNeg1()` (= `48 C7 C0
FFFFFFFF`). Пролог ровно `57 56 41 54` **без** `sub rsp,8` (в отличие от
Vulkan), эпилог — ровно три `pop`.

Диспетчер `cgEmitCallBody` (`src/cg_expr.z` ~7170): ветка
`if cgTryLinuxNetCall(c) == 1 → return cgLinResReg` стоит **после**
`cgTryLinuxVulkanCall`. `tryLinuxVkSurfaceCall` в C++ — заглушка
`return false` (`codegen_wl_wsi.cpp:19`), `cgTryLinuxGUICall` — тоже
заглушка (`src/cg_expr.z:10307`), поэтому пропуск этих двух прозрачен.

Слоты `.data` (`cgSockPeerRVA`, `cgSockPeerLenRVA`, `cgLinNetErrRVA`,
`cgLinNetIpBufRVA`), их `+dData` в `cgFixupSectionRVAs` и цикл фикстур
4b — в `.z` уже были с прошлых юнитов; ничего не понадобилось добавлять.
`fixupSectionRVAs()` намеренно **не** двигает `linNetErrRVA`/`linNetIpBufRVA`
— это C++-баг, зеркалим (фикс-массив `cgGlobalFixRva` правится отдельным
циклом 4b).

### ПОЙМАННАЯ ОШИБКА ПОРТА: пропущенный `mov rax, r11`

В C++ `net_tcp_send`/`net_tcp_recv`/`net_udp_recv` после четырёх `pop`
делают **`4C 89 D8`** (`mov rax, r11`) и уже потом `jmp` на общий выход.
Я этот байт пропустил. Фикс — `cgNetFinishRestoreR11(netExit)`
(`41 5C 5E 5F 4C 89 D8 E9 rel32`).
В `net_udp_send` этой инструкции **нет и в C++** — дословно зеркалим
(эталонный баг), тест `n8` этого и требует.

### ГРАБЛЬ ГЛАВНАЯ: липкий `gKoDriver` в selfhost-парсере

`src/_cgimg.z` расширен шестым источником `srcF` (`app linux` + все
`net_*`), `tools/cgimg_check.py` — до шести контейнеров. Первый прогон:
`img6 MISMATCH: selfhost=(5456, 280295329708355966) ref=(12790,
-2543921928130337230)`.

Бисекция предшественников: img6 в одиночке OK, после img1..img4 OK,
**после img5 (`mode 3`, `app linux driver`) — всегда BAD.**
Восстановление байтов префиксным FNV (`src/_cgdbg6.z`, по образцу
`src/_cgdbg.z` + `tools/ko_diff.py`): первое расхождение — **байт 16,
`e_type`**: self `01 00` = ET_REL, ref `02 00` = ET_EXEC; у self `e_phoff=0`,
`e_shoff≈0x12d0` → сработала ветка `if cgKoDriver() != 0 → cgBuildKO();
return` в `cgGenerateWide`.

**Корневая причина:** в C++ `Parser::parse()` делает свежий `Program prog;`
(`src/parser.cpp:2362`) на **каждый** вызов — дефолты из `ast.h:274..310`.
В `selfhost/parser.z` конфигурационные глобалы, которые парсер только
**выставляет** (`gKoDriver`, `gKernelExplicit`, `gBootManual`, `gReal16`,
`gLedLow`), **не сбрасывались в `parseRun`** (там сбрасывались только
`gPos/gNTok/gDepth/gPErr/gPFatal/gErrLineOut` + `azReset()` + `gMcu/gLedPin/
gArm64Chip`). После `app linux driver` липкий `gKoDriver == 1` уезжал в
`gH[H_FLAGS] |= 1` (`CGF_KODRIVER`), `cgKoDriver()` читал бит уже у **нового**
блоба — и `srcF` собирался как модуль ядра.

**Фикс:** `resetProgConfig()` в начале `parseRun` (`selfhost/parser.z`) —
24 присваивания, дословно дефолты `Program` из `ast.h`
(`gAppType/gAppCategory/gRenderType/gKernelMode`, все пять липких флагов,
`gAsmWord=64`, `gSysclk=72000000`, `gSystick/gSramKb=0`,
`gArm64Clock=1000000000`, `gAndroidApi=30`, `gAndroidMin=21`,
строковые id модулей/меток в 0).

### ГРАБЛЬ: новая функция в `.z` ломает golden-дампы

После добавления `resetProgConfig` упал `test-front`: golden ждал
`func parseRun @6878` там, где уже шёл `func resetProgConfig`. Дампы
`selfhost/golden/*.dump` — это вывод **C++**-фронтенда
(`make golden` → `pardump src/parser.cpp`), то есть авторитет, и их
переfreeze — это ровно тот случай, ради которого цель написана.
`make golden && make test` → снова `MAKE_RC=0`.

### Тест

- `python3 tools/cgemit_check.py tools/cgemit/net_linux1_b.z` → **14/14
  functions byte-identical**; с `-b` → **15/15** (включая whole-TU
  `_text len=2546`).
- `python3 tools/cgimg_check.py` → **6/6 OK**, img6 `len=12790
  h=-2543921928130337230` (единственный контейнер с `cgNetSocksUsed=1`,
  четырьмя слотами `.data` и disp32 в lea-фикстурах).
- `timeout 1800 make -f Makefile.linux test` → **`MAKE_RC=0`,
  0 MISMATCH**, 15 `front-end … match`, `codegen-smoke OK`,
  `codegen-image OK`.

---
## 05.10 (часть 12) — `codegen_httpdl.cpp` ЗАКРЫТ: HTTP-download-блоб

### Что портировано

Эталон — `src/codegen_httpdl.cpp` (277 строк) + байты из
`src/httpdl_blob.h` (`kHttpdlBlob[]`, 477784 байт, `HTTPDL_BLOB_ENTRY
0x8330`).

**1. Байты блоба → `src/cg_httpdl_blob.z` (новый модуль).**

В `.z` нет бинарных массивов, только строковые литералы, поэтому байты
выложены восемью кусками по 65536 (7×65536 + 19032):

```
tools/gen_httpdl_blob_z.py  →  src/cg_httpdl_blob.z   (DO NOT EDIT)
```

- экранирование ровно то, что умеет `lxScanString`
  (`selfhost/lexer.z:744..812`): `\n \t \r \\ \" \0`; 0x0A/0x0D обязательны
  — сырым переводом строки инструкция растянулась бы на несколько строк и
  `preprocessIncludes` (строчный `std::getline`) увидел бы внутри литерала
  похожие на директиву строки. Байты ≥0x80 кладутся сырыми, файл пишется
  в бинарном режиме;
- длина передаётся **явно** (`cgHttpDlPutChunk(s, n)`) — в blob'е полно
  NUL'ов, `strLen()` остановился бы на первом;
- round-trip проверен: раскодированные литералы == `kHttpdlBlob` байт-в-байт.

Модуль содержит `CG_HTTPDL_BLOB_ENTRY`, состояние
`cgHttpDlBlobEmitted`/`cgHttpDlEntryLabel`, `cgHttpDlPutChunk`,
`cgHttpDlEmitBlobBytes`, `cgEmitHttpDlBlob`. `use cg_httpdl_blob` добавлен
в `src/cg_expr.z` **сразу после** `use cg_type` (цепочка в комментарии
шапки обновлён), `cgHttpDlUsed` остался в `src/cg_emit.z` рядом с
`cgTlsUsed`/`cgJsUsed`.

**2. Детект → `src/cg_expr.z`** (эталон `codegen_httpdl.cpp:29..102`):
`cgIsHttpDlName` (11 имён), `cgDetectHttpDlExprUsage`
(Call/Binary/Member/ArrayAccess, у Call — ранний `return`),
`cgDetectHttpDlBlock`, `cgDetectHttpDlStmt` (Return/ExprStmt/Assign f3,f4/
VarDecl f7/If f0+(f1,f2)+(f3,f4)/While/Loop/Switch stride 3/For f1,f2,f3),
`cgDetectHttpDlUsage` (функции с `f11==0`, потом глобалы f7).
Вызов в `cgGenerateWide` — **между** `cgDetectNetSockUsage()` и
`cgDetectVkUsage()` (порядок `codegen.cpp:8645..8656`).

**3. `cgEmitHttpDlBlob()`** — guard `cgHttpDlUsed != 0 && cgLibOutput == 0`,
вставка **сразу перед `cgFixupSectionRVAs()`** (`codegen.cpp:8723..8744`):
NOP-pad до 16 (`while cgCodeLen % 16 != 0 → emit8(0x90)`), запоминается
`blobStart`, эмитятся байты, `cgLabelPos[cgHttpDlEntryLabel] = blobStart +
0x8330`. `cgFreshState()` получает сбросы `cgHttpDlUsed`,
`cgHttpDlBlobEmitted`, `cgHttpDlEntryLabel = -1`.

**4. `cgTryHttpDlCall(c) -> int` → конец `src/cg_expr.z`**
(эталон `:125..277`), хелперы `cgHttpDlGuard` (= lambda `guard`),
`cgHttpDlEmitRx` (= lambda `emitRx`), `cgHttpDlBlobReg` (= `kBlobRegs`).
Карта имён: op1..op7 очевидны, `_winpe`→op8 `winPe=1`,
`_winpe_media`→op9, `iso_extract`/`http_download_iso`→op8 `winPe=0`.
Arity-guard'ы дословно: op4 `1..3`, op5 `==4`, op6 `==5`, op7/(op8&&winPe)/op9
`1..2`, op8 `2..3`, остальные `==2`. Порядок: guard'ы → `if entryLabel<0 →
newLabel()` → `httpDlUsed = true` → `saved = regsUsed; spillRegs();
regsUsed = 0` → ветки → `48 C7 C7 imm32(op)` → `E8` + `cgFixPush(cgCodeLen,
entryLabel)` + `emit32(0)` → `emitJmp(done)` → `emitLabel(done)` →
`emitJmp(exitLabel)` → `emitLabel(exitLabel)` → общий выход-шаблон
(`regsUsed=0; freeReg(1..3); r=allocReg(); …`).

Ветка в диспетчере `cgEmitCallBody` — **сразу после `cgTryLinuxNetCall`**
(`codegen.cpp:5524`), внутри `if cgIsLinux == 1` (`appType == Linux`).

**5. Bulk-эмиттер `cgCodeAppend(p, n)`** в `src/cg_emit.z` — один
`cgEnsure` вместо 477784 штук (вместо по-байтового `emit8`-цикла).

### ГРАБЛЬ №1: капы строковых буферов

Один чанк = 65536 байт, а `lxScanString` требует `w + 2 <= STR_CAP -
gStrUsed`. Поднято:

- `selfhost/lexer.z` `STR_CAP` **262144 → 4194304**;
- `selfhost/ast.z` `STR_CAP_AST` **2097152 → 4194304**.

Почему 4 МиБ, а не больше: лексер/парсер одним `lexInit`/`azReset`
сплитают **весь** spliced-исходник одной программы, а до blob'а во всех
`.z` было ≈37 КиБ литералов (самый большой — 64 КиБ в `cg_httpdl_blob.z`).
4 МиБ = 478 КиБ blob'а + ~20x запас. Важно: `$(BIN)` = `build/linux/zenith`
ссылается **PARSEROBJ** (selfhost-парсер), то есть эти капы на критическом
пути каждой компиляции; бутстрапы `tools/{lex,parse}obj.o` со старыми
капами парсят только `selfhost/*.z` — им хватает. Для чисто-selfhost
бинарора лимит остаётся 64 МиБ heap.

**NUL внутри литерала живёт весь путь** (проверено, до порта вызывало
сомнения): лексер пишет `slen = w` (полная длина), парсер `tokStr` =
`azStr(lexTextPtrAt, lexTextLenAt)` — по длине токена, а не по `strLen`;
C++-эталон `t.text.assign(p, tl)` → `std::string` →
`for (char c : s) rdata.push_back(c)`. `azStrLit`/`strLen` применяются
только к идентификаторам. Дедуп пула (`cgStrIdsEq`) тоже length-aware.

### ГРАБЛЬ №2: `test-front` падает после правки константы в `selfhost/*.z`

Тот же сценарий, что и в «части 11» с новой функцией: golden-дампы —
вывод **C++**-фронтенда, он видит `global STR_CAP: int = (num 4194304)`
там, где в дампе ждался `262144` (6 файлов). `make golden && make test`
→ `MAKE_RC=0`. Заметь: `selfhost/ast.z` C++-фронтенд **отклоняет** и в
golden не попадает — его правки (`STR_CAP_AST`) тест не видит вообще.

### Тест: img7, cgemit НЕ применяется

- **`src/_cgimg.z`** — седьмой источник `srcG` (`app linux`, все op1..op9 и
  все arity-ветки `http_server`/`_msiso`/`_winpe`/`_winpe_media`/
  `iso_extract`, плюс detect-обход VarDecl/Assign/If/While/For/Return),
  `emit(..., srcG, 0)`; **`tools/cgimg_check.py`** — `SRC_NAMES` += `srcG`,
  `range(1,8)`, `ref_container` для `i == 7` → plain ELF (вместе с 1,2,6).
- `python3 tools/cgimg_check.py` → **7/7 OK**, img7 `len=491550
  h=-3185870257842899445` — единственный контейнер с `cgHttpDlUsed=1`,
  RWX `p_flags` и rel32 в точку входа блоба.
- **cgemit-тест для httpdl не делаем.** Режим A (per-function) вешается:
  `E8 rel32` патчится через `cgFixPos`, а `pbMask`/`pbMaskWhole` маскируют
  только `cgCallFixPos`/`cgFuncRefPos`/`cgGlobalFixPos`/`cgStrFixPos`/
  `cgKoStrFixPos`/`cgElfImpPos`/`cgImpCallPos`/`cgHeapFixPos`/`cgNetFixPos`
  — **`cgFixPos` не входит в маску**, а `cgLabelPos[entryLabel]` в
  per-function харнессе не выставлен (blob не эмитится) → disp32 ≠ эталона.
  Режим B (whole-TU) тоже непригоден: если добавить эмиссию блоба, `cgCode`
  ≈ 481 КиБ → hex-строка ≈ 962 КиБ, а `pbLit/pbN` режет `lxBAppend(gPBuf,
  gPPLen, 16384, …)` (`selfhost/parser.z:86..96`), а `pbHexBytes` пишет
  `2*n` символов в `gTmp = alloc(8192)` (`src/_cgemit.z`) — переполнение.
  Сильнее img7 ничего не покрывает: FNV-64 всего образа ловит и сами байты
  блоба, и все rel32, и флаги, и раскладку.

### Тест (полный)

- `python3 tools/cgimg_check.py` → **7/7 OK**.
- `timeout 1800 make -f Makefile.linux test` → **`MAKE_RC=0`,
  0 MISMATCH**, 15 `front-end … match`, `codegen-smoke OK`,
  `codegen-image OK`.

### Следующий шаг

`tryLinuxWLCall` → `tryShaderCall` → семейство `detect*Usage` → потом
директива «только syscall».

---
## 05.10 (часть 13) — `codegen_wl_linux.cpp` ЗАКРЫТ: Wayland-сокет в selfhost

### Что портировано

Эталон — `src/codegen_wl_linux.cpp` (443 строки, `detectWL*` + `tryLinuxWLCall`).

**1. Детект → конец `src/cg_expr.z`**: `cgDetectWLExpr`, `cgDetectWLBlock`,
`cgDetectWLStmt`, `cgDetectWLUsage`. Три отличия от `detectNetSock*`/
`detectHttpDl*`, зеркалим дословно:

- **Unary обходится** (`un->operand`), и поле у него — **`f1`**, а не `f0`
  (`f0` = id оператора). Это важнее, чем кажется: `cgDetectWLUsage` ходит по
  телам **всех** программ, и рекурсия в `cgF(e,0)` на строковом id дала бы
  `cgTag()` по мусору;
- **нет Assign и Switch** (в net/httpdl они есть);
- имя проверяется **префиксом** `wl_` (`cgStrHasPrefix`), а не списком имён.

Вызов в `cgGenerateWide` — **между `cgDetectVkUsage()` и
`cgDetectVkSurfaceUsage()`** (`codegen.cpp:8653..8656`). `cgFreshState()`
получает `cgWlUsed = 0` (раньше флаг вообще нигде не сбрасывался и никогда
не выставлялся — пустой хвост).

**2. `cgTryLinuxWLCall(c) -> int` + хелперы → конец `src/cg_expr.z`**:
`cgWlLeave(label)` (pop r14/r13/r12/rsi/rdi + `add rsp,8` + jmp) и
`cgWlDecWrite()` (инлайновый decimal-принтер в stdout через `div r9d`).
`leaRip` = уже существующий `cgVkLeaRip`, `svc` = уже существующий
`cgNetSvc`. Пролог `48 83 EC 08 / 57 / 56 / 41 54 / 41 55 / 41 56`, эпилог
— `wlExit` с общим выходом-шаблоном. Три ветки (`wl_open`, `wl_close`,
`wl_list_globals`) перенесены байт-в-байт; сырые `0F 82`/`0F 8E rel32`
(т.е. `jb`/`jle`, которых нет в таблице `emitJccLit`) идут через
`emit8` + `cgFixPush`, как в C++.

**3. Диспетчер** `cgEmitCallBody`: ветка `cgTryLinuxWLCall` — **сразу после
`cgTryHttpDlCall`** (`codegen.cpp:5526`).

Ветки `.rdata`/`.data` под `cgWlUsed` (`cgBuildLinuxImportData`), запись
`envp` в слот на старте (`emitLinuxEntryPoint`) и reject в `cgBuildKO`
уже лежали в `src/cg_elf.z` с прошлых юнитов — ничего добавлять не
понадобилось.

### ГРАБЛЬ: шесть оконных билтинов НЕ портированы

`wl_create_window`, `wl_present`, `wl_process`, `wl_close_window`,
`wl_fb`, `wl_pixel` в C++ уходят в `tryLinuxWLWindowCall`
(`codegen_wl_window.cpp`, **773 строки** — отдельный юнит). В `.z` эта
ветка пока не написана: имена не входят в `isWLBuiltin`, функция
возвращает 0 и билтин падает в общий «backend builtin dispatch is not
ported» — ровно как до юнита. Порядок в C++ (окно **до** `isWLBuiltin`)
делает пропуск прозрачным: поведение для `wl_open`/`wl_list_globals`/
`wl_close` не меняется. `detectWLUsage` при этом уже поднимает `cgWlUsed`
для оконных имён (префикс `wl_`) — раскладка `.data` от этого не зависит
(слоты выделяет `cgWlUsed`, а не конкретный билтин).

### Тест: img8

`src/_cgimg.z` — восьмой источник `srcH` (`wl_open` / `wl_list_globals` /
`wl_close`, плюс унарный минус, чтобы прогнать обход `N_UNARY` в детекте);
`tools/cgimg_check.py` — `SRC_NAMES` += `srcH`, `range(1,9)`, `i == 8` →
plain ELF.

- `python3 tools/cgimg_check.py` → **8/8 OK**, img8 `len=16914
  h=-1404876951840641508` — единственный контейнер с `cgWlUsed=1`.
- `timeout 1800 make -f Makefile.linux test` → **`MAKE_RC=0`,
  0 MISMATCH**, 15 `front-end … match`, `codegen-smoke OK`,
  `codegen-image OK`.

### Следующий шаг

`tryShaderCall` + `detectShaderUsage` (`codegen_shader.cpp`, 179 строк) →
`codegen_wl_window.cpp` (773) → семейство остальных `detect*Usage`.

---
## 05.10 (часть 14) — `codegen_shader.cpp` + `spvasm.cpp` ЗАКРЫТЫ: SPIR-V

### Что портировано

Эталон — `src/codegen_shader.cpp` (179 строк: `detectShaderUsage:29`,
`registerShaderCall:95`, `tryShaderCall:118`, `emitShaderModules:160`) и
`src/spvasm.cpp` (353 строки: `tokenize:171`, `parseString:192`,
`pushLiteral:213`, `assemble:250`, `enum Opcode:64`).

**1. Таблицы → `src/cg_spvtab.z` (710 строк), генератор `tools/gen_spvtab_z.py`
(177 строк).** Таблицы читаются из C++-исходника (`enum Opcode` из
`spvasm.h`, `kOps`/`kEnums`/`kResultFirst` из `spvasm.cpp`), а не пишутся
руками, чтобы номера не разъехались. На выходе: **83 опкода, 124 енума,
15 result-first**. Четыре функции:

- `cgSliceEqLit(p, n, lit)` — сравнение байтов с NUL-литералом;
- `cgSpvOpCode(p, n)` — имя опкода → номер;
- `cgSpvEnumVal(p, n)` — имя енума → u32. **Порядок обязателен:** цепочка
  идёт сверху вниз и `Uniform` всплывает **2**, а не 26 (поздние определили
  бы ранние);
- `cgSpvResultFirst(opcode)` — нужна ли перестановка результата.

**2. `src/cg_shader.z` (888 строк) — новый модуль-лист, `use cg_spvtab`.**
Содержит весь остальной порт:

- **лимиты вместо `std::vector`** — 4096 строк / 512 токенов / 4096 id /
  4096 operands / 16384 слов / 8192 байта strbuf / 64 рекорда. Жёстко
  захардкожены литералами в типах: **константы размера массива в `.z` не
  читаются**, а `sizeof`-аналогов нет;
- **ассемблер**: `cgSpvSplitLines`/`cgSpvPushLine`, `cgSpvTokenize`/`cgSpvTokFlush`,
  `cgSpvPass1Line` (id-map, bound), `cgSpvPass2Line` (эмиссия), `cgSpvAssemble`;
  `cgSpvParseString` (эвейпинг `\n \\ \" \r \t`, иначе отдаёт сам символ),
  `cgSpvParseHex` (`strtoul` без проверки хвоста), `cgSpvParseDec`
  (цифр==0 **или** `i != n` → ошибка — зеркалит `strtoll` + `t.empty()`);
  sink 0=words / 1=operands; `cgSpvEmit`;
- **ошибки**: `cgSpvErr*` буферы + `cgSpvRaise()` (префикс
  `"SPIR-V assembly failed: "`), `cgSpvAsmErr`;
- **детект**: `cgDetectShaderExpr`/`cgDetectShaderBlock`/`cgDetectShaderStmt`
  (Call/Binary/Member/ArrayAccess/**Unary через f1**; Return/ExprStmt/VarDecl
  f7/If/While/Loop/For; **Assign и Switch отсутствуют**), `cgDetectShaderUsage`;
- **`cgRegisterShaderCall`**, **`cgEmitShaderModules`**, **`cgTryShaderCall`**.

**3. Диспетчер** `cgEmitCallBody`: ветка `cgTryShaderCall` — **сразу после
`cgTryLinuxWLCall`** (`codegen.cpp:5528`), результат `return cgLinResReg`.

**4. `cgGenerateWide`** (`src/cg_elf.z`): `cgDetectShaderUsage()` вызывается
**между `cgDetectWLUsage()` и `cgDetectVkSurfaceUsage()`**
(`codegen.cpp:8645..8656`: network, netSock, sound, tls, httpDl, js, disasm,
vk, wl, **shader**, vkSurface). `cgFreshState()` получает `cgShaderUsed = 0`
и `cgShN = 0`.

**5. Убран стаб** `func cgEmitShaderModules() end` из `src/cg_elf.z` —
реализация теперь лежит в `cg_shader.z`, стаб дал бы «Duplicate function»
(`selfhost/parser.z:3258`).

**6. lea** в `cgTryShaderCall` — через уже существующий `cgVkLeaRip`
(`src/cg_expr.z:1036`), он байт-в-байт равен C++ `lea r,[rip+disp32]`.

### ПОЙМАННАЯ ОШИБКА ПОРТА: узел вместо strId

`cgCallArg(c, i)` возвращает **ZAST-узел**, а не строковый id. Первый
вариант складывал в `cgShKey[]`/`cgShText[]`/`cgShKind[]` сам узел и лез в
`cgStrLen()` по мусору → длина из чужой памяти → **SIGSEGV** в
`cgSpvSplitLines` (`movzbl (base+i)`, вылет за пределы RW-сегмента).

Для `N_STRING` strId лежит в **`f0`** — как уже делает `Create:File`
(`src/cg_expr.z:4559`, `cgStrPtr(cgF(cfA0, 0))`). Починка: `cgF(textE, 0)` /
`cgF(kindE, 0)` в трёх местах (dedup, запись, поиск в `cgTryShaderCall`) и
`cgErrAppendStrId(cgF(textE, 0))` в ошибке `shader_file`.

### Решения и отклонения от C++

- **`detectShaderUsage` выходит ПОСЛЕ ФУНКЦИИ**, в которой нашёлся первый
  shader-вызов (`if (shaderUsed) return;` в конце каждой итерации) — билтины
  второй функции в рекорды **не** попадают. Копировать буквально. В `.z`
  добавлен выход и по `cgHasErr()`.
- **`shader_file` НЕ читает файлы**: `zffi_readFile` живёт только в
  `src/main.z`, харнесс `_cgimg`/`_cgtest` его не линкует →
  `cgErrSet("shader_file: cannot open '")` + путь + `'"'` (в репо нет ни
  одного `*.spvasm`, у C++ там тоже всегда `ifstream`-падение).
- **`cgTryShaderCall` — БЕЗ общего выходного шаблона**: C++ не трогает
  `regsUsed`, кладёт `cgLinResReg = r` как есть (может быть **-1**).
  Отличие от Vulkan/Net/HttpDl/WL — намеренное.
- **Рекорды**: дедуп по паре `(key, kind)` через `cgStrIdsEq` (байтовое
  сравнение — azStr не interning'ит), `key == text` для `shader()`. `lea`
  всегда целят в **первую** запись с данным key (как в C++).
- Ошибки `shader module RVA not assigned (build order bug)` и
  `shader text was not registered by the pre-scan (internal error)` →
  `cgLinResReg = 0; return 1`.
- `emitShaderModules` вызывается **последним** в `cgBuildLinuxImportData`,
  **до** `cgFixupSectionRVAs()` (он доштучивает `cgGlobalFixRva[]`).

### ГРАБЛИ

- **`use`-цепочка кодогена обязана оставаться ЛИНЕЙНОЙ**: `parseRun` не
  дедуплицирует spliced-модули, ромб даёт «Duplicate function»
  (`selfhost/parser.z:3258`). Поэтому `cg_shader.z` — **лист** (как
  `cg_httpdl_blob.z`), а не «`use` того же модуля из двух мест».
- **Числа в `.z` — только hex**, как в C++ (`0x07230203` и т.п.).
- **В `.z` нет `break`/`continue`** — флаги и `&& stop == 0` в условиях.
- 3 предупреждения `ZT-BUG` в `_cgimg`/`_cgtest` (`k >= 0`, `condition
  always true`, `op <= 9`) — **пресуществующие**, из `src/cg_emit.z:1918` /
  `cg_type.z:688,848` / `cg_expr.z:11962`; вставка новых модулей их только
  сдвигает (+1599 строк в `_cgtest`).
- Счётчик `Bug check: N potential bug(s)` **плавает не по нашей вине**:
  его меняет другой агент в `src/bugfind.cpp` (между прогонами было 11 → 3).

### Тест: img9

`src/_cgimg.z` — девятый источник `srcI`: `app linux`, четыре вызова
`shader()` — `vertex`+T1, `fragment`+T2, **повтор** `vertex`+T1 (дедуп),
`compute`+T1 (тот же key, другой kind → вторая запись, но lea целят в
первую) — плюс унарный минус, `if`, `while`, `for`, чтобы прогнать обход
всех веток детекта. T1 — реальный SPIR-V-модуль: `OpEntryPoint` c
`"main"` (экранирование наружу), `OpTypeInt 32, 0` через **запятую**,
hex-литерал `0x00000001`, **отрицательный** `-1`, комментарий `#`.

Экранирование наружу (`zesc` в генераторе фикстуры): реальный перевод
строки → `\n`, обратный слэш → `\\`, кавычка → `\"`. **Round-trip
обязателен** — иначе в `_cgimg.z` попадает синтаксически сломанный литал.

`tools/cgimg_check.py` — `SRC_NAMES` += `srcI`, `range(1,10)`, `i == 9` →
plain ELF, блок img9 в докстринге.

- `python3 tools/cgimg_check.py` → **9/9 OK**, img9 `len=12318
  h=-1251378926652827548` — единственный контейнер с SPIR-V в `.rdata`.
- `timeout 2400 make -f Makefile.linux test` → **`MAKE_RC=0`,
  0 MISMATCH**, 15 `front-end … match`, `codegen-smoke OK`,
  `codegen-image OK` (img1..img9).

### Следующий шаг

`codegen_wl_window.cpp` (773) → семейство остальных `detect*Usage`
(network/sound/tls/js/disasm) → **директива «только syscall»** → порт
оптимизаций, make-подобный язык в `main.cpp`, слой 2 с WinPE.

---
## 05.10 (часть 15) — `codegen_wl_window.cpp` ЗАКРЫТ: окно и shm-фреймбуфер

### Что портировано

Эталон — `src/codegen_wl_window.cpp` (**773 строки**, одна функция
`tryLinuxWLWindowCall:61`). Самая «железная» часть Wayland: рукописный
wire-протокол, `sendmsg`+SCM_RIGHTS, `memfd_create`/`ftruncate`/`mmap`.

**1. Хелперы-лямбды C++ → отдельные функции `cgWw*` в конце `src/cg_expr.z`**
(в `.z` лямбд нет):

| C++ (лямбда) | `.z` |
|---|---|
| `out32/off/outHeader` (`:111..123`) | `cgWwOut32`, `cgWwOutReg32`, `cgWwOutHeader` |
| `writeOut/writeLen/writeOutCheck` (`:126..144`) | `cgWwWriteOut`, `cgWwWriteLen`, `cgWwWriteOutCheck` |
| `writeOutFd` (`:148..193`, 96 байт msghdr+iov+cmsg, `svc(46)`) | `cgWwWriteOutFd` |
| `leaEvent` (`:196`) | `cgWwLeaEvent` |
| `movToR12/R13/R14` (`:201..203`) | `cgWwMovToR12/R13/R14` |

Переиспользованы из портированного ранее: `cgVkLeaRip` (=`leaRip`),
`cgNetSvc` (=`svc`), `cgWlLeave` (=`wlLeave`).

**2. `cgTryLinuxWLWindowCall(c) -> int` → конец `src/cg_expr.z`** (под
`cgTryLinuxWLCall`). Шесть веток (`wl_create_window`, `wl_present`,
`wl_process`, `wl_close_window`, `wl_fb`, `wl_pixel`) перенесены
**механически**: конвертер `/tmp/opencode/conv_ww.py` выдавал тело построчно
(`emit8`/`emit32` → по одному на строку, `leaRip`→`cgVkLeaRip`, `svc`→
`cgNetSvc`, `emitJcc`→`emitJccLit`, `wlXxxRVA`→`cgWlXxxRVA`,
`int x = newLabel()`→`var x: int = newLabel()`, `}`→`end`), шапка/лямбды/
общий выход писались руками. **Проверка — тест img10, а не чтение**: такая
транскрипция правится только байтовым паритетом.

**3. Диспетчер**: в C++ окно вызывается **изнутри `tryLinuxWLCall`**
(`codegen_wl_linux.cpp:110..113`), ДО `isWLBuiltin`. Ровно то же в
`cgTryLinuxWLCall` (`src/cg_expr.z`): шесть имён → `return
cgTryLinuxWLWindowCall(c)`; при несовпадении аргументов окно возвращает 0 и
билтин уходит дальше по диспетчеру (`tryShaderCall` → «не портирован»).

**4. Раскладка `.data`/`.rdata` не менялась**: все 17 слотов окна
(`cgWlWNameRVA`…`cgWlOutRVA`) и строки (`wl_compositor`, `xdg_wm_base`,
`wl_shm`, `z-wl-fb`, `zenith-app`) лежали в `cg_elf.z` с прошлых юнитов —
`cgWlUsed` раскручивает весь блок целиком, независимо от того, какой именно
`wl_*`-билтин увидел детект.

### КАК НАСТУПИЛ НА ГРАБЛЬ: референс живой (другой агент правит `src/*.cpp`)

Замеры **перестали сходиться**, причём одинаково для img1..img9 (длины
совпадали, хеши — нет). Виноват не мой порт: в **20:36** другой агент
дописал в `src/codegen_elf.cpp` две правки и пересобрал
`build/linux/zenith`:

1. **Re-space `.data`** от реального размера `.rdata` до странички —
   в `.z` уже был (порт раньше, коммент `(:150..160)`);
2. **`argc/argv` в `_start`**: `mov rdi,[rsp]` + `lea rsi,[rsp+8]` перед
   `call main` (+12 байт) — **в `.z` отсутствовал**.

**Как искать, а не гадать** (алгоритм на будущее):

- длина совпала, хеши нет ⇒ разница **не в размерах**, а в байтах; и
  выравнивание `.text` так маскирует +12 байт, что длины равны — поэтому
  сравнивать по длине **бессмысленно**;
- `git diff src/*.cpp` показывает сразу два хака, но не говорит, в каком
  они состоянии собранный бинарь → нужны **байты**;
- байтовый дамп selfhost без файлового I/O: временный `src/_cgdiag.z`
  (копия `_cgimg.z` с `pbInit/pbLit/pbNum/pbFlush` + `pbHexBytes` из
  шаблона `tools/cgemit_check.py`) печатает `@offset:hex` по 64 байта;
  Python сравнивает с эталонным `.elf`. **Первое расхождение: 0x119c**,
  дальше только сдвиг релативных адресов ⇒ единственная причина = 12
  байт в `_start`;
- фикс: 9 `emit8` в `cgEmitLinuxEntryPoint` сразу после
  `cgEmitMixCrt0Call()`; `_cgdiag.z` удалён.

**Вывод для следующих юнитов: после любой правки `src/*.cpp` другим агентом
`make test` станет красным не по нашей вине. Портировать их правку в `.z`
(это же и есть паритет), а не «чинить» тест.**

### Тест: img10

`src/_cgimg.z` — десятый источник `srcJ`: `wl_open`,
`wl_create_window(640,480,"zenith")`, `wl_pixel(1,2,0xFF00FF00)`,
`wl_present`, `wl_process`, `wl_fb`, `wl_close_window`, `wl_close` — т.е.
**все шесть** оконных веток (условия в них — метки, эмитятся целиком,
достаточно вызвать каждую один раз). `tools/cgimg_check.py` — `SRC_NAMES` +=
`srcJ`, `range(1,11)`, `i == 10` → plain ELF.

- `python3 tools/cgimg_check.py` → **10/10 OK**, img10 `len=16914
  h=-2520265942535671238` (та же длина, что у img8: одинаковая
  `cgWlUsed`-раскладка `.data`/`.rdata`, разный `.text`).
- `timeout 2400 make -f Makefile.linux test` → **`MAKE_RC=0`,
  0 MISMATCH**, 15 `front-end … match`, `codegen-smoke OK`,
  `codegen-image OK` (img1..img10).

### ГРАБЛЬ

- **`.z` не имеет лямбд** — вся «внутренняя арифметика» C++-функции
  выносится в отдельные `cgWw*`-функции. Это безопасно: они не рекурсивны и
  вызываются только отсюда.
- Имена `var` в `.z` уникальны **в пределах блока**, а не функции — шесть
  `if`-веток спокойно объявляют свои `done`/`noFd`/`a0` (проверено на
  `cgTryLinuxWLCall`: `var done` встречается 3 раза в одной функции).
- `emit8` маскирует `& 0xFF`, `emit32` пишет по байту — `emit32(0xFFFFFFFF)`
  и `emit32(-1)` дают одни и те же байты.

### Следующий шаг

Семейство остальных `detect*Usage` (network/sound/tls/js/disasm) →
**директива «только syscall»** → порт оптимизаций → слой 2 с WinPE.
`make`-подобный язык — **отдельное приложение на Zenith**, делает другой
агент, в `main.cpp` его не трогаем.

---
## 05.10 (часть 16) — семейство `detect*Usage`, img11 и ДВА ПОЙМАННЫХ БАГА

### Что портировано

Пять обходчиков «кто использует сеть/звук/TLS/JS/дизассемблер» из
`codegen.cpp:8646..8656`: `detectNetworkUsage`, `detectSoundUsage`,
`detectTlsUsage`, `detectJsUsage`, `detectDisasmUsage`. Каждый — тот же
обход ZAST, что и существующий `cgDetectHttpDl*`, отличается только
предикат имени и ставящийся флаг.

- В `src/cg_expr.z` добавлено **633 строки** (генерил скриптом
  `/tmp/opencode/gen_detect.py` — временный, в `/tmp`): 5 ×
  `cgDetect*Usage` + `*ExprUsage`/`*Block`/`*Stmt` + хелперы
  `cgIsNetHttpGetName`, `cgIsDisasmName`, `cgIsSoundName`,
  `cgIsTlsName`, `cgIsJsName`. Шаблон — существующий `cgDetectHttpDl*`.
- Вызовы в `cgGenerateWide` (`src/cg_elf.z:3398..3408`) — в C++-порядке:
  network, netsock, sound, tls, httpdl, js, disasm, vk, wl, shader,
  vksurface.
- В `cgFreshState` добавлены сбросы `cgHttpGetUsed`, `cgSoundUsed`,
  `cgTlsUsed`, `cgJsUsed`, `cgDisasmUsed` **и `cgVkUsed`** — последний
  существовал и выставлялся, но **не сбрасывался вообще** (латентная
  утечка между сборками, нашли попутно).

Наблюдаемость: `trySoundCall` — только PE (`codegen.cpp:5586`,
Console/GUI); `httpGetUsed` на Linux эффекта не даёт (`:4067` внутри
PE-ветки `print` с `!isLinux`; в `.z` — `cgIsLinux == 0`,
`cg_expr.z:3653`). `tryTlsCall`/`tryJsCall`/`tryDisasmCall`
**достижимы на Linux** — но их эмиттеры пока не портированы (см.
«Следующий шаг»).

### Тест: img11

`src/_cgimg.z` — одиннадцатый источник `srcK`: `extern func puts` +
имена, поднимающие `cgSoundUsed`. `tools/cgimg_check.py` — `SRC_NAMES`
+= `srcK`, `range(1,12)`, `i == 11` → plain ELF.

`python3 tools/cgimg_check.py` → **11/11 OK**, img11 `len=13858
h=5303463847172874656`.

### ПОЙМАННЫЙ БАГ №1: builtin `sin` ≠ `std::sin`

img11 встал ровно на один отличающийся байт — 0x3424 (ref `4c`, было
`4d`) — это **синус-LUT** в `.data`. Причина: Zenith-билтин `sin` — это
x87 `fsin` поверх roundtrip в float32 (`src/codegen.cpp:849..866`,
`src/cg_expr.z:550`), а эталон строит таблицу `std::sin` в `double`.
На 512 точках это ровно одно расхождение (i=462: −18868 против −18867).

Лечить builtin нельзя (он паритетен для пользовательского кода) —
таблица **зашивается литералом**: `tools/gen_soundlut_z.py` переписывает
блок между маркерами

    # --- BEGIN cgSoundLutAppend (auto: tools/gen_soundlut_z.py) ---
    # --- END cgSoundLutAppend ---

а заполняющий цикл заменён на вызов `cgSoundLutAppend()`. Таблица
считается `math.sin` (та же libm) и сверена с ref ELF на `0x3088`.

### ПОЙМАННЫЙ БАГ №2 (главный): локальный массив не нулевой

После правки LUT **одиночная** сборка `srcK` сошлась с ref
байт-в-байт, а `cgimg_check` оставался MISMATCH **при той же длине**:
`selfhost=(13858, 2847645439270509933)` vs `ref=(13858,
5303463847172874656)`.

- Дамп: временная копия харнесса `src/_cgimg2.z` с `dumpHex(cgImg, …)`
  после img11 → **3 разных байта** на `0x3610..0x3612`: ref `00 00 00`,
  было `c5 14 44` = `0x4414c5` — адрес из **`.text` самого харнесса**.
- Бисект (`src/_cgbisect.z`: накопительно A, B, … J, после каждого —
  сборка srcK): `srcA..srcF` → OK, **`srcG` → сломан**, и ломан навсегда
  (H, I, J тоже). Ломает **img7** (`http_download`, 491 КБ).
- Разбор: `PT_DYNAMIC` → `DT_HASH` → файл `0x35f8` = `.hash`
  (`nbucket=4, nchain=3, buckets[4], chains[3]`), порчено ровно
  **`chains[0]`**.
- Виновник — `src/cg_elf.z:1841` (и ровно тот же код в
  `cgBuildELFLib`, `:2308`):

        var chain: [4096]int
        var ci: int = 1
        ...
            chain[ci] = prev        # пишется с ci = 1
        ...
        while chi < nsym
            cgElPut32(chain[chi])   # читается с chi = 0  <-- chain[0]

  В C++ это `std::vector<int> chain(nsym)` — **нули**. В `.z` локальный
  фикс-массив **не инициализируется**, поэтому `chain[0]` вообще никогда
  не записывается и несёт мусор со стека. Порча выглядит «постоянной»
  не из-за глобала: слот стека не перезаписывают ни одна из промежуточных
  сборок. Лечение — заливка `chain[0..nsym-1]=0` перед циклом, оба сайта.

Аудит остальных локальных фикс-массивов в `src/*.z` (`poolOff`,
`emitted`, `need`, `ksList`, `secNames`, `secNameOff`,
`shOff/shSize/shAln`) — все пишутся до чтения. Класс бага остаётся
открытым: **любой локальный массив, пишемый не с нуля, надо заливать.**

### ГРАБЛИ

- Файлы с бинарными литералами **не UTF-8**: `src/cg_httpdl_blob.z`
  (0x80) и `src/cg_elf.z` внутри `cgSoundLutAppend` (0x92) — так же,
  как `kHttpdlBlob`. Python-инструменты читать с
  `errors="surrogateescape"` (побайтово корректно), а не
  `encoding="utf-8"`.
- Бисект многосборочного харнесса делать **копией** (`_cgbisect.z`,
  `_cgimg2.z`), а не правкой `_cgimg.z`.
- «Одна сборка сошлась» **не достаточна**: `cgimg_check` гоняет все
  контейнеры в одном процессе и именно так ловит утечки состояния.

### Следующий шаг

Добрать эмиттеры, достижимые на Linux, но не портированные:
`tryTlsCall` (`codegen.cpp:5593` — Console/GUI/**Linux**),
`tryJsCall` (`:5601` — …`&& !koDriver`) — плюс их блобы
(`kTlsBlob` ~113 КБ, `kJsBlob` ~190 КБ) и соответствующие img-контейнеры.
`tryDisasmCall` закрыт в «части 17». Дальше — **директива «только
syscall»** → порт оптимизаций → слой 2 с WinPE. `make`-подобный язык —
отдельное приложение на Zenith, делает другой агент, в `main.cpp` его не
трогаем.

---
## 09.10 (часть 17) — `tryDisasmCall` + disasm-блоб, img12 и ДВА ПОЙМАННЫХ БАГА

### Что портировано

- **`src/cg_disasm_blob.z`** (генератор `tools/gen_disasm_blob_z.py`,
  чанки по 8192, паттерн скопирован с `gen_httpdl_blob_z.py`): 29432
  байта `kDsBlob`, `kDsBlobEntry = 0x6230`, `cgDisasmPutChunk`,
  `cgDisasmEmitBlobBytes`, `cgEmitDisasmBlob`. Сами байты **не** редактировать
  руками — только регенератором.
- **`src/cg_expr.z`**: `cgDsGuard`, `cgDsMovR8`, `cgDsMovR9`, `cgDsStageAbi`,
  `cgDsStoreStackSlot`, `cgDsEntryCall`, `cgTryDisasmCall` (≈12807) + диспетч
  `codegen.cpp:5610` (`appType == Linux && arch == X86_64 && !koDriver`):
  `if cgKoDriver() == 0 && cgTryDisasmCall(c) == 1` (7214).
  ВАЖНО: эталонные `guard`/`emitMovR8`/`emitMovR9`/`stageAbi` в
  `codegen_disasm.cpp:150..171` **не** защищают reg 7 (rdi-операнд) и reg 2
  в `disasm_one`-пути — реплицировать ровно, иначе регистральный паритет ломается.
- **`src/cg_elf.z`**: `cgEmitDisasmBlob()` — после httpdl-блоба, до
  `cgFixupSectionRVAs`/`cgResolveJmpFixups` (порядок `codegen.cpp:8711..8737`),
  гейт `cgDisasmUsed != 0 && cgLibOutput == 0`; в `cgFreshState` — сбросы
  `cgDisasmBlobEmitted = 0`, `cgDisasmEntryLabel = -1`.
- `use cg_disasm_blob` (строка 18).

### Тест: img12

`src/_cgimg.z` — двенадцатый источник `srcL`: `mass5/mass6/mass7` (вызовы
`disasm` с 5/6/7 аргументами) и `disasm_one`, через `alloc(8192)`/`free`.
`tools/cgimg_check.py`: `SRC_NAMES += ("srcL",)`, `range(1, 13)`,
`i == 12` → plain ELF.

- `python3 tools/cgimg_check.py` → **12/12 OK**, img12
  `len=36894 h=-7805999705305791640`.
- `timeout 2400 make -f Makefile.linux test` → **`MAKE_RC=0`**,
  **0 MISMATCH**, 249 `OK`.

### ПОЙМАННЫЙ БАГ 1 — padding перед disasm-блобом: нули, а не NOP

C++ `emitDisasmBlob` (`codegen_disasm.cpp:117`):
`while (blobStart % 16 != 0) { emit8(0); ... }` — **обнулить**. У httpdl —
NOP (`emit8(0x90)`), образец скопировался оттуда. Длина контейнера при этом
совпадает, структура `.text` тоже — отличаются ровно N байт выравнивания,
поэтому ловится **только** побайтовым сравнением, не «длиной и структурой».

### ПОЙМАННЫЙ БАГ 2 (главный) — heap-фикстуры пушатся sentinel'ом, а не переменной

Все **21** место `src/cg_expr.z` вызывало
`cgPushHeapFix(cgCodeLen, CG_HEAP_AREA_RVA /* = 0xFFFFFF00 */)`. Эталон
(`codegen_builtins.cpp`, `codegen_builtins_linux.cpp`, `codegen.cpp`) везде
кладёт **переменную** `heapAreaRVA` / `heapFreeHeadRVA` / `heapOffsetRVA`:
`buildImportData()` (`codegen.cpp:8657`) вызывается **до** emit-цикла и уже
посчитал реальные RVA, так что в момент push'а переменная содержит готовое
значение. Цикл резолюции sentinel'ов (`codegen_elf.cpp:502..504`, зеркально
`codegen_pe.cpp:1690..1692`) по факту **мёртвый** — и в `.z` он отрабатывает
раньше, чем фикстуры вообще появляются: `cgBuildLinuxImportData()` вызывается
в `cgGenerateWide` (`src/cg_elf.z:3414`), до цикла эмита функций.

Следствие: `disp32 = 0xFFFFFF00 - rip` → цель `0x3FFF00` вместо `0xA000`
(`.bss`), `0x3FFE00` вместо `0x9008`, `0x3FFD00` вместо `0x9000`. Меняются
**ровно 38 байт** в `.text`; длина контейнера и сам disasm-блоб — байт-в-байт
совпадают. Ломается только контейнер, где реально есть `alloc`/`free`
(img12 — первый такой во всём харнессе: img1..img11 эти ветки не проходят).

Лечение — 21 замена констант на переменные в `src/cg_expr.z`. Правильный
образец в дереве уже был: `src/_cgtest.z:126` пушит `cgHeapAreaRVA`.

### ГРАБЛИ

- **`from` — зарезервированное слово** selfhost-лексера
  (`selfhost/lexer.z:633`). `func h64(from: int, ...)` падает
  «Expected parameter name», причём с **полностью сбитыми номерами строк**
  (эскейп-литерал внутри файла). Не гадать — смотреть `lexer.z`.
- Числовой паритет «длина + FNV» не говорит, **где** расхождение. Путь:
  драйвер-копия (`_cgd12.z`, удалён после отладки) печатает `peek8`
  каждого байта `cgImg`, Python сверяет с эталонным ELF побайтово и
  печатает диапазоны. Дальше — `objdump -D -b binary -m i386:x86-64
  --adjust-vma=0x401000` по обрезку `.text`: у контейнера `e_shoff = 0`,
  обычный `objdump -d` молчит.
- Ключевые слова лексера (`from`) стоит держать под рукой — `grep '"from"'
  selfhost/lexer.z`.

### Следующий шаг

`tryJsCall` (`codegen.cpp:5601`, `src/codegen_js.cpp`, 746 строк,
`kJsBlob` 189816 байт) + его генератор блоба + фикстура img14.
`tryTlsCall` закрыт в «части 18». Дальше — **директива «только
syscall»** → порт оптимизаций → слой 2 с WinPE. `make`-подобный язык —
отдельное приложение на Zenith, делает другой агент, в `main.cpp` его не
трогаем.

---
## 09.10 (часть 18) — `tryTlsCall` + TLS-блоб, img13 и ПОЙМАННЫЙ БАГ С UTF-8

### Что портировано

- **`src/cg_tls_blob.z`** (генератор `tools/gen_tls_blob_z.py`, чанки по
  8192): 113272 байта `kTlsBlob`, `kTlstlsrt_entry = 0x7680`,
  `cgTlsPutChunk`/`cgTlsEmitBlobBytes`/`cgEmitTlsBlob`. **Выравнивание
  здесь NOP (`emit8(0x90)`), не нули** — как в `codegen_tls.cpp:107`
  (крипто-код грузит SIMD-константы `movdqa` со смещений внутри `.text`).
  Это третий образец подряд, и он снова отличается от двух предыдущих:
  disasm — `emit8(0)`, httpdl — NOP, tls — NOP.
- **`src/cg_expr.z`**: `cgTlsGuard`, `cgTlsEntryCall`, `cgEmitTlsIoInit`,
  `cgTryTlsCall` + `use cg_tls_blob`; диспетч — `if cgTryTlsCall(c) == 1`,
  **перед** disasm (`codegen.cpp:5593` → `:5601` js → `:5610` disasm).
- **`src/cg_elf.z`**: хук в **C++-порядке** (`codegen.cpp:8711..8737`):
  `(tlsUsed || jsUsed) && !libOutput` → **ПЕРЕД httpdl**, затем httpdl,
  затем disasm. Порядок влияет на раскладку `.text`. В `cgFreshState` —
  сбросы `cgTlsBlobEmitted`/`cgTlsEntryLabel`.

### Фикстуры, которые пришлось покрыть

`tls_connect` в C++ проверяет `dynamic_cast<StringExpr*>`: литерал даёт
`mov rcx, literalLen`, всё остальное — inline-`strlen`. Вторая ветка
не достижима из одного вызова, поэтому в img13 добавлена обёртка
`connVar(sock, host)`, внутри которой `host` — параметр. Плюс
`tls_send`/`tls_recv`/`tls_close`/`tls_last_error`.

### ТЕСТ

`python3 tools/cgimg_check.py` → **13/13 OK**, img13
`len=122918 h=8704592932605507178` (113272 байта блоба + слот
`TLS_IO_DONE` в `.data` + RWX `.text`).
`timeout 2400 make -f Makefile.linux test` → **`MAKE_RC=0`**,
**0 MISMATCH**, 250 `OK`.

### ПОЙМАННЫЙ БАГ (самый дорогой из всех за юнит)

**`edit`-инструмент работает через Unicode, а `src/cg_elf.z` — не UTF-8.**
Внутри `cgSoundLutAppend()` лежит литерал sin-LUT, где есть сырые байты
`0x92` и подобные (тот же класс, что `src/cg_httpdl_blob.z` и
`src/cg_disasm_blob.z`/`src/cg_tls_blob.z`). Два `edit`-правки в этом
юните прочитали файл как UTF-8, записали `0x92` как U+FFFD (`EF BF BD`)
и **незаметно испортили 455 байт**. Симптом: img11 (звук) вдруг начал
падать с **той же длиной** и другой суммой, причём спустя три юнита
после того, как он был зелёным.

Лечение: `python3 tools/gen_soundlut_z.py` (регенератор маркеров
BEGIN/END в `src/cg_elf.z`, работает с **bytes**). Проверка перед
коммитом:

```
python3 -c "import glob;
[print(p) for p in glob.glob('src/*.z')
 if b'\xef\xbf\xbd' in open(p,'rb').read()]"
```

Должно печатать **ничего**. Список файлов с намеренно-не-UTF-8 содержимым
(править только через `open(p,'rb')` / `errors="surrogateescape"`):
`src/cg_httpdl_blob.z`, `src/cg_disasm_blob.z`, `src/cg_tls_blob.z`,
`src/cg_elf.z` (внутри `cgSoundLutAppend`).

### ГРАБЛИ

- **`loop` — зарезервированное слово** selfhost-лексера
  (`selfhost/lexer.z`, `TLoop`). `var loop: int = newLabel()` падает
  «Expected variable name». Вместе с `from` («часть 17») — список растёт;
  перед именованием проверять `selfhost/lexer.z`.
- `tlsFixups` и `importCallFixups` на Linux **не резолвятся**: их патчит
  только `buildPE` (`codegen_pe.cpp:1841`) и PE-ветка `resolveFixups`,
  а `buildELF` работает с `elfImportFixups`. Поэтому в `cgEmitTlsIoInit`
  `disp32` остаётся нулём — и в эталоне, и здесь. `cgPushImportCall`
  вызывается только ради `checkFixupOverlaps`.

---
## 09.10 (часть 19) — `tryJsCall` + JS-блоб, img14 и БАГ С BUMP-ХИПОМ (64 МиБ)

### Что портировано

- **`src/cg_js_blob.z`** (генератор `tools/gen_js_blob_z.py`, чанки по
  8192, 24 слота `cgJsHostStubLabel`): 189816 байт `kJsBlob`,
  `kJsJsrt_entry = 0x2AD00`, `kJs__bss_end = 0x10FF4E0` →
  **`CG_JS_BSS_PAD = 17633128 нулей`** добиваются в `.text` после блоба
  (поэтому img14 = 17.9 МБ, а остальные контейнеры — килобайты).
  Выравнивание блоба — **нули**, как у disasm, и **не** NOP, как у
  httpdl/tls: третий образец, третий вариант. 14 Linux-слотов
  `kJsHostLinux` (индексы 0,1,2,3,12,13,14,15,16,17,18,20,21,22) → на
  каждый `cgJsHostFlagLabel[slot]` (8-байтовый флаг в `.data`) и
  `cgJsHostStubLabel[slot]` (заглушка в `.text`, куда уходит `jmp`
  мимо недоступного хоста).
- **`src/cg_expr.z`**: `use cg_js_blob`; блок `cgJsGuard`/`cgJsEntryCall`/
  `cgTryJsCall` (`:13268`, `:13276`, `:13282`) — проверка имени
  (`js_reset`/`js_eval`/`js_result`/`js_error`), arity (`js_eval` ровно
  1, остальные ровно 0), `cgPushJsFix` для слотов
  `CG_JS_SLOT_RESULT`/`CG_JS_SLOT_ERROR`, `spillRegs`/`reloadRegs` вокруг
  вызова. Диспетч `cg_expr.z:7219`: `if cgKoDriver() == 0 && cgTryJsCall(c) == 1`
  — между tls (`:7216`) и disasm, как в `codegen.cpp:5593 → :5601 → :5610`.
- **`src/cg_elf.z`**: хук в **C++-порядке** (`codegen.cpp:8711..8737`,
  комментарий `:3450`): `(tlsUsed || jsUsed) && !libOutput` → **tls**,
  httpdl, **js**, disasm — порядок меняет раскладку `.text`. Всё **ДО**
  `cgFixupSectionRVAs()` (там считается длина `.text`) и **ДО**
  резолва `jmp`-фикстур (там патчится `rel32` вызова блоба). `jsFixups`
  на Linux резолвятся наравне с прочими (`cgElfPatchDisp`,
  `codegen_elf.cpp:914/:1263`), слоты `cgJsResultRVA`/`cgJsErrorRVA` в
  `.data` уже были заведены; в `cgFreshState` — сбросы
  `cgJsBlobEmitted`, `cgJsEntryLabel`, `cgJsHostFlagLabel`
  (`cg_elf.z:3341`), иначе многосборочный харнесс унаследовал бы флаг
  и положил бы блоб во второй контейнер.

### Фикстура img14

`srcN`: `js_reset()`; `js_eval("var x = 1 + 2; x")` литералом и через
обёртку `runJs(code)` — параметр нужен ради **второй** ветки проверки
аргумента (как `connVar` в img13); `js_result()`; `js_error()`.
`tools/cgimg_check.py` → `SRC_NAMES += srcN`, `range(1, 15)`, `i == 14`.

### ПОЙМАННЫЙ БАГ (главный юнита): bump-хип Zenith против libc heap

Симптом: сборка драйвера на img14 падала `rc=139` (SIGSEGV) внутри
`cgBuildELF`, а при временной диагностике печатала

```
out of memory while growing the ELF image buffer
```

и всё равно падала. Две беды сразу:

1. **`alloc()` в Zenith — это НЕ malloc.** Для Linux-таргета кодоген
   эмитит **bump-хип внутри `.bss` самой эмитируемой программы**
   (`codegen.cpp:3022`, хип-область `heapAreaRVA`, 64 МиБ в `.bss`),
   плюс свой `free`, пишущий блок в свободный список. Эталон при этом
   использует `std::vector`/`ofstream` → libc heap → потолка не видит.
   Рост `cgImg` до 33.5 МиБ (`cap*2` от 16 МиБ) для 17.6-мегабайтового
   js-блоба упирался в потолок хипа: `alloc(33554432)` возвращал `0`.
   Хуже того, шаги удвоения 64K+128K+…+33.5M сами по себе ≈ 67 МиБ —
   то есть лимит был бы превзойдён даже без копий.
   **Лечение:** буферы кодогена (`cgCode`, `cgImg`, `cgData`,
   `cgRData`, `cgElTmp`) переведены на libc heap через
   `extern func realloc(p: int, n: int) -> int` (`src/cg_emit.z`).
   `realloc(0, n)` = `malloc(n)`, `realloc(p, n)` сохраняет содержимое и
   **сам** освобождает старый блок → ручные `cgCopyBytes` + `free`
   выкинуты из всех пяти `*Ensure`. Паритет не задет: буферы живут
   только внутри драйвера, их содержимое уходит в контейнеры
   `srcA..srcN` как есть, ни один эмитируемый байт не меняется.
2. **`eprintln(число)` здесь — SIGSEGV.** Аргумент-`int` трактуется
   как указатель строки; работает только `println(int)`. Моя
   диагностика `eprintln(nc)` в `cgImgEnsure` **маскировала** настоящую
   ошибку: вместо сообщения про OOM драйвер молча падал с `rc=139`, и
   полтора часа ушли на поиск « Segfault до записи заголовка».
   Правило: для трассировки чисел — только `println`.

Почему нельзя было сделать проще:

- **`free` нельзя переопределить через extern** — `free` это builtin
  (`codegen.cpp:3076`), он проверяется **раньше** поиска `extern func`,
  значит builtin'овый `free` получил бы уже libc-указатель и упал бы.
- **`malloc` под другим именем нельзя** — символ обязан совпадать с
  Zenith-именем функции, а `malloc` занят/не-нужен: хватает `realloc`.
- **`alloc`/`kfree` builtin'ы нельзя переключить на libc** — они
  эмитятся в код самого драйвера, и менять их значило бы менять
  драйвер, а не буферы.

### ТЕСТ

`python3 tools/cgimg_check.py` → **14/14 OK**, img14
`len=17949726 h=-4845514970219923369`.
`timeout 2400 make -f Makefile.linux test` → **`MAKE_RC=0`**,
**0 MISMATCH**, **251 `OK`**. Проверка U+FFFD по `src/*.z` — пусто.

### ГРАБЛИ

- **Временные `println(N)` в кодогене ломают `tools/cgimg_check.py`:**
  парсер ищет `imgN len=` и ловит число из диагностики (`len` читается
  как `100` у **всех** контейнеров, а хеши при этом совпадают). Симптом
  неочевидный: «MISMATCH» с одинаковым хешем = забытая трассировка.
  20 штук сняты перед финальной проверкой.
- `[ZT-BUG016] comparison 'k >= 0' is always true` и `'op <= 9'` в
  `src/_cgimg.z` — предупреждения багчекера от веток вроде
  `if cgJsHostStubLabel[slot] >= 0`; на паритет не влияют.
- Изменение аллокатора буферов — **единственное** место в порте, где
  драйвер принципиально не копирует C++ (`std::vector` → libc heap).
  Держать в голове, если кто-то захочет «вернуть `alloc` ради
  чистоты»: img14 перестанет собираться.

### Следующий шаг

Все три Linux-эмиттера закрыты: `tryTlsCall` (часть 18), `tryJsCall`
(часть 19), `tryDisasmCall` (часть 17) — хук в `cgBuildELF` теперь
выглядит ровно как `codegen.cpp:8711..8737`. Дальше по плану —
**директива «только syscall»** → порт оптимизаций → слой 2 с WinPE.
`make`-подобный язык — отдельное приложение на Zenith, делает другой
агент, в `main.cpp` его не трогаем.

---
## 09.10 (часть 20) — фронтенд в без-libc ELF: `_lexdrv`/`_astdrv`/`_parsdrv`

### Что сделано

- **Три selfhost-драйвера** гоняются двумя путями и сверяются
  байт-в-байт (`tools/cgfront_check.py`, цель `make -f Makefile.linux
  test-cgfront`, входит в `test`):
  - REF — `build/linux/zenith selfhost/_X.z --no-opt`;
  - SELF — харнесс `src/_cgfront.z` (собран эталоном, libc ему можно):
    сплайс через `build/linux/srcprep_dump` (потому что `parseRun` не
    раскрывает `use`) → `parseRun` → `cgBind` → `cgGenerateWide()` →
    пара `(len, FNV-64)` против эталонного `.elf` → диф байт при
    расхождении → оба `.elf` запускаются, сверяются rc/stdout/stderr;
  - статичность САМОГО артефакта: ровно 2 program headers, нет
    PT_INTERP/PT_DYNAMIC, т.е. печать через `write(1)`, выход через
    `exit_group`, память — bump-хип в `.bss` (правило части 20:
    «сисколы + управление памятью», только лексер/парсер/AST).
- **Новый драйвер `selfhost/_lexdrv.z`** (`app console` + `use lexer`):
  34 токена (`TFunc` первым), 6 идентификаторов, 3 числа, сумма 44;
  пассивный прогон `"var x = ;\n"` → 5 токенов и `lexErrorCount != 0`;
  печатает `ZLEX toks=`/`ZLEX errs=`, rc=0. Статический ELF 37786686
  байт, ошибки лексера идут в stderr (`Lexer error at line 1: ...`).
  Golden-дамп добавлен отдельно: `selfhost/golden/selfhost__lexdrv.dump`
  (16 `front-end … match` в тесте).
- **`Makefile.linux`**: цели `test-cgfront` (в `.PHONY` и в `test`),
  правило `$(SRCPREP)` (`tools/srcprep_dump.cpp` + `src/use_resolver.cpp`).

### ПОЙМАННЫЙ БАГ ГЛАВНЫЙ: дубликат глобала — last-wins против first-wins

Симптом: после закрытия `tryJsCall` пара «все 37 переменных AST
референснуты» (`probe_g`) расходилась с эталоном ровно на **944 байта
(0x3B0)** с дельтой по ФНВ64, при **идентичной длине**; якорные
`disp32`-слоты (`.data` 0x40c018..0x40c2d0, `gToks` @0x40c2d8)
расходились на 93 адреса подряд внутри одного диапазона.

Причина: **`gStrUsed` объявлен дважды** — `selfhost/lexer.z:126` и
`selfhost/ast.z:126`. C++ (`codegen_elf.cpp:492`):
`globalOffsets[g->name] = totalSize` — присваивание в
`std::unordered_map`, **последний выигрывает**; порт же пушил каждую
глобальную переменную в `cgGoName/cgGoOff`, а `cgGoFind`
(`src/cg_emit.z:282`) — линейный поиск **первого** совпадения → все
ссылки из AST шли в слот лексера (self 0x280c330 вместо 0x280c6e0,
дельта ровно 944). Дубликат ровно один — проверено сканом всех
`var`-имён в `selfhost/*.z`.

Лечение (`src/cg_elf.z`, цикл раскладки глобалов, ~`:1045`): перед
append ищем `var gof = cgGoFind(...)`, найден → `cgGoOff[gof] = total`
(последний перетирает, как в C++), не найден → append. Правка —
только bytes-путём (файл не UTF-8).

### ИНЦИДЕНТ: `src/cg_elf.z` обнулён и восстановлен

В 18:36 файл (3521 строка, **untracked в git** — весь порт `src/cg_*.z`
не под контролем версий) оказался **0 байт** (truncate in place) —
параллельный агент в это же время гонял свои правки. Копий на диске
нет, fd никто не держал. Восстановлен **из `opencode.db`**
(13 ГБ SQLite сессий, `part.data` содержит все вызовы инструментов —
реплей write/edit/bash в хронологии). После восстановления: 3609
строк, cp1251 `0x92` на месте, U+FFFD нет, патч last-wins на месте.

### ТЕСТ

`python3 tools/cgimg_check.py` → **14/14 OK** (регрессии после
восстановления `cg_elf.z` нет).
`python3 tools/cgfront_check.py` → **3/3 OK (static, run OK)**:
`_lexdrv len=37786686 h=-6204509983948649091`,
`_astdrv len=37919142 h=3810269895258709701`,
`_parsdrv len=40268766 h=-8514026650002624372`,
финал `codegen-front selfhost/lexer+parser+ast: OK`.
`timeout 2400 make -f Makefile.linux test` → **`MAKE_RC=0`**,
**0 MISMATCH**, **268 `OK`/`match`**, 16 `front-end … match`,
`codegen-front …: OK`. U+FFFD по `src/*.z` — пусто.

### ГРАБЛИ

- **Гонка параллельных агентов за фиксированные пути:** `cgfront_check`
  пишет вход/выход в `build/linux/cgfront_{in,out}` — пока шла моя
  проверка, параллельный агент пересобирал эталон (`build/linux/zenith`
  временно отсутствует → «нет эталона», гонка за `cgfront_out.elf` →
  `FileNotFoundError` на втором таргете). Лечение — перегнать чекер,
  когда `pgrep Makefile.linux` пуст; по возможности увести IN/OUT в
  временный каталог под `build/`.
- **Дубликаты имён глобалов в selfhost-исходниках:** сравнение «в
  первом/последнем» ведёт себя как `std::unordered_map` **last-wins**,
  любой линейный поиск — first-wins. Новые дубликаты имён глобалов
  (не только `gStrUsed`) будут ломать раскладку **молча**: длина
  совпадает, хеш нет. Сверять с `codegen_elf.cpp:492`.
- **`src/*.z` порта не в git:** обнулённый файл невозможно взять из
  репозития — только `opencode.db` (`part.data`) или реплей сессии.
  Перед рискованными правками — копия рядом (`*.bak`) или коммит.

---
## 10.10 (часть 21) — директива «только syscall»: mini-dlopen Vulkan и стабы libc

### Что сделано

- **Бан динамики в selfhost**: ветка `cgPushElfImport` (`src/cg_expr.z`)
  отвечает *«extern call through the dynamic loader is forbidden
  (syscall-only directive)»*; `cgBuildELF` всегда печатает `phnum = 2`,
  `emitLinuxExitViaLibc` → только `emitLinuxExitSyscall`. C++-эталон
  обычных программ и до этого был статичен → байтовый паритет сохранён;
  для vk C++ остаётся динамическим (`DT_NEEDED libvulkan.so.1` +
  `libc.so.6`) — по построению это другой класс `.elf`.
- **`cgEmitVkLoader` (`src/cg_elf.z`)**: хитхоп mini-dlopen целиком на
  `emit8` — `openat`/`mmap` (bias = `0x600000000000 + idx*0x400000`,
  prot=7, anon FIXED + файловый overlay + зануление хвоста), таблица
  `v2f` по96 байт/символу, релоки (RELATIVE/GLOB_DAT/JUMP_SLOT/64),
  IFUNC, heap-слот в `.data` через `mmap`.
- **`applyL` → `stubL`**: хук в applyL (`49 89 F6`, выравнивание стека
  `sub rsp,8 / add rsp,8`, `test rax / jne apadd`) вызывает `stubL`,
  которая `strcmpL`-ом по одному имени из `cgVkStubNameRVA[0..64]`
  возвращает тело стаба; промах (rax=0) → ud2 в GOT → SIGILL ровно на
  первом вызове неопределённого символа.
- **65 стабов libc** (`src/cg_elf.z`, тела до `# ---- stubL`):
  память/строки/`pthread_*`→0/`abort`→exit_group(134), `strncpy`/
  `strspn`/`strpbrk`/`strrchr`/`strstr`/`strcat`/`__strncat_chk`,
  семейство `*snprintf*` — наивная копия формата (форматы loader'а
  «Searching for layer manifest files» — без спецификаторов), файловые
  (`opendir`/`readdir`/`fopen`/`fclose`/`fread`/`fseek`/`stat`/`access`
  → NULL/−1: loader просто не находит манифестов), `get*id` — реальные
  syscall (102/104/107/108), `__ctype_tolower_loc` — таблица 384×int
  строится в rdata прямо при эмите, `pow` → xorps 0.0, `dirname` →
  возврат указателя без изменений, `dlopen`/`dlsym`/`dlerror` → NULL,
  `qsort`/`strtol`/`strtok` → заглушки (с миром «нет файлов» не зовутся),
  DATA-символ `stderr` → адрес кода-заглушки (передаётся только в наши
  стабы). `_chk`-варианты маппятся на те же тела (slen игнорируется).
- **`NODE_CAP` 131072 → 262144** (`selfhost/ast.z`) + пересборка
  `build/linux/zenith`: тела loader/stubs — тысячи строк — переполняли
  пул узлов (симптомы: «Error … Duplicate function ''» с пустыми именами
  и «Parser error: AST too large»).
- **`cgVkLeaRipL(r, lab)`** (`src/cg_elf.z`, перед `func cgVkEtestRR`):
  lea rip на МЕТКУ через `cgFixPush(cgCodeLen, lab)` — тот же rel32-формат,
  что у `emitJmp`. `cgVkLeaRip` принимает только RVA.
- **Новый хелпер теста**: `tools/cgfront_check.py` — цель
  **`cgfront vk`**: сплайс `tools/cgemit/vkrun.z` → харнесс → статичность
  (`check_static`) + запуск self и эталона → сравнение rc/stdout/stderr
  (byte-parity `.elf` здесь неприменим — см. выше). Референс
  `build/vkrun_ref.elf` пересобирается автоматически.
- **`Makefile.linux`**: `vkrun.z` переведён из mode A в `CGEMIT_PROGS_B`
  (C++ `--obj` форсирует `koDriver` и отказывается от `vk_*/wl_*`;
  mode B, эталон plain ELF — 2/2 byte-identical).

### ПОЙМАННЫЕ БАГИ

1. **Метка как RVA (главный).** 21 диспетчерный `cgVkLeaRip(0, stubX)`
   передавал id метки вместо RVA → рантайм-цель `0x400000 + id` (байты
   ELF-заголовка) → SIGSEGV на `0x400019`, строки `00 7f 45 4c 46`.
   У lea и у jmp форма fixup'а одинакова (`target − (at+4)`), поэтому
   лекарство — меточный fixup `cgVkLeaRipL`, а не пересчёт RVA руками.
2. **`movzbl (%reg),%reg` убивает указатель.** В strcspn-стабе
   `48 0F B6 12` (movzx rdx,[rdx]) сделал rdx=символ `0x3b` →
   следующий `si_addr=0x3b`. Всегда разводить r10=указатель /
   r11=байт: `49 89 F2`, `45 0F B6 1A` (REX45/41), `41 38 CB`.
3. **`realloc` — ветка наоборот**: `p==0` уходил в `[rdi-16]`; нужен
   `cgVkEjne(rz0)`, а не `je`.
4. **`;` между statement'ами в `src/cg_elf.z`** (55 строк emit8 из
   старого эмита loader'а): Zenith-лексер молча выбрасывает `;`
   (семантика не меняется, харнесс `cgfront` собирается), но
   `tools/cgemit_check.py` считает ЛЮБУЮ строку `Lexer error`
   фатальной → весь `test-cgemit` красный. Правило: после правок
   `cg_*.z` грепать сборку харнесса на `Lexer error`, не только на
   `Error|Parser error`.
5. **`make golden` vs параллельный агент.** `selfhost/bugfind.z`
   правился параллельным агентом в 12:01/12:13 между заморозкой
   golden (11:53/12:12) и прогоном → `test-front` МISMATCH ровно по
   `@NNNN`-позициям (`BF_MIN @7302/@7327/@7325` — все три версии файла).
   Перед финальным прогоном: `pgrep -f Makefile.linux` пуст, свежий
   `make golden`, затем сразу `make test`.
6. **`filter-out` матчит целое слово**: `filter-out vkrun.z` НЕ отсекает
   `tools/cgemit/vkrun.z` — нужен паттерн `%vkrun.z`.
7. **Отладка неопределённых символов** (пошагово): SIGILL на ud2
   (`0x401216`) → gdb `bt` → `#1 = 0x6000000XXXXX` (возврат из vulkan,
   bias `0x600000000000`) → `objdump -d --start-address=...` →
   `call <plt>` → имя. Аргументы вызова: bp по собственному
   `FF 15`-месту (стабильный VA `0x4010f6` в образе), ПОСЛЕ
   срабатывания — `break *0x6000000330c8` (в wolken-mmap'd регион gdb
   bp заранее не ставит: «Cannot insert breakpoint»). Скрипты:
   `/tmp/c4.gdb` (RIP/bt), `/tmp/c9.gdb` (две стадии).

### ТЕСТ

- `timeout 2400 make -f Makefile.linux test` → **`MAKE_RC=0`**,
  **0 MISMATCH**, **259 `OK` + 23 `match`**, включая
  `cgfront vk: len=19710 h=188092053107930716 OK (static, runtime parity)`
  и `codegen-parity(b) tools/cgemit/vkrun.z: OK`.
- смоук: `./build/vkrun_ref.elf` и `./build/linux/cgfront_out.elf` →
  `4206592`, `4206831`, rc=0, `cmp` stdout — идентично.
- `python3 tools/cgimg_check.py` → 14/14 OK; U+FFFD по
  `src/*.z selfhost/*.z tools/*.z` — пусто.
- дискин: `journalctl --vacuum-size=100M` + `apt-get clean` →
  `/` 95% → 91% (2.5G свободно); sudo-пароль `12` (передал пользователь).

### Следующий шаг

- **Порт оптимизаций** (`src/optimizer.cpp` → `src/cg_opt.z`?) —
  `--no-opt` остаётся обязательным во всех проверках, пока нет порта;
  затем **`.ko`-драйвер под рутом** (см. «Грабли»/PLAN.md: загрузка
  через `insmod` по sudo) и **`zenite`-установщик с `--mix` через
  zenmake**; слой 2 с WinPE — по PLAN.md.
- Остатки/риски стабов: `qsort`/`strtol`/`strtok`/`pow` — заглушки с
  грубыми значениями; если vk начнёт их реально звать (не через «мир
  без файлов») — услышим по расхождению вывода (`cgfront vk`).
- `vkrun.z` в `tools/cgemit/` засоряет wildcard mode A — если будут
  новые vk-программы, сразу класть в `*_b.z` или дописывать
  `filter-out %vkrun.z`.

---

## 11.10 (часть 22) — `asm {}` закрыт целиком (валидация ширин) + три бага, ронявших тесты

### asm: недостающей частью оказалась валидация, а не энкодер

`src/cg_asm.z` (порция `asmRegIndex` + `cgEmitAsmInstr`/`cgEmitAsm16Instr`
= codegen.cpp:6868-7638) уже лежал в дереве и байт-в-байт совпадал, но
ветка `N_ASM` в `src/cg_expr.z` шла мимо **прохода валидации**
`validateAsmWidths` (codegen.cpp:79-143), которого в `.z` не было вовсе.
C++ зовёт его первой строкой `generateWide` (codegen.cpp:8708), и
нарушение = throw -> `"Codegen error: <текст>"`. Матрица: real16 — только
0/16, arm64 — 0/32/64, stm32 — 0/32, всё остальное — 0/32/64, то есть
**`asm16 {}` на x86-64 цели — ошибка компиляции**
(`release/документация/14_ассемблер.txt`, матрица таргетов).

- **Новое в `src/cg_asm.z`** (после шапки, до энкодера):
  `cgValidateAsmWidths()` / `cgAsmValStmt` / `cgAsmValBlock` /
  `cgAsmWidthOk` / `cgAsmReject` — обход тел всех функций в порядке C++
  (if -> then/else, while/loop/for -> body, switch -> каждый case body),
  `ws = cgF(s,0)`, отказ собирается в байтовый буфер `cgAsmEb*` и уходит в
  `cgErrSet` (как C++, который конкатенирует which/target/allowed).
- **Вызов** — первым в `cgGenerateWide()` (`src/cg_elf.z`, правка
  bytes-путём: файл не UTF-8) с ранним выходом по `cgHasErr()`.
  `src/cg_zast.z`: добавлен `const FLAG_REAL16: int = 8` (бит H_FLAGS,
  selfhost/ast.z:69).
- **Текст ошибки совпадает с C++ байт-в-байт**:
  `asm16 blocks are not supported for x86-64 target: use 'asm' (native 64-bit) and 'asm32', but not 'asm16'`
  — сверено против `build/linux/zenith` на отдельной программе.
- **Негативный тест `asm16neg OK` в `src/_cgtest.z`** (test-cgtest, входит
  в `make test`): программа с `asm16 {}` кладётся в ZAST через
  `parseRun`+`cgBind`, т.е. строкой-литералом. КЛАСТЬ ЕЁ statement'ом
  драйвера НЕЛЬЗЯ: C++-валидация отвергла бы компиляцию самого драйвера.
  Дальше ассерты `cgHasErr()==1` и `strEqZ(cgErrText(), "<эталон>")`.
- `tools/cgemit/asm1_b.z` остался 64/32-битным (3/3 byte-identical:
  `main` 222 байта, `wide32` 99, `_text` 347): программа с `asm16` на
  x86-64 невалидна и в C++, теста на неё быть не может.
- `cgEmitAsm16Instr` портирован дословно, но байтово его пока нечем
  проверить: real16-бэкенд — слой 2 (`codegen_real16.cpp`); валидация
  гарантирует, что в слой 1 он не вызывается.

**Грабля языка:** мнемоники `or`/`and`/`not` в asm-блоки не пишутся — это
ключевые слова лексера `TPipePipe`/`TAmpAmp`/`TBang`
(selfhost/lexer.z:576,585,588), а мнемоника принимается только как
`TIdent`/`TTypeInt` (selfhost/parser.z:1791). Ограничение одинаково в C++
и .z (фронтенд один), поэтому кейсы `or`/`and` из arith-таблицы и
group3-`not` в тестовых программах не покрываются в принципе.

### БАГ 1: пропущенная декларация `gOCallSa` в `selfhost/opt.z`

Порт оптимизатора (`selfhost/opt.z`, часть 22, начат вне этой сессии)
использовал `gOCallSa` в `oTinyWalk` (:3918) и присваивал в
`oSubstituteTiny` (:4005), но **не объявлял**. Симптом — та самая
«иногда вылезающая» ошибка: `Codegen error: undefined variable 'gOCallSa'`
на ЛЮБОМ харнессе с `use ../selfhost/parser` (parser.z:6 `use opt`), то
есть на всём cgemit/cgfront/cgtest сьюте. Фикс: `var gOCallSa: int = 0`
рядом с `gOOcRoot` (opt.z:3890).

### БАГ 2: `# [no_main]` из комментария модуля делал программу библиотекой

`hasNoMain` (src/main.cpp:85-112) и `zffi_hasNoMain` (src/zffi.cpp:251)
гнали **инлайн-текст после `expandUseDirectives`** (main.cpp:1390,
main.z:1599) и при этом не пропускали комментарии (флаг `inLineComment`
объявлен, но не выставляется никогда — директива ведь сама живёт в
комментарии). В шапке `selfhost/opt.z` (строка 27) стоял буквальный текст
`# [no_main]` — и любая программа с `use parser` начинала собираться как
библиотека: у `app linux` расширение выхода стало **`.so` вместо `.elf`**
(main.cpp:1715), а `cgemit_check.py` падал на
`FileNotFoundError: /tmp/.../cgemit.elf`. Правка: флаг берётся ДО экспансии
в обоих драйверах (`src/main.cpp` и `.z`-порт `src/main.z:1599`), текст в
opt.z переписан без скобок. Правило: **заголовочные директивы
(`app`/`# [no_main]`/`kernel_mode`) принадлежат только главному файлу** —
как и записано в stripHeaderDirectives (main.cpp:114-116).

### БАГ 3: `test-cgfront` ронял `_parsdrv` — «too many jump fixups»

`cgFixPush`/`newLabel`/`emitLabel` в `.z` живут на фиксированных массивах
`[8192]`, а в C++ там `std::vector`. Замер на крупнейшей программе дерева
(`selfhost/_parsdrv.z` = parser+ast+lower+**opt**+lexer, сплайс 336 КБ,
после того как opt.z попал в цепочку `parser.z`): **jfix=8724,
labels=7797, call=4088, global=3379, go=384** — потолок 8192 превышен.
Подняты до **65536** все фикстурные таблицы (`CG_JFIX_MAX` и `CG_FIX_MAX`
+ все их `[N]int`-массивы и проверки в `src/cg_emit.z`; `CG_FO_MAX`=8192
оставлен — это счётчик числа функций). На байты ёмкость не влияет.

**Грабля (ловится молча!):** размер массива в `.z` — только числовой
литерал. `var x: [CG_JFIX_MAX]int` даёт `Error at line N: Expected array
size`, **но rc=0 и сломанный ELF всё равно выписывается**, и дальше
происходит segfault без единой подсказки (симптом: «харнесс упал (rc=139)»
в `cgfront_check`). `cgemit_check.py` такие строки считает фатальными, а
`cgfront_check` — нет. Правило: после правок размеров массивов грепать
вывод компиляции на `Error`, не только на rc.

### ТЕСТ

- `python3 tools/cgemit_check.py -b tools/cgemit/asm1_b.z` ->
  **3/3 byte-identical**.
- `make -f Makefile.linux test-cgtest` -> RC=0, `asm16neg OK`.
- `timeout 2400 make -f Makefile.linux test` -> **`MAKE_RC=0`,
  0 MISMATCH, 244 `OK` + 23 `match`** (в том числе cgimg 14/14,
  cgfront 4/4, `asm16neg OK`, все `codegen-parity`/`(b)`).
- `python3 tools/cgfront_check.py` -> **4/4 OK (static, run OK)**:
  `_lexdrv len=37786686 h=-6204509983948649091`,
  `_astdrv len=37919142 h=-7920865598932590389`,
  `_parsdrv len=49042758 h=1043002788004775083` (вырос с 40268766 из-за
  opt.z в цепочке parser.z — обе стороны растут одинаково),
  `cgfront vk len=19710 h=188092053107930716`.
- U+FFFD по `src/*.z selfhost/*.z tools/*.z` — пусто; `src/cg_elf.z`
  (не UTF-8) — сырые `0x92`/суррогаты на месте, правка bytes-путём.

### Что дальше

- Порт оптимизаций (`selfhost/opt.z`, часть 22) — пользователь продолжает
  сам; с него началась вся история с граблями 1 и 2.
- asm для слоя 1 закрыт целиком; `cgEmitAsm16Instr` ждёт real16-бэкенда
  (слой 2), тестовой программы под него пока нет.
- `--no-opt` во всех проверках обязателен (optimizer.cpp в selfhost
  не портирован).

## Грабли (проверенные ранее, не наступать повторно)

- **`alloc()` внутри кодогена — это bump-хип в `.bss` эмитируемой
  программы (64 МиБ), а не libc malloc** (`codegen.cpp:3022`). Буферы
  `cgCode`/`cgImg`/… на больших контейнерах (img14, js-блоб с
  17.6 млн нулей) растут до 33.5 МиБ и упираются в потолок → `alloc`
  возвращает `0`. Лечится переводом буферов на `extern func realloc`
  (см. «часть 19»); `free`/`malloc` как имена недоступны — `free`
  builtin.
- **`eprintln(число)` → SIGSEGV** (int трактуется как указатель
  строки), работает только `println(int)`. Трассировать числа
  исключительно `println`.
- **Любая временная `println(N)` в кодогене ломает `cgimg_check.py`:**
  парсер читает `len` из диагностической строки → все контейнеры
  «MISMATCH» с **совпадающими** хешами. Это и есть признак забытой
  трассировки, а не расхождения генерации.

- **Поля класса НЕ имеют `= init`** (`var x: int = 5` в class — синтаксическая
  ошибка, C++ тоже ругается). Сравнения в тестах только `var x: T`.
- `app console` на Linux-сборке C++ = **AppType::Linux (8)** (ifdef _WIN32 в
  parser.cpp:1329); selfhost пишет 8 всегда — на Linux паритет есть,
  кросс-сборка под Windows сейчас не паритетна (не трогаем).
- `use` в lower.z ЗАПРЕЩЁН (сплайс в parser.z, дуп-лексер/цикл).
- azStr не дедуплицирует — сравнения только azStrEq/azStrLitEq.
- Цикл по классам: cur — это ИМЯ (strId), не node id.
- В Zenith нет `elif`; имена var уникальны в пределах функции.
- Драйвер печатает site-ошибки самим парсером во время parseRun — это норма
  (rc при этом может быть 0: dup-func, bad-token).
- bad-token C++ rc=1 («no functions found»), parseRun rc=0 — это проверка
  main.cpp, Н парсера.
- C++ ошибки lower ПЕЧАТАЮТСЯ как `Parser error: <msg>` без site-строки (rc=1);
  в ABI parseRun это rc=3 с msg в parseErrMsg.
- **Никогда не пушить sentinel в `cgPushHeapFix`** — только переменную
  `cgHeapAreaRVA`/`cgHeapFreeHeadRVA`/`cgHeapOffsetRVA`, как делает C++.
  Резолюция sentinel'ов (`0xFFFFFF00`…) живёт **до** emit-цикла и по факту
  мёртвая; если пушить константу, `disp32` останется `-rip` и уедет в
  `0x3FFF00`-подобные адреса. Ломается только на контейнерах с
  `alloc`/`free`.
- Выравнивание в `.text` перед блобом (`emitDisasmBlob`) в C++ —
  `emit8(0)`, а не NOP. У httpdl — NOP; **не копировать образец между
  блобами вслепую**, смотреть свой `*.cpp`.
- **`src/cg_elf.z` / `src/cg_*_blob.z` — НЕ UTF-8.** Никогда не править их
  unicode-инструментами (edit и т.п.): `0x92` из литерала `cgSoundLutAppend`
  превращается в U+FFFD и **молча ломает img11** — симптом появляется через
  несколько юнитов. Править bytes-путём (`errors="surrogateescape"`) или
  регенератором (`tools/gen_soundlut_z.py`, `tools/gen_*_blob_z.py`).
- `from` — зарезервированное слово selfhost-лексера (`selfhost/lexer.z:633`).
- `loop` — то же самое (`TLoop`); не использовать как имя переменной.
- Временное: `selfhost/_astdrv.z`, `selfhost/_parsdrv.z`,
  `selfhost/_lexdrv.z` (часть 20) — удалить потом вместе с целью
  `test-cgfront` и харнессом `src/_cgfront.z`;
  `lexdiff_test.elf` в корне — мусор от прогона, удалить.
