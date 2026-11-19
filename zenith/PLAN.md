# План работ

Подробная передатка по переключению на selfhost-парсер — **NEXT.md**
(лейауты ZAST, грабли, ABI). **Все шаги 1–6 NEXT.md ВЫПОЛНЕНЫ**:
`make clean && make && make test` зелёный.

## Статус

- [x] selfhost/ast.z, lexer.z, parser.z, lower.z — готово и протестировано.
- [x] parseobj.z → parseobj.o → src/parseembed.cpp (ZAST→Program).
- [x] main.cpp переведён на `parseZ` (3 точки вызова, сообщения байт-в-байт).
- [x] Makefile: `PARSEROBJ` заменяет `LEXOBJ` в `$(BIN)` (коллизия `lex*`/`zenith_obj_init`),
      `bootstrap-parseobj`, `pardump`/`golden`/`pardiff`/`test-front`.
- [x] `test-front`: 15/15 золотых дампов совпадают.
- [x] Чистка неиспользуемых файлов (см. ниже).

### Правило чистки (обязательное)

**Как только что-то переписано на `.z` — сразу удалять связанные с ним
мусорные C++-файлы, не копить их.** Пример: лексер переехал в
`selfhost/lexer.z` → удалены `selfhost/reference/lexer.cpp`,
`selfhost/lexref.cpp`, `selfhost/lexdiff.z` и мёртвый `class Lexer` из
`src/lexer.h`.

**После того как весь AST-кодоген переписан в `codegen.z`/`main.z` —
УДАЛИТЬ ВСЕ AST-файлы из `src/`** (и `src/*.h` к ним):
`codegen.cpp`, `codegen.h`, `codegen_elf.cpp`, `codegen_pe.cpp`,
`codegen_js.cpp`, `codegen_wasm.cpp`, `codegen_arm64.cpp`,
`codegen_stm32.cpp`, `codegen_x8632.cpp`, `codegen_bios.cpp`,
`codegen_efi.cpp`, `codegen_gui.cpp`, `codegen_dx11*.cpp`,
`codegen_real16.cpp`, `codegen_vulkan.cpp`, `codegen_webgpu*/wl_*.cpp`,
`codegen_net*.cpp`, `codegen_sound.cpp`, `codegen_ko.cpp`,
`codegen_builtins*.cpp`, `codegen_shader.cpp`, `codegen_dwarf.cpp`,
`codegen_disasm.cpp`, `codegen_httpdl.cpp`, `codegen_tls.cpp`,
`codegen_sw.cpp`, `codegen_real16.cpp`, `codegen_android`-остатки,
`src/mix*.cpp`, `src/syslibs.cpp`, `src/spvasm.cpp`, `src/bugfind.cpp` —
по мере перехода каждого на .z. Оставить только то, что ещё не переписано.

**Ировские (IR) кодогены пока НЕ трогаем специально** — их переписываем
только ПОСЛЕ того, как AST-кодоген будет готов:
`irgen.cpp`, `iropt.cpp`, `irasm*.cpp`, `ir_ssa.cpp`, `irbugfind.cpp`,
`andropt.cpp` + их `.h`.

### Полная независимость от C++ (правило пользователя 05.10)

**Все переписанные `.z`-файлы обязаны быть полностью независимыми от
C++.** Конкретно:

1. Никакой зависимости от C++-исходников: ни `use`/вызовов, ни
   подстановок из `.h`, ни линковки с C++-объектами, ни гонки через g++.
   Каждый модуль компилируется только selfhost-компилятором
   (`build/linux/zenith`) из одних `.z`-файлов. Проверяем на харнессе:
   `python3 tools/cgemit_check.py tools/cgemit/<prog>.z` и
   `make -f Makefile.linux test` ходят без единого C++-транслейта,
   если свежий `zenith` уже собран.
2. Ссылки вида `codegen.cpp:5674` в комментариях — **не** зависимость,
   а провенанс: точка, откуда портирована строка. Держим их (по ним
   делается diff с оригиналом), но они никогда не должны читаться как
   «чтобы это скомпилировалось, нужен C++» — ни одного кодового байта
   от C++ не ожидается.
3. Цифры, маски, константы выясняются из C++-исходника на этапе порта и
   **записываются в `.z` буквально**; после удаления C++-файла
   («Правило чистки» выше) ни один модуль не замечает его отсутствия —
   тесты остаются зелёными без единого `.cpp` в дереве.
4. Эталон `zenith --obj --no-opt` в `tools/cgemit_check.py` — временный
   костыль верификации (C++ пока является источником истины по байтам).
   Он живёт **только** в тестовом скрипте, а не в продовых `.z`-файлах,
   и после полного порта уходит вместе с C++-файлом.

### Уже удалено (чистка 04.10)

| что | почему |
|---|---|
| `zenith/src/zenith.txt` | zip-архив исходников, случайно лежавший в `src/` (916K) |
| `zenith/os/uefi/__pycache__/` | кэш Python |
| `zenith/release/src/` | устаревшая копия компилятора (1.9M), на неё не ссылается никто |
| `документация/` (корень) | дубликат; живая копия — `zenith/release/документация/`
  (на неё ссылается `main.cpp`). Уникальные/более полные файлы слиты туда: `14_ассемблер.txt`, `16_stm32.txt`, `17_arm64.txt`, `19_сокеты.txt` |
| `selfhost/reference/lexer.cpp`, `selfhost/lexref.cpp`, `selfhost/lexdiff.z` | старый C++ лексер + его дифф-тест; лексер уже в `selfhost/lexer.z` |
| `selfhost/golden/selfhost_lexdiff.dump` | золотой дамп удалённого дифф-теста |
| `src/codegen_android.cpp` | только комментарий, 0 символов (`compileAndroid()` живёт в `codegen_arm64.cpp`) |
| `class Lexer` в `src/lexer.h` | осталась без реализации и без вызовов |
| `zenith/NEXT_STEPS.md` | устаревшая передатка (NEXT.md) |

## Статус 04.10 — шаг 2 (main.z) ВЫПОЛНЕН

- `zenith-z` собирается (`make -f Makefile.linux zdriver`), линкуется из
  `build/linux/main_z.o` + `$(PARSEROBJ)` с `-Wl,-init,zenith_zmain_init`.
- `src/main.z` (~1790 строк) — **полный** порт `main.cpp`, кроме `--ir`.
- Через `src/zffi.h`/`zffi.cpp` (временный плоский C ABI, `zprog*` = `Program*`).
- Портировано и проверено на **байт-в-байт паритет** (stdout/stderr/rc,
  для сборок — и бинарник): `cmdNew`, `cmdBuild`, `cmdWatch` +
  `collectSourceFiles` + `watchRefresh/Rebuild/Relaunch`, `--cc/--cxx`
  (mix: `zffi_mix*` + `g_mix` + `zffi_optimize(..., buildMode)`),
  `--watch`, все пути ошибок.
- **Известные отличия**: только строка `--ir` в usage (намеренно,
  `zenith-z --ir` → `Error: --ir is not available here: ...`, rc=1).
- `make -f Makefile.linux test` зелёный.

### Грабли, выловленные при порте main.z (не повторять)

- `&arr + n` — **элементный сдвиг ×8**, не байтовый. Только `intVar + n` —
  байтовый. 5 мест починены через `var tp: int = &gTLine` и т.п.
  `sAddInt`'s `&gNum + k` самосогласован — не трогать.
- В `--obj`/KO `print`/`println` идут через `tryKOCall → _printk` → stderr
  **без `\n`**. Весь вывод драйвера — через `zffi_out()` + helper `oLine(s)`.
  `eprint`/`eprintln` (fd-2) — корректны как есть.
- C++ возвращает `int` → в RAX нулевое расширение → `-1` приходит как
  `4294967295`. Любая zffi-функция, возвращающая `-1`, должна возвращать
  `long long` (так и сделано: `zffi_listZ`, `zffi_launch`, `zffi_wait`).
- `fs::path` пишется в поток **с кавычками** (`Compiled: "<f>" -> <lib>`,
  `Lexer error in "<f>":`), обычный `std::string` — без (`Build successful:`).
- bugfind сужает диапазон только при guard **на самой** переменной индекса
  (`var i: int = cl - 1; if i < 0 || i >= gLFN return 0`), не на выражении.
- Ветка watch использовала `t` без объявления (читал мусор из стека) →
  нужен `var wt: int = zffi_appType(prog)`.
- child-аргументы в watch собираются с `ca = 1` (argv[0] не включаем).

---

## Дальше

Порядок (согласован): **4 → 2 → 1 → все остальные бэки**.

1. ~~Чистка неиспользуемых файлов~~ — **ГОТОВО** (таблица выше).
2. ~~**main.z**~~ — **ГОТОВО** (см. выше; extern `Codegen` через zffi жив).
3. **codegen.z** — ядро AST-кодогена + первый рабочий бэкенд
   (x86-64 ELF), полностью независимый от `.cpp`, без IR.
   После этого main.z переключается на него и extern убирается.
   **НАЧАТО 04.10**: создан `src/codegen.z` (ZAST-ридер + буфер кода +
   регистры + x86/x86-64 примитивы), проверен `src/_cgtest.z`
   (FNV-хеши `5349884057702756315` / `4141289819001028584` совпали с
   независимой моделью формул `codegen.cpp`). Подробности — NEXT.md.
4. Потом потихоньку — **все остальные AST-бэки** в `.z`,
   с удалением каждого переписанного `.cpp` из `src/` («Правило чистки»).

Требования к `codegen.z`:
- **полностью независим от .cpp бэкенда** (ни одного include/вызова в
  старые C++-бэки);
- **IR не использует** — только AST/ZAST;
- **ПОЛНОТА (указание пользователя)**: в `.z` должно быть ВСЁ, что есть в
  `codegen.cpp`, плюс весь `codegen_elf.cpp` (он отвечает и за контейнер ELF,
  и за Linux-бэкенд: `detectLinuxNeed`, `buildLinuxImportData`,
  `emitLinuxEntryPoint/ExitSyscall/ExitViaLibc/LibInit`,
  `emitStartupRelocator`, `buildELF`, `buildEFLib`), плюс связанные с этим
  путём файлы, **включая `codegen_vulkan.cpp`**. Т.е. бэкенд = ELF + ядро
  Linux-пути + vulkan + wayland + net/linux + sound + builtins/linux + ko
  + dwarf + встроенные blob-вызовы. Ничего «на потом» не оставлять.
- после перехода — удалять переписанные файлы (см. «Правило чистки»).

**Уточнение объёма (указание пользователя 04.10, третье).** Пункт «ПОЛНОТА»
выше — это **конечная** цель, порядок же работ такой:

1. **Ядро сейчас, бэкенды отдельно.** Уже портированный кусок `codegen.cpp`
   разбивается на логические модули сразу (см. «Модульная разбивка» ниже);
   каждый файл бэкенда ложится **своим модулем** по мере порта, а не
   дописывается в ядро.
2. **Сначала только путь Linux/x86** — `codegen.cpp` + `codegen_elf.cpp` +
   `codegen_ko.cpp` + хвост `try*Call` для `app linux`. Остальные бэкенды
   (PE, arm64, stm32, wasm, dx11, bios, efi …) — **следующим слоем**.

   *Причина изменения записи «в .z должно быть всё»:* инвентаризация даёт
   43 145 строк `codegen*.cpp`; тащить их все в один шаг нелогично, пока
   `zenith-z` ещё не собирает проекты. Цель не отменяется — меняется
   порядок: сначала закрывается Linux/x86 целиком (с удалением его `.cpp`
   по «Правилу чистки»), потом слой за слоем остальные бэкенды.

   Полнота внутри выбранного слоя сохраняется: `app linux`/`console`
   обязан вести себя байт-в-байт как C++ — включая ko, vulkan, wayland,
   net, sound, builtins и dwarf, они входят в слой.

### Объём (инвентаризация 04.10, `src/codegen*.cpp` = 43 145 строк)

| файл | строк | что |
|---|---:|---|
| `codegen.cpp` | 8844 | ядро: 119 методов `Codegen::` — emit-примитивы, регистры, `exprType`, `isFloatExpr`, `emitAddrOfExpr`, `emitBinaryExpr` (604), `emitExpr` (3456), `emitStmt` (506), `emitAsmInstr`/`emitAsm16Instr`, `emitFunction`, `emitEntryPoint` (630), `generateWide` (280) |
| `codegen_arm64.cpp` | 4642 | бэкенд ARM64 |
| `codegen_stm32.cpp` | 5117 | бэкенд STM32 |
| `codegen_builtins.cpp` | 2721 | `tryBuiltinCall` (Win32/EFI/BIOS builtin'ы) |
| `codegen_pe.cpp` | 3239 | бэкенд Windows PE |
| `codegen_wasm.cpp` | 2080 | бэкенд WASM |
| `codegen_dx11_shaders.cpp` | 2282 | DX11 шейдеры |
| `codegen_x8632.cpp` | 1445 | бэкенд x86-32 |
| **`codegen_elf.cpp`** | **1345** | **контейнер ELF + Linux-бэкенд (9 методов)** |
| `codegen_gui.cpp` | 1124 | Win32 GUI (`tryGUICall`) |
| `codegen_efi.cpp` | 1043 | EFI |
| `codegen_builtins_linux.cpp` | 814 | `tryLinuxCall`, `tryLinuxGUICall`, `tryKOCall` |
| `codegen_ko.cpp` | 826 | `emitKOEntry/ObjInit`, `buildKO` |
| `codegen_wl_window.cpp` | 774 | Wayland window (`tryLinuxWLWindowCall`) |
| `codegen_js.cpp` | 747 | JS builtin'ы |
| `codegen_sound.cpp` | 742 | `detectSoundUsage`, `emitSoundGen/MixHelper`, `trySoundCall` |
| `codegen_dx11.cpp` | 732 | DX11 |
| `codegen_bios.cpp` | 670 | BIOS |
| `codegen_net.cpp` | 664 | Winsock `tryNetCall` |
| `codegen_wl_linux.cpp` | 444 | `detectWLUsage`, `tryLinuxWLCall` |
| **`codegen_net_linux.cpp`** | **570** | **`tryLinuxNetCall`** |
| `codegen_real16.cpp` | 393 | real-mode 16 бит |
| **`codegen_vulkan.cpp`** | **399** | **`detectVkUsage`, `tryLinuxVulkanCall`** |
| `codegen_dwarf.cpp` | 361 | `writeDebugInfo` |
| `codegen_httpdl.cpp` | 277 | `detectHttpDlUsage`, `emitHttpDlBlob`, `tryHttpDlCall` |
| `codegen_tls.cpp` | 285 | `detectTlsUsage`, `emitTlsBlob`, `tryTlsCall` |
| `codegen_disasm.cpp` | 230 | `detectDisasmUsage`, `tryDisasmCall` |
| `codegen_shader.cpp` | 180 | `detectShaderUsage`, `tryShaderCall` |
| `codegen_sw.cpp` | 134 | `emitSWInit/Present/Cleanup` |
| `codegen_wl_wsi.cpp` | 21 | `detectVkSurfaceUsage`, `tryLinuxVkSurfaceCall` |

**Порядок диспетчеризации вызовов в `emitExpr` (codegen.cpp:5506–5614)** —
для `appType == Linux`: `tryKOCall` (koDriver) → `tryLinuxCall` →
`tryLinuxGUICall` → `tryLinuxVulkanCall` → `tryLinuxVkSurfaceCall` →
`tryLinuxNetCall` → `tryHttpDlCall` → `tryLinuxWLCall` → `tryShaderCall`;
затем независимо от appType: `tryTlsCall` (Console/GUI/Linux),
`tryJsCall` (… && !koDriver), `tryDisasmCall` (… && X86_64 && !koDriver).

**Состав «первого бэкенда» (x86-64 ELF, `app linux`/`console`)**:
`codegen.cpp` + `codegen_elf.cpp` + `codegen_vulkan.cpp` +
`codegen_wl_linux.cpp` + `codegen_wl_window.cpp` + `codegen_wl_wsi.cpp` +
`codegen_net_linux.cpp` + `codegen_net.cpp` + `codegen_sound.cpp` +
`codegen_builtins_linux.cpp` + `codegen_builtins.cpp` + `codegen_ko.cpp` +
`codegen_dwarf.cpp` + `codegen_disasm.cpp` + `codegen_httpdl.cpp` +
`codegen_tls.cpp` + `codegen_js.cpp` + `codegen_sw.cpp` + `codegen_shader.cpp`.

Это и есть «слой 1» из уточнения объёма выше (Linux/x86). Всё, что в таблице
не входит в этот состав — **слой 2**, портится после того, как слой 1 закрыт
и его `.cpp` удалены: `codegen_arm64`, `codegen_stm32`, `codegen_pe`,
`codegen_wasm`, `codegen_x8632`, `codegen_gui`, `codegen_efi`,
`codegen_bios`, `codegen_real16`, `codegen_dx11_shaders`.

### Разбивка на 2 параллельных сессии (когда дойдём до >1 бэкенда)

- **Сессия A (ядро)**: `codegen.z` = `codegen.cpp` целиком + `codegen_elf.cpp`
  + linux/vulkan/wayland/sound/net/ko/dwarf/blob-хвост. Первый рабочий бэкенд.
- **Сессия B (бэки)**: после A — остальные контейнеры в `.z` по одному
  (`pe` → `x8632` → `bios`/`efi` → `arm64` → `stm32` → `wasm`/`js` → `dx11`),
  каждый сразу удаляя свой `.cpp` («Правило чистки»).
- Пока бэкенд один — параллельно не делим.


### Статус 04.10 — шаг 3 НАЧАТ (`src/codegen.z`)

**Архитектура.** `codegen.z` принимает **ZAST-блоб**, а не C++ `Program`:
`selfhost/ast.z` + `lower.z` (сплайс через `selfhost/parseobj.z`) уже выдают
пониженное «плоское» AST, и `.z`-бэкенд читает его напрямую, не трогая
объекты C++-фронтенда. Флаги драйвера (`isLibrary`/`objOutput`/путь вывода)
остаются в драйвере. Модуль без `app` и `main` — драйвер делает `use codegen`.

**Готово в ядре `codegen.z` (~2255 строк на начало шага, ~6269 строк сейчас
после разбивки на модули — см. «Модульная разбивка»):**

1. Чтение ZAST: `cgBind`/`cgH`/`cgSide`/`cgNodeCount`/`cgNodeAddr`/`cgTag`/
   `cgLine`/`cgF`/`cgSetF`/`cgFAddr`/`cgStrPtr`/`cgStrLen`/`cgLitEq`;
   константы `H_*`, `N_*`, `H_SIZE=64`, `CG_NODE_BYTES=72`.
   Узел = 72 байта: `tag`(u32), `line`(u32), 16 полей по 4 байта
   (поле `f` → `node + (2+f)*4`), как в `selfhost/ast.z azNew/azGet`.
2. Буфер кода: `cgEnsure` (рост ×2 через `alloc`+`cgCopyBytes`+`free`),
   `emit8/16/32/64`, `cgInit`/`cgReset`/`cgCodePtr`.
3. Регистры: `allocReg`/`freeReg`/`allocXmmReg`/`freeXmmReg`, пул `{0,1,2,3,6,7}`.
4. x86/x86-64: `emitMovReg`, `emitMovRegImm`, BP load/store, `emitAdd/Sub/Imul`
   (**дословно** — спец-случаи в C++ дают другие байты, чем общая формула),
   `emitAnd/Or/Xor`, `newLabel`.
5. SSE: `emitMovssXmm(+Imm)`, `sseRR`, add/sub/mul/div/ucomiss/cvt*/sqrt/andps/
   minss/maxss/xorps/roundss. C++ `emitMovssXmmImm(float)` разложен на
   `emitMovssXmmImmInt(bits)` — в `.z` нет битового приведения float→int.
6. disp8-помощники, `spillRegs`/`reloadRegs`, метки/фикстуры (`emitJcc`
   по strId, `emitJccLit` по литералу, `cgApplyFixups`).
7. Ошибки через `cgErrSet`/`cgHasErr` вместо `throw`.
8. **Система типов и раскладки**: `TK_*` (TypeKind из `ast.h`), тип = 6 слов
   `[kind, structName, isPtr, addrSpace, arraySize, fnSigId]` и передаётся
   указателем на эти слова (`cgFAddr`, `cgTyScratch`); `cgStrIdsEq`
   (сравнение по содержимому — `azStr` не дедуплицирует);
   `cgComputeStructLayouts` (8 проходов, как `computeStructLayouts`
   codegen.cpp:7538), `cgStructTypeSize` (=1179), `cgArrayElemStride` (=1376);
   таблица переменных `cgVarClear/cgVarFind/cgVarPut`;
   `cgAllocStmts` (= `allocateBlockVars` 7589) и `cgSetupFunc` (верх
   `emitFunction`: параметры/`locals`/`spillBase`/`frameSize`).

**Харнесс `src/_cgdrv.z`** (`app console` + `use ../selfhost/parser` +
`use codegen`): парсит строку-источник, `cgBind(parseOutPtr(), parseOutLen())`
и печатает раскладки. Свёрено с расчётом по C++:

- `Point`=16, `Rect`=48, поле `v` (vec3) @36 (правило
  `offset % fieldSize` использует сам размер поля как выравнивание);
- встроенные `vec2`/`vec3`/`color` структуры регистрируются и парсером C++
  (`parser.cpp:2394`), и selfhost — составы совпадают;
- `func f(a: int, b: float, c: Point)`: `paramBytes=32`,
  `a=-32 b=-24 c=-16`, `locals=180`, `spillBase=140`, `frame=200`,
  локальные `x=-40 y=-44 r=-92 i=-100 z=-108 w=-116 t=-124 u=-132`.

`make -f Makefile.linux test` зелёный после каждого куска.

**Найдено при тестировании (записать на будущее):**
- **ZAST-строки НЕ NUL-терминированы**: запись = `[u32 len][len bytes]`,
  вплотную к следующей (`selfhost/ast.z azStr`). Любое сравнение «дочитать
  до 0» уходит в чужую строку и даёт ложные отказы/совпадения. Все сравнения
  идут через `cgStrLen` (`cgStrIdsEq`, `cgStrIs`, `cgStrEqZ`); `cgLitEq`
  (два `.z`-литерала) остаётся NUL-based. Найдено по симптому: `exprType`
  для `p2: Point = p` возвращал Void, а `p.x > 0` — Int вместо Bool.
- `selfhost/lexer.z lxBAppendNum` печатает `'0'` для **любого** `v <= 0`
  (отрицательные не поддерживаются) — `pbNum` в харнессе поэтому выведет
  `0` вместо `-40`. Чинить `selfhost/` не входит в шаг 1–3.

- Лексер отказывается от литералов > `int64 max` (см. выше).
- `-o /tmp/x` для `app linux` даёт `/tmp/x.elf`.
- `use`-резолвер ищет модуль в `baseDir`, `baseDir/include`, `include`,
  `cwd`, `cwd/include` и рядом с бинарём (до 3 уровней вверх) — отсюда
  `use ../selfhost/parser` в `src/_cgdrv.z`.
- Имена-дубликаты `H_*`/`N_*` между `codegen.z` и `selfhost/ast.z`
  при сплайсе одного файла **не ошибка** (компилируется), но значения
  обязаны совпадать — они скопированы 1:1.
- `vec3`/`vec2`/`color` принимаются только при `gAppType == 1`, то есть
  источник должен начинаться с `app gui dx tool` (без `dx`/`sr`/`vulkan`
  `gRenderType=0` → `gAppType=8`).

9. **Типы выражений**: `cgStrIs`/`cgStrEqZ`/`cgLitLen` (без NUL!),
   `cgTyMake`/`cgTyCopy` (кольцо из 256 scratch-слотов 6 слов — C++ возвращает
   `Type` по значению), `cgIsFuncPtr`, `cgSigRet`, `cgFuncRetType`,
   **`cgExprType`** (= `exprType` 1306), **`cgCallCalleeKind`** (=1497,
   `cgCalleeVar` = out-параметр), **`cgIsFloatExpr`** (=1080),
   **`cgStructValueQwords`** (=1199). Отладочный блок `ZT_CALLDEBUG` в
   `isFloatExpr` не переносился (только stderr-трассировка).

Сверено на харнессе: `p.x > 0` → Bool, `p2: Point = p` → Struct + `qwords=2`,
`r.v` → Vec3 + `qwords=2`, `r.w` → Float + `isF=1`, `q + 1.5` → Float.

10. **Адресные примитивы и фикстуры** — `emitLeaRegFromBP` (=1536),
    `emitLoadFromAddr` (=1553), `emitLoadFromAddrR10` (=1651),
    `emitGlobalLeaReg` (=1742, пишет в `cgGlobalFixups` + `cgGlobalsRVA`);
    таблицы фикстур `cgFuncRefFixups`/`cgGlobalFixups`/`cgCallFixups`
    (заполняются здесь, патчит контейнер), `cgFuncOffsetPut/Find`
    (= `funcOffsets`), `cgIsUserFunc` (=1415, `f11` = isExtern).

**Дальше (на 05.10, обновлено):** `emitStmt` **ГОТОВ** (кроме `N_ASM`),
`populateGlobalVarInfos` **ГОТОВО**, `emitFunction` **ГОТОВО**, **весь
Linux entry-point кластер ГОТОВ** (`emitLinuxEntryPoint`,
`emitLinuxExitSyscall`, `emitLinuxExitViaLibc`, `emitLinuxLibInit`,
`emitStartupRelocator`, `emitMixCrt0Call`, `emitGlobalInit` — см. п.19).
`collectStrings` **ГОТОВ** (п.20). **`generateWide` (Linux) + `buildELF`
ГОТОВЫ** (п.21). Осталось: `tryLinuxCall` и вся диспетчерская
`try*Call` (`codegen_builtins_linux.cpp` 814 стр →
`codegen_net_linux.cpp` 569 → `codegen_wl_linux.cpp` 443 →
`codegen_gui.cpp`/`codegen_vulkan.cpp`) — без них `app linux` не может
вызвать ни один системный билтин (`cg_expr.z:7135`); затем
`detect*Usage`-семейства (14 штук), `emitAsmInstr` (и с ним последняя
ветка `N_ASM`), `syslibs`-проба `linuxSonameFor` → **`buildELFLib`** →
`emitEntryPoint` (630, PE/слой 2).
`globalOffsets` заполняет **бэкенд** (`codegen_elf.cpp:472`) — через
`cgGoName/cgGoOff/cgGoN` в `cgBuildLinuxImportData`, читает их
`cgPopulateGlobalVarInfos`.

**Порядок после ядра (указание пользователя 05.10):** доделав ядро,
собрать под Linux выходные артефакты — **динамические библиотеки**
(`buildELFLib` + `emitLinuxLibInit` → `.so`, `DT_INIT`, `exportEntries`) и
**модули ядра** (`koDriver`/`buildKO` → `.ko`), — и только после этого
переходить **слой 2, начиная с WinPE** (`codegen_pe.cpp`).

**Дорожная карта (указание пользователя 05.10, вторая часть):**
1. полностью доделать Linux-бэкенд с драйверами и **оптимизациями**
   (`optimizer.cpp`/`iropt.cpp`/`ir_ssa.cpp` — сейчас в selfhost это
   ещё C++ через `zffi_optimize`);
2. динамические библиотеки `.so`, затем `.ko`; портировать
   `codegen_vulkan.cpp` (пока без графики);
3. **собрать self-host впервые без линковки с оригинальным бэкендом**
   (один бэкенд, с поддержкой генерации файлов и оптимизаций);
4. написать в `main.cpp` **свой маленький make-подобный язык**
   (синтаксис в духе Makefile) для сборки проектов Zenith — имя главного
   файла и команда запуска выбираем сами, затем создать этот файл;
5. результат — работающий self-host (в `.exe` в том числе).

### Прогресс шага 3, вторая часть 04.10 (ядро, сейчас `src/cg_expr.z` + `src/cg_emit.z`)

11. **Эмиттеры выражений** (порядок `codegen.cpp`):
    `cgEmitUnaryExpr` (414), `cgEmitFloatMathCall` (786, с unaryInPlace →
    itof → sin/cos/tan → atan2 → min/max → fmod → pow и `return -1` при
    несовпадении арности **внутри** matched-ветки), `cgEmitStructAddrR10`
    (1245) / `cgEmitStructRegs` (1291), `cgEmitAddrOfExpr` (1406),
    `cgEmitFloatExpr` (1912), `cgExprContainsCall`/`cgExprHasArrayAccess`/
    `cgMemberPath`, `cgEmitExprKeepAlive`/`...R10`/`cgEmitFloatExprKeepAliveR10`
    (2110/2129/2145, C++ `int& keepReg` → глобальный `cgKeepReg`),
    **`cgEmitBinaryExpr` (2155–2759) + `cgEmitBinaryInt` / `cgEmitBinaryFloat`**
    (спил-ветки `tempReg < 0`, `scaleRight`, `idiv`/`shift` с `push/pop rcx`,
    **инвертированные** `jcc` через `cgEmitJccSkip`: `==→0x85 !=→0x84
    <→0x8D >→0x8E <=→0x8F >=→0x8C` — это НЕ маппинг `emitJcc`),
    `cgEmitFtoiExpr` (2759), **`cgEmitExpr` (2777)** со всеми ветками,
    `cgEmitArrayAcc` (2890), заглушка `cgEmitCallExpr` (`ftoi` работает,
    остальное → `cgErrSet`).
12. **`cgEmitStmt` (6233) — ПОРТИРОВАН ЦЕЛИКОМ 05.10**, кроме ветки
    `N_ASM` (`emitAsmInstr`, 6753 → это п. «Дальше»). Покрыты `N_RETURN`,
    `N_EXPRSTMT`, `N_VARDECL`, `N_ASSIGN` (индекс / путь полей / плоское),
    `N_PTRASSIGN`, `N_IF`, `N_WHILE`, `N_LOOP`, `N_SWITCH`, `N_BREAK`,
    `N_CONTINUE`, `N_FOR`. Разметка всех узлов сверена по
    `selfhost/parser.z`, добавлены `cgEmitBlock`, `cgSwitchLabels[4096]`,
    стеки `break`/`continue`, арена синтетических узлов `cgSynth*` (для
    member-assign). Подробности и грабли — NEXT.md, раздел 05.10.
13. **Пул строк и фикстуры строк** — `cgStringPoolIdx` + `cgStrFix*` /
    `cgKoStrFix*` (в `.z` пул держит strId и сравнивает **содержимое**,
    т.к. `azStr` не дедуплицирует), `cgObjOutput` + `cgKoDriver()`.

**Проверка паритета (новое, вместо Python-модели): `tools/cgemit_check.py`.**
Генерирует `src/_cgemit.z` из тестируемой программы, парсит её тем же
selfhost-парсером, для каждой функции проигрывает ветку `N_RETURN`
`emitStmt` через `cgEmitStmt`, а рядом собирает ту же программу
`zenith --obj --no-opt` и сравнивает байты из `objdump .o` **подстрокой**:
`43/43` функции в `tools/cgemit/expr{1,2,3}.z` байт-в-байт совпали
(`make -f Makefile.linux test-cgemit`, добавлен в `test`).

Грабли этого этапа (не повторять):
- **`--no-opt` обязателен**: оптимизатор правит AST (`x * 2` → сдвиг,
  свёртка констант), и без него две стороны легитимно расходятся.
- `ptr<ptr<T>>` не парсится ни C++, ни selfhost («Expected type after ptr») —
  вложенные указатели через структуру-обёртку.
- Предел вложенности правоскрестных `a + (b + (...))` — 4 уровня: на 5-м
  `allocReg` кончается. C++ бросает и `.z` `cgErrSet` **одним и тем же
  текстом** (`register allocation failed: expression too deep (all 6 GP
  registers in use)`), но `.z` продолжает эмитить мусор до конца цикла,
  потому что ветка `N_IDENT` не проверяет `allocReg() < 0`.
- `app console` пишет `pbInit/pbFlush` в **stderr**, а не stdout.
- `pbNum` печатает `0` для отрицательных → FNV-хеш иногда выводится как `0`;
  в проверке участвуют только hex-байты.
- `%of` (`50% = expr`): в C++ это свой `fprintf` + `exit(1)` (rc=1, текст
  без префикса); в `.z` — `cgErrSetPlain` (флаг `cgErrPlain`), вывод
  драйвером ещё не подключён.

14. **Модульная разбивка (04.10, третья часть шага 3).** Причина — указание
    пользователя: **«ядро сейчас + бэкенды отдельно»**: уже портированный
    кусок `codegen.cpp` разбивается на логические модули сразу, а каждый
    файл бэкенда ложится **своим модулем** по мере порта (не дописывается
    в ядро). Единый `src/codegen.z` разрезан на линейную цепочку:

    | файл | строк | что |
    |---|---:|---|
    | `src/cg_zast.z` | 342 | раскладка ZAST (`H_*`/`N_*`/`CG_NODE_BYTES`), `cgBind` и чтение узлов/строк, сравнение строк (`cgStrEq*`/`cgStrIs`/`cgStrIdsEq`), слот ошибок, `cgWordSize` |
    | `src/cg_emit.z` | 2375 | байтовый эмиттер: буфер кода, GP/XMM-регистры, x86/SSE-энкодеры, метки/фикстуры, `cgSpillBase`, адресные примитивы кадра, таблицы фикстур бэкенда |
    | `src/cg_type.z` | 976 | типы (scratch-кольцо), раскладки структур, таблица переменных, свёртка кадра, `cgExprType`/`cgIsFloatExpr`/`cgCallCalleeKind`/`cgStructValueQwords` |
    | `src/cg_expr.z` | 3372 | ход по AST: эмиттеры выражений, `cgEmitExpr`, generic ABI-путь `cgEmitCallExpr`, `cgEmitStmt`, строковый пул |
    | `src/codegen.z` | 24 | фасад: только `use cg_expr` — драйверы продолжают писать `use codegen` |

    Порядок подключения — **строго одна линейная цепочка**:

    `codegen → cg_expr → cg_type → cg_emit → cg_zast`

    *Причина именно такой схемы.* `parseRun` **не дедуплицирует**
    подключённые модули, поэтому повторное `use` одного модуля в двух ветках
    (diamond) даёт `Error at line N: Duplicate function '<name>'`, причём
    **rc может быть 0** — компилируется, но в stderr мусор. Поэтому каждый
    модуль подключается ровно **один раз** во всём дереве: цепочкой, а не
    графом. Каждое ребро цепочки настоящее — это и держит её правильной:

    - `expr → type`: обход AST спрашивает типы;
    - `type → emit`: `cgSetupFunc` пишет `cgSpillBase` эмиттера;
    - `emit → zast`: `cgStrPtr`/`cgStrLen`/`cgLitEq`/`cgErrSet`/`H_*`.

    Перемещения, без которых цепочка не складывается:

    - `cgStrIs` (и `cgStrIdsEq`) уехали из среды в `cg_zast`: их вызывает
      сам ридер (`cgStrEqId`), держать их в слое типов значило бы поднять
      ребро от ZAST вверх к типам;
    - `cgWordSize` объявлен в `cg_zast`: его пишет `cgBind`, иначе слой ZAST
      зависел бы от эмиттера (цикл);
    - `cgBind` остался в `cg_zast` — он пишет и blob-состояние, и `cgWordSize`,
      и держать его выше значило бы заставить читателей blob-состояния
      подниматься вверх.

    Записываемое правило: **нельзя `use`-ить один модуль дважды.** Новый
    бэкенд подключается из фасада (или из того слоя, который его зовёт),
    ровно в одном месте.

    Проверка после разбивки: `make -f Makefile.linux test` зелёный
    (bugfind 35, irbugfind 33, JS, front 15/15, cgemit 43/43), FNV-хеши
    `src/_cgtest.z` не изменились (`5349884057702756315` /
    `4141289819001028584`).

    **Грабль:** при первой сборке у `cg_zast.z` случайно не попали строки
    22–91 (константы `H_*`/`N_*`), и **это прошло молча** — идентификатор,
    используемый только в функциях, которые оптимизатор выбрасывает до
    кодогенерации, не даёт ошибки «undefined variable». Проверять состав
    модулей нужно **покрытием строк** (каждая строка оригинала ровно один
    раз в одном из новых файлов), а не только по факту «собралось и тесты
    зелёные».

15. **Правила порта вызовов (05.10, generic ABI-путь `cgEmitCallExpr`).**

    **а) Инвокационно-локальное состояние C++.** В `emitExpr`'s CallExpr
    ветке `placedGP` / `placedXmm` / `spillBytes` — *локальные* каждой
    инвокации (codegen.cpp:5674/5686): вложенный вызов в аргументе
    (`f(a, g(x))`) обязан не трогать внешний mask выставленных аргументов и
    внешнюю глубину спилла. В `.z` эти значения обязаны быть модульными
    (их пишут `placeQwordIntoSlot` и два спилл-хелпера), поэтому
    инвокационность восстанавливается **обёрткой**:

    `cgEmitCallExpr` (save 3 значений → `cgEmitCallBody` → restore) → `res`.

    Симптом без обёртки: расхождение в `push`/`pop` и в `stackOff` стековых
    аргументов (`4889442400` против `4889442430`). То же правило ко всему,
    что в C++ живёт на стеке вызова, а в `.z` — в глобале модуля.

    **б) rel32 проверяем mask-ом, пока нет `emitFunction`.** Смещение цели
    вызова — абсолютное внутри всего code-буфера; харнесс
    `tools/cgemit_check.py` эмитит по одной функции в свежий буфер и
    проолога не выдаёт, так что rel32 совпасть не может. Харнесс печатает
    `mask=<позиции 4-байтовых релок>`, а сравнение (`find_masked`)
    требует точного совпадения **всех остальных** байтов. Когда появится
    `emitFunction` и весь TU ляжет в один буфер — маску снять и перейти к
    точному совпадению. Маскируются: `cgCallFix*`, `cgFuncRef*`,
    `cgGlobalFix*`, `cgStrFix*`, `cgKoStrFix*`, `cgElfImp*`, `cgImpCall*`, `cgHeapFix*`, `cgNetFix*`.

    **в) Страж вместо диспетчера.** `try*Call` (codegen.cpp:5506..5614)
    не портирован, и пока это так, вызов имени, которое не `extern func`,
    не нет-extern функция Zenith и не косвенный callee, даёт `cgErrSet`.
    Молчаливый прогон в generic-ветку означал бы `E8` к несуществующему
    символу — C++ попадает туда только если `try*` совпал.

    **г) Почему `try*Call` пока не свой модуль.** `try*` вычисляют аргументы
    через `emitExpr`, а `emitExpr` зовёт диспетчер → взаимная рекурсия.
    `use`-цикл в `.z` запрещён (`Error: include c_a: include cycle`), а
    diamond запрещён дупликатом функций, поэтому линейная цепочка из п.14
    не допускает разнесения этих подсистем. Два рабочих варианта:
    держать их в `cg_expr.z`, либо инвертировать ребро через
    `ptr<func(int, ptr<int>) -> int>`-hook, который ставит верхний модуль
    (синтаксис указателей на функцию работает — проверено). Выбор — при
    первом портированном `try*`, с указанием причины здесь.

    **д) Пробелы ZAST (фиксировать, а не молчать):** `selfhost/ast.z azBuild`
    не кладёт в блоб `isVirtual`/`vtable` → виртуальный диспетч
    (codegen.cpp:5890..6003) из `.z` недоступен; `mixCtx` — construct
    драйвера `--cxx`, в selfhost отсутствует; `linuxSonameFor` — хост-проба
    `.dynsym`, нужна только вне `--obj` (soname пока = `f12` = `from "…"`).

    **Проверка:** `tools/cgemit/call1.z` (20 функций: 0..8 арг, вложенные
    вызовы, float-возврат, struct-by-value на 2 и 6 слотов, косвенный
    вызов) + `expr{1,2,3}.z` → **63/63** байт-в-байт; `make -f
    Makefile.linux test` зелёный; хеши `src/_cgtest.z` не изменились.

16. **Порт `print` и «нелюксиские» эталоны (05.10, codegen.cpp:3856..4414).**

    **а) `app console` — это НЕ AppType::Console.** `selfhost/parser.z
    parseAppType()` (2587) ставит `gAppType = 8` и для `console`, и для
    `linux`, и для `gui tool`/`gui sr` — то есть ровно `AppType::Linux`.
    А `AppType::Console (=0)` в selfhost-парсере не выставляет никто.
    `codegen.cpp:8575` выставляет `isLinux=true` строго по
    `prog.appType == AppType::Linux`, поэтому **ветка `print` (`&& !isLinux`)
    недостижима в `app console`** и вообще в режиме `--obj`
    (`main.cpp:1407`: `--obj` требует `appType == Linux`).

    **б) Как тестировать `!isLinux`-ветки.** Любой appType ≠ 8, который
    дорабатывает до x86-бэкенда: `app gui dx11 tool` (→ 1, PE),
    `app efi` (→ 2, PE `.efi`), `app bios` (→ 3, flat), `app bare` (→ 4,
    flat `.bin`). В харнессе `cgIsLinux`/`cgSysvAbi` уже выводятся из
    `cgH(H_APPTYPE) == 8` — отдельного флага не нужно, достаточно исходника
    с нужной `app`-строкой.

    **в) Mode B умеет не только ELF.** `tools/cgemit_check.py` mode B
    (`-b`, файлы `*_b.z`) раньше читал только `stem+'.elf'`. Добавлен
    `pe_text_bytes()` (MZ → `e_lfanew` → `PE\0\0` → секции → `.text`) и
    `ref_image(stem)`, который пробует `stem+'.elf' / '.efi' / '.bin' / stem`
    и декодирует в сырые байты (flat-образ `app bare`/`app bios` отдаётся
    как есть). `find_masked` работает по `.text` PE так же, как по
    executable-PT_LOAD ELF: релоки (strFix/impCall/…) замаскированы,
    intra-функциональные jmp разрешены на обеих сторонах одинаково.

    **г) Порт.** `cgPrWriteStr` / `cgPrWriteRange` / `cgPrIndent` — лямбды
    C++ (`emitWriteStr`/`emitWriteRange`/`emitIndent`), вынесены в
    модульные функции `src/cg_expr.z` (в `.z` вложенных функций нет).
    Ручной rel8-патч `code[jnePos2] = size - jnePos2 - 1` →
    `var jnePos2 = cgCodeLen; ...; poke8(cgCode + jnePos2, cgCodeLen - jnePos2 - 1)`
    (адрес берётся на момент патча — `cgEnsure` может переложить буфер).
    JSON-сканер `ZJSN`-записи `netFix` эмитится **всегда**, даже когда
    `httpGetUsed == 0` (C++ выставляет `jmp notJson` и всё равно пишет
    мёртвый цикл) — из-за этого `print(int)` занимает ~1434 байта.

    **д) `http_download*` (4650..5029) — гамма CloseHandle разная.**
    `statusFailed`/`createFailed` закрывают **только** hUrl+hInternet
    (rbx — путь, а не хэндл: CreateFileA ещё не выполнялся / провалился),
    `urlFailed` — только hInternet, `readFailed`/`writeFailed` — hUrl +
    hInternet + hFile. Копирование одного блока на все ошибки даёт ровно
    +17 байт на лишний `CloseHandle` и валит все rel32 внутри функции.
    Лямбда `emitAsk` → модульная `cgDlAsk(textIdx, textLen, yesLabel,
    noLabel, declined)`; `noLabel < 0` — «declined»-путь.
    Длины промптов в байтах: `"Скачать файл? (y/n) "` = 31,
    `"Отдать почти весь канал? (y/n) "` = 51.

    **е) `;` не разделитель операторов в `.z` — и `zenith` при этом
    возвращает rc=0.** Лексер печатает `Lexer error … Unexpected character: ;`
    и пропускает символ, компилятор отдаёт 0. Внутри `cgemit_check.py.build()`
    это означало: полупарсенная программа «собралась», паритет смотрелся на
    мусоре, а `Lexer error` молча проглатывался (вывод печатался только при
    rc≠0). Правила: (1) в `.z` одна операция на строку, `;` — только внутри
    строкового литерала, комментарий — только `#` (не `//`); (2)
    `cgemit_check.py` теперь считает **любую** диагностическую строку
    (`Lexer error`, `Parser error`, `Unexpected token`, `Error…`) фатальной
    и для нашей сборки, и для эталонной.

    **Проверка:** `tools/cgemit/print1_b.z` (5 функций: строка, int, float,
    отрицательный int, `print(n)+n`) и `tools/cgemit/httddl1_b.z` (4:
    `http_download`, `_ask`, `_speed`, `…+1`) → **9/9 байт-в-байт** в mode B;
    итог по сьюту — **132 функции** (110 mode A + 22 mode B: heap1_b 9,
    net1_b 4, httddl1_b 4, print1_b 5), `make -f Makefile.linux test`
    зелёный (rc=0).

17. **Порт `http_json` и `buildHttpJsonHelper` (05.10, `codegen.cpp:5260..5505`
    + `src/httpjson_rt.cpp`).**

     **Состав.** Новый модуль **`src/cg_httpjson.z` (1053 строк)** — полный
     порт `src/httpjson_rt.cpp` (703 строки, ручной ассемблер `HJ`):
     энкодеры `hjRex`/`hjModrm`/`hjRmMem`/`hjPushR`/`hjAluImmReg`/… ,
     свободные функции `hjPutStr` (= `putStr`), `hjEmitBoundaryChecks`,
     `hjEmitFindTag`, `cgBuildHttpJsonHelper` (= `buildHttpJsonHelper`
     194..704) и врезка `cgEmitHttpJsonHelperCall` (= `codegen.cpp:5433..5446`,
     с глобалами `cgHttpJsonHelperEmitted`/`cgHttpJsonHelperLabel`).
     Ветка `http_json` (5260..5505) — в `src/cg_expr.z` (вызов
     `cgEmitHttpJsonHelperCall()` на `cg_expr.z:6006`, затем
     `mov rax,rdi` + `jmp jsDone`, как в `codegen.cpp:5447..5449`).

     **Цепочка `use` расширена на одно ребро:** `codegen → cg_expr → cg_type
     → cg_httpjson → cg_emit → cg_zast` (в `cg_type.z` добавлен
     `use cg_httpjson`; сам модуль `use cg_emit`). Всё ещё линейная цепочка,
     каждый модуль подключается ровно один раз (правило из п.14).

     **Мёртвый код не портирован:** `emitCopyFromBodyEsc`
     (`httpjson_rt.cpp:186`) в C++ имеет ноль вызывающих — в `.z` его нет.

     **Найден баг в `.z`-порте (починен):** в `hjPutStr` 2-байтовый кусок
     эмитил `B8 <2 байта>` вместо полного `mov eax, imm32` — C++
     `mov_r32_imm` всегда пишет 4 байта. Симптом: 4 сдвига `rel32`
     на 8 байт в функции. Лечено двумя `emit8(0)` после двух байт literals.

     **Найден баг в C++-эталоне (починен, НЕ повторять):**
     `src/httpjson_rt.cpp:269` — комментарий `// \\` **заканчивался
     обратным слэшем**, поэтому phase-2 (line splicing) C++ склеивал
     строку 270 (`h.e.alu_imm_reg(0, R_RBP, 2)`) с комментарием, и она
     выбрасывалась. `escQ`/`escN`/`escR`/`escT` не пострадали — их
     комментарии кончаются на `"`/`n`/`r`/`t`. Следствие: эталонный
     генератор **не сдвигал курсор после пары `\\`**, и пара затиралась
     следующим символом. Проверяется одной командой:
     `g++ -std=c++17 -E src/httpjson_rt.cpp | grep -A1 5C5C` — если после
     `mov_mem_imm16` нет `alu_imm_reg`, сплит снова сработал.
     Правка: `// \\ backslash` (последний символ — не `\`).
     **Правило на будущее: в C++ комментариях `//` не оставлять `\` последним
     символом строки.**

     **Грабль — goldens устаревают молча.** `selfhost/golden/*.dump`
     сравниваются с `@NNNN` (номер строки в конкатенированном потоке), а
     `make golden` нужно гонять после **каждой** правки `selfhost/*.z`:
     правка буфера печати 4096→16384 в `selfhost/parser.z` дала +4 к
     номерам строк и уронила `test-front` (`_parsdrv.z`, `parseobj.z`),
     хотя содержимое дампов (без `@`) не изменилось. Перегенерировано;
     сверка «что ещё изменилось» — `diff <(sed 's/ @[0-9]*//' golden)
     <(sed 's/ @[0-9]*//' new)`.

     **Проверка:** `tools/cgemit/httjson_b.z` (1 функция `j1` c `http_json`)
     → **1/1 байт-в-байт** в mode B; итог по сьюту — **133 функции**
     (110 mode A + 23 mode B: heap1_b 9, httddl1_b 4, httjson_b 1,
     net1_b 4, print1_b 5), `make -f Makefile.linux test` зелёный (rc=0).

18. **Слой 1 Linux-бэкенда: состояние + `buildLinuxImportData` (05.10).**
     Начат перенос `src/codegen_elf.cpp` (1345 строк) в `src/cg_elf.z`.

     **Новое/изменённое:**
     - `src/cg_elf.z` (новый, 681 строка): константы ELF64, образ файла
       (`cgImg*`, `cgImgPut8/16/32/64` — семантика байтов как у
       `emit16/32/64`, т.к. `v` может быть отрицательным), `cgAlignUp`,
       пустой `cgDetectLinuxNeed`, `cgComputeSectionRVAs`
       (codegen_pe.cpp:459 — цель-агностичный, дубликата для Linux нет),
       `cgPoolPtr/cgPoolLen`, `cgAddRdataStr`, `cgPutAbsPtr` и сам
       `cgBuildLinuxImportData` (codegen_elf.cpp:120..509).
     - `src/cg_emit.z`: состояние из `codegen.h` — **97 слотов `*RVA`**
       (имена с префиксом `cg`, дефолты codegen.h, отправные сентинелы
       `cgHeapOffsetRVA=0xFFFFFD00` и т.п.), массив
       `cgVkSurfaceProcsStrRVA[40]`, буферы `.rdata`/`.data`
       (`cgRData`/`cgData` + `Ensure/Push/Fill`), `cgStringOffsets[4096]`,
       `cgEntryPointCodeOffset`, `cgGlobalsSize`, таблица `cgGo*`
       (аналог `globalOffsets`, ключ — ZAST strId), **9 флагов `*Used`**
       (netSocks/sound/tls/js/vk/wl/vkSurface/disasm/httpDl).
     - Цепочка `use` получила верхний слой:
       `codegen -> cg_elf -> cg_expr -> cg_type -> cg_httpjson -> cg_emit
       -> cg_zast`. Ребро `cg_elf -> cg_expr` **настоящее**: пул строк
       (`cgStrPoolN/cgStrPoolId/cgStrPoolRaw`) и фикстуры живут в
       `cg_expr.z`, буферы и фикстуры `cgCode`/`cgGlobalFix*` — в
       `cg_emit.z`. Вариант «elf между httpjson и emit» отвергнут: там
       ребро `httpjson -> elf` было бы структурным.
     - `src/_cgtest.z`: смоук ELF-слоя с реальными ассертами (привязывает
       минимальный ZAST через `parseRun`+`cgBind`, потому что
       `buildLinuxImportData` читает `H_APPTYPE`/`H_GLOBALS`).
       Ожидаемая раскладка: `.text @0x1000`, `.rdata @0x2000`,
       `.data @0x3000`; `"hello\0"` -> `cgRDataLen=16`, `.data=24`
       (heapOffset+heapFreeHead+randSeed), `cgStringRVA=0x2000`,
       `heapOffset=0x3000`, `heapFreeHead=0x3008`, `randSeed=0x3010`,
       `heapArea=0x3018`. Ассерты проверены негативным прогоном
       (подстановка 16->17 печатает FAIL).

     **Грабли:**
     - `.z` переменная не может расти `cap *= 2` из нуля (0*2=0) —
       рост буфера обязан идти так, как в `cgEnsure` (сначала 65536).
     - Строки в пуле **двух родов**: `cgStrPoolId[i] >= 0` — ZAST strId
       (`cgStrPtr/cgStrLen`), `< 0` — сырой `.z`-литерал по
       `cgStrPoolRaw[i]` (`cgLitLen`). Читает оба `cgPoolPtr/cgPoolLen`.
     - `floor`/`sin` в `.z` — float-интринсики: работают только в
       float-позиции (`var a: float = floor(x)`). Присваивание
       `var a: int = <float>` — неявное (cvtttss2si), `int(x)` как
       каста не существует. Собственно каст не нужен: `lround`
       эмулируется `floor(x+0.5)`/`ceil(x-0.5)`.
     - `writeDQ` (codegen_elf.cpp:124) и `hasNl` (:129) в C++ объявлены и
       нигде не читаются — не перенесены.
     - `emitShaderModules` (codegen_shader.cpp) пока заглушка
       (`cgEmitShaderModules` пустая) — собственные шейдеры не портируются.

     **Проверка:** `make -f Makefile.linux test` зелёный (rc=0),
     **133/133 функции байт-в-байт**; `src/_cgtest.z` выходит с 0.

19. **Весь Linux entry-point кластер + чек целого TU в харнессе (05.10).**
     Подробный разбор — NEXT.md, раздел «05.10 (часть 3)».

     **Новое/изменённое:**
     - `src/cg_elf.z`: `cgEmitMixCrt0Call` (no-op, `mixCtx` нет),
       `cgEmitStartupRelocator`, `cgEmitLinuxExitSyscall`,
       `cgEmitLinuxExitViaLibc`, `cgEmitLinuxLibInit`,
       `cgEmitLinuxEntryPoint` — по `codegen_elf.cpp:518..630`.
     - `src/cg_zast.z`: **`cgStrSynth`** — синтетический ZAST strId.
       strId = ОФФСЕТ от `cgStrBase` (`u32 len + bytes`), поэтому
       строка, которой в программе нет, заводится буфером **после** блоба
       и возвращается как `buf - cgStrBase` — читатели не меняются.
       `cgStrSynthInit()` вызывается из `cgBind` сразу после
       `cgSynthInit()`; интернирование linear-scan'ом.
     - `src/cg_emit.z`: `cgLinuxSonameFor()` (ядро, не `cg_elf.z` — его
       зовёт и generic-путь extern-вызова `codegen.cpp:6168`); возвращает
       фоллбэк `"libc.so.6"`, DSO-проба `syslibs.cpp` — отдельный юнит.
     - `src/cg_expr.z`: закрыт дефект — extern без `from "..."`
       передавал `dllId == 0` прямо в `cgPushElfImport`, а C++ подставляет
       `mix::linuxSonameFor(call->name)`.
     - `tools/cgemit_check.py`: `pbMaskWhole()` (без `cgCallFix*`/
       `cgFuncRef*`) и плейсхолдер `@WHOLE@` — **режим B эмитит весь TU
       одним буфером** (все функции + `cgEmitLinuxEntryPoint`, когда
       `cgIsLinux`, затем `cgResolveFixups` + `cgApplyFixups`) и строкой
       `_text` ищет его в `.text` референса. `call rel32` и меточные
       переходы проверяются уже **без маски**.

     **Грабли (новые):**
     - `cgHttpJsonHelperEmitted` (`cg_httpjson.z:542`) — флажок «врезать
       `http_json`-хелпер раз на TU» (`codegen.h:521`). Второй проход
       харнуса видел `== 1` и пропускал хелпер (600 байт вместо 3232).
       Сбрасывается в `cgPerFuncReset()`.
     - `emitLinuxEntryPoint` выходит с кодом 0 всегда: `main`,
       вернувший ненулевое значение, процесс не валит (см. `_cgtest.z` —
       там `exit(1)`).
     - `cgApplyFixups(base)` патчит **меточные** переходы по
       `cgLabelPos`; `call`/`funcRef` патчит отдельный `cgResolveFixups()`
       по `funcOffsets`. Для целого TU нужны **оба**.
     - Режим A (`--obj`) целым TU проверять нельзя: референс — `.o`, где
       вход даёт ещё не портированный `emitKOEntry`, а `ref_blob` не
       собирается. Режим B подходит и для не-Linux-целей: без entry
       буфер ложится префиксом `.text`.

     **Проверка:** `make -f Makefile.linux test` зелёный (`MAKE_RC=0`),
     **17 групп / 151 функция байт-в-байт** (было 146; +5 = строки
     `_text`), `codegen-smoke src/_cgtest.z: OK`.

20. **`collectStrings` — первая половина `generateWide` (05.10).**
     Подробный разбор с полной таблицей полей ZAST-узлов — NEXT.md,
     раздел «05.10 (часть 4)».

     **Новое/изменённое:**
     - `src/cg_expr.z` (в конце файла, за пулом строк): служебная
       `cgCollectBlockStrings(start, len)` (цикл по side-списку — в ZAST
       блока как узла нет), `cgCollectExprStrings`, `cgCollectStmtStrings`,
       `cgCollectStrings`. Порядок обхода повторяет `codegen_pe.cpp:169..340`
       байт-в-байт — он задаёт номера строк в пуLE, а значит и LEA-цели.
     - `src/cg_zast.z`: `const CG_RT_DX11 = 1`, `CG_RT_VULKAN = 2`
       (`ast.h:12`).
     - `src/_cgtest.z`: блок `collectStrings` — одна программа на все
       ветки, ассерт `cgStrPoolN == 12` + `zsChk(i, lit)` на каждый
       элемент (`f1..f11` по порядку обхода, глобал `g1` последним).
       Негативный прогон подтверждён (`!= 12` → rc=1).

     **Грабли (новые):**
     - **`use` — ключевое слово Zenith** (`use codegen`): функцию так
       назвать нельзя, парсер валится в «Expected function name» ещё до
       того, как дошёл до `return`.
     - `N_PTRASSIGN` и `N_ASM` в `collectStmtStrings` в C++ **нет** —
       литерал в `*p = "s"` в пул не попадает. Счётчик из 12 ровно и
       ловит это расхождение; лишний даже «правильный» по духу код
       поехал бы всем номерам дальше.
     - `cgH(H_RENDERTYPE) == 1` (DX11): в эталоне **перед** обходом
       в пукладывают 16 байт IID, `"main"`, `"vs_5_0"`, `"ps_5_0"`,
       `"POSITION"` и пути `dxDiagPath(kDxDiagFiles[i])`. Это слой 2
       (`codegen_dx11_shaders.cpp`), поэтому — громкий `cgErrSet`, а не
       тихое расхождение.
     - `cgCollectStrings()` в харнесс пока **не вносим**: иначе
       `app gui dx11` программы режима B начнут падать на этом `ErrSet`.

     **Проверка:** `make -f Makefile.linux test` зелёный (`MAKE_RC=0`),
     **17 групп / 151 функция байт-в-байт**, `codegen-smoke src/_cgtest.z: OK`.

21. **`buildELF` + `generateWide` (Linux-ветка) — весь путь до готового
     образа (05.10).** Подробный разбор — NEXT.md, раздел
     «05.10 (часть 5)».

     **Новое/изменённое** (всё в `src/cg_elf.z`, конец файла):
     - `cgImgPadTo`/`cgImgAppendStr` — рост буфера образа;
     - `cgCheckFixupOverlaps` + `cgOvListN`/`cgOvListPos` + `cgOvItem[65536]`
       (`codegen_pe.cpp:350`), 10 списков фикстур;
     - буферы `cgEl*`/`cgGot*`, `cgElfHash`, `cgElfPatchDisp`;
     - **`cgBuildELF()`** (`codegen_elf.cpp:631..1040`) — GOT →
       `.dynstr`/`.dynsym`/`.rela`/`hash` → layout → ehdr/4 phdr →
       сборка файла → `kZenithMagic`;
     - **`cgFreshState()`** (`codegen.h:477..484`, `:840..843`) — сброс
       всех членов `Codegen` для реентерабельности;
     - **`cgGenerateWide()`** (`codegen.cpp:8565..8829`) — Linux-ветка:
       `freshState` → `cgIsLinux/cgSysvAbi` из `cgH(H_APPTYPE)==8` →
       `computeStructLayouts` → `collectStrings` → `computeSectionRVAs`
       → `buildLinuxImportData` → цикл функций → `emitLinuxEntryPoint`
       → `emitStartupRelocator` → `fixupSectionRVAs` → `resolveFixups`
       → `applyFixups(0)` → поздние строки → `buildELF()`.
     - `else if` в цепочках `cgOvListN`/`cgOvListPos` и в выборе бакета
       SysV `.hash`.
     - `Makefile.linux`: цель `test-cgimg` (входит в `test`);
       `tools/cgimg_check.py`, `src/_cgimg.z`.

     **Три бага, найденных только побайтовой сверкой:**
     - shell sort в `checkFixupOverlaps` заканчивался `j = 0` вместо
       break → `cgOvItem[j] = v` затирал нулевой элемент, массив
       становился мусором и сыпал ложные «overlapping fixups» (лечится
       флагом `done`);
     - GOT-цикл: `cgDataFill(0,8)` внутри цикла росил `cgDataLen`, и
       слот получал `dataBase + 2*i*8` (первый совпадал, дальше +8 за
       слот) — симптом: единственное расхождение `r_offset` во второй
       записи `.rela`. Лечится `var gotBase: int = cgDataLen` до цикла;
     - сверяться надо с `build/linux/zenith <src> --no-opt`: эталонный
       `optimizer.cpp` в selfhost ещё C++ (через `zffi_optimize`), и его
       проход убирает неиспользуемые глобалы, меняя `dataSize`.

     **Грабли (новые):** `print(x)` в selfhost = `println`, а
     `print(intPtrVar)` печатает число, не строку; `zffi_writeFile`
     NUL-terminated → дамп ELF в файл невозможен (диагностика — выводом
     фиксированных полей/слотов и чанковыми хешами); `pow2()` в `.z`
     нет; `cgPerFuncReset()` — только харнессовый, в `generateWide`
     не нужен; `detect*Usage()` в C++ пока не вызывается откуда-либо.

     **Следующий блокер:** `cg_expr.z:7135` отвечает ошибкой на любой
     системный билтин в `app linux` — не портирован
     `codegen_builtins_linux.cpp` (`tryLinuxCall`, 814 строк) и
     вся диспетчерская `try*Call`.

     **Проверка:** `make -f Makefile.linux test` зелёный (`MAKE_RC=0`),
     **17 групп / 151 функция байт-в-байт**, `codegen-smoke
     src/_cgtest.z: OK`, **`codegen-image src/_cgimg.z: OK`**
     (imgA 12722 байта, imgB 8222 байта — байт-в-байт с эталоном).

22. **Директива 05.10 (вечер): selfhost → ТОЛЬКО СИСКОЛЛЫ + два
     параллельных агента на `src/`.** Подробности — NEXT.md, раздел
     «05.10 (часть 6)». **ВЫПОЛНЕНО 10.10 (часть 21)** — итоги и грабли
     в NEXT.md, раздел «10.10 (часть 21)»: импорты/GOT/PT_INTERP/
     DT_NEEDED запрещены (`phnum = 2`), Vulkan — через собственный
     mini-dlopen в `cgEmitVkLoader` + 65 стабов libc (без libc/libm/ld),
     `NODE_CAP` 131072 → 262144, смоук `vkrun.z` rc=0 (вывод побайтово
     с динамическим эталоном), `make test` → `MAKE_RC=0`, 259 `OK` +
     23 `match`, новая цель `cgfront vk` (рантайм-паритет) в
     `tools/cgfront_check.py`. Контракт ниже — исторический (для дня
     запуска директивы).

     - **Что:** переписать всё в selfhost так, чтобы генерируемые
       программы работали исключительно на сырых syscall — без libc,
       без динамического загрузчика (`PT_INTERP`/`DT_NEEDED`/GOT).
       Точки: extern-путь `cgEmitCallBody` (`cgPushElfImport`),
       ветка `if cgElfImpN > 0` в `cgBuildELF` (тогда `phnum = 2`
       всегда), `emitLinuxExitViaLibc` → только `emitLinuxExitSyscall`.
     - **Кто:** `src/*.cpp`/`src/*.h` — два параллельных агента;
       `src/*.z`, `tools/cg*.py`, `Makefile.linux`, `NEXT.md`/`PLAN.md` —
       я. `src/main.z` общий, правки согласовывать. Порядок `use`
       линейный, новые модули — только в конец.
      - **Контракт:** `timeout 1800 make -f Makefile.linux test` →
        `MAKE_RC=0`, **20 групп / 198 функций байт-в-байт** +
       `codegen-smoke src/_cgtest.z: OK` +
       `codegen-image src/_cgimg.z: OK` (**5 контейнеров: img1/img2
       `.elf`, img3 `.so`, img4 `.o`, img5 `.ko`**). Смена кодогена C++ →
       пересчёт эталонных хешей в `_cgtest.z` и len/FNV64 в
       `tools/cgimg_check.py`.

     **Сделано сегодня (в дополнение к п.21):**
     - `cgTryLinuxCall` в `src/cg_expr.z` — **ветка печати**
       (`print`/`println`/`eprint*`, строки и int) по
       `codegen_builtins_linux.cpp:28..254`, включая включение в
       `cgEmitCallBody` вместо ошибки «backend builtin dispatch not
       ported». Ветка float и `sleep`/`halt`/`exit`/`mem*` ещё не
       портированы (громкий `cgErrSet`).
     - Тест `tools/cgemit/linprint_b.z` (режим B — **единственный**, что
       реально проверяет `tryLinuxCall`; режим A форсирует
       `cgKoDriverFlag = 1` и уходит в `tryKOCall`): **9/9 byte-identical**,
       включая `_text`. Найден баг `emitJcc` vs `emitJccLit` (id
       строковой таблицы вместо литерала → молчаливый JE), записан в
       «Грабли».
     - Важно: **режим A харнесса форсирует `cgKoDriverFlag = 1`** →
       C++ зовёт `tryKOCall`, а не `tryLinuxCall`; печать проверяется
       только режимом B.
     - **05.10 (часть 7): `tryLinuxCall` ЗАКРЫТ** — доделаны float-ветка
       печати, `halt`, `exit`/`exit_process`, `memNew`/`memDel`/`memByte`/
       `memQ`/`memByteW`/`memQw` (`cgLinMemRead`/`cgLinMemWrite`).
       `sleep` в `cgTryLinuxCall` не портирован: он мёртв и в C++, и в
       selfhost (общий arm `codegen.cpp:3740` возвращает раньше
       диспетчера). Тест `linprint_b.z` → **16/16 byte-identical**.
     - **НОВАЯ ГРАБЛЬ:** сплайс `_cgtest.z` переполнил токенный кап
       selfhost-лексера (`TOK_CAP 131072`, `expandUseDirectives` склеивает
       всю `use`-цепочку в один буфер → `parseRun` один раз). Поднято до
       **524288** в `selfhost/lexer.z` (+ `gToks`), дальше обязательно:
       `make bootstrap-parseobj bootstrap-lexobj` → `make` → **`make golden`**
        (без него падает `test-front`). Подробности — NEXT.md, «часть 7».
      - **05.10 (часть 8): `tryKOCall` ЗАКРЫТ** — диспетчер
        `cgEmitCallBody` теперь зеркалит `codegen.cpp:5510`: KO-ветка
        стоит **перед** `tryLinuxCall` и охранена `cgKoDriver()`.
        Перенесены printk-семейство, `rdtsc`/`io_delay`/`outb`/`inb`,
        `peek*`/`poke*`, `kalloc`/`alloc`/`kfree`/`free`, `kzalloc`,
        `ktime_ms`/`ktime_ns`/`jiffies`; добавлены ko-фикстуры
        (`cgKoExtCall*`, `cgKoDataFix*`) и хелперы `cgKoLoadFmt`/`cgKoCall`.
        Тест `tools/cgemit/ko1.z` (режим A) → **20/20 byte-identical**.
         Пойман баг: `emit32(0xCC0)` был записан как `emit32(2240)` —
         константы теперь только в hex. Подробности — NEXT.md, «часть 8».
      - **05.10 (часть 9): Vulkan ЗАКРЫТ** (директива №6,
        `codegen_vulkan.cpp`) — перенесены обе половинки: detect-обход
        `detectVkUsage`/`detectVkSurfaceUsage` (`src/cg_elf.z`,
        хуки в `generateWide` перед `cgBuildLinuxImportData`) и эмиттер
        `cgTryLinuxVulkanCall` (`src/cg_expr.z`, 9 веток) + заглушка
        `cgTryLinuxGUICall → 0`; диспетчер теперь четыре зелёные ветки.
        Хелпер `cgStrHasPrefix` — в `src/cg_zast.z`. Тест
        `tools/cgemit/vk1_b.z` (режим B — Vulkan идёт через GOT/DT_NEEDED,
        в режиме A такого пути нет) → **11/11 byte-identical**, включая
        whole-TU `_text`. Поймана грабль: `callRipSlot` не писал позицию ни
        в один список фикстур → слот не маскировался харнессом; фикс —
        `cgPushGlobalFix(pos, slotRva)` (байты не меняет, `patchDisp` в
        `buildELF` перепишет те же 4 байта той же формулой). Подробности —
        NEXT.md, «часть 9».
     - **05.10 (часть 10): `.so` и `.ko` ЗАКРЫТЫ** (директива №5,
       «динамические `.so` и `.ko` — в селфхомт сделать полностью») —
       портированы `cgBuildELFLib` (`codegen_elf.cpp:1040..1345`,
       `ET_DYN`, phnum=3, export-имена в `.dynstr`, `.hash` по всем
       dynsym, `DT_INIT`) и `cgBuildKO` (`codegen_ko.cpp:207..682`,
       `ET_REL`, symtab/strtab/shstrtab/rela, koNeeded, `--obj`-ветка
       `SHT_NOBITS`), трамплины `cgEmitKOEntry`/`cgEmitKOObjInit`,
       `cgCollectExportEntries`, константы `CG_ET_REL`/`CG_SHT_*`/
       `CG_R_X86_64_*`, и рефакторинг `cgGenerateWide` ровно по
       `codegen.cpp:8672..8831` (ветки lib/koDriver/обычный +
       `if (koDriver) { buildKO(); return; }` после `fixupSectionRVAs()`).
       Харнесс `src/_cgimg.z` расширен до **5 контейнеров**
       (`tools/cgimg_check.py`, per-case эталон: `.elf`/`.so`/`--obj`→`.o`/
       driver→ET_REL в `$TMPDIR/zenith_ko_1` со стенд-ин gcc). Появились
       `src/_cgdbg.z` + `tools/ko_diff.py` — восстанавливают байты `cgImg`
       из префиксных FNV и показывают первый отличающийся байт. Поймана
       грабль: сортировка вставками в `buildKO` писала `kOff` в index 0
       (5 relas → `[237,75,230,230,237]`). Известные отклонения: порядок
       `std::unordered_set` в `--obj` не воспроизведён (контейнеры с ≥2
       extern'ами в тест не входят); shell-часть `buildKO`
        (modpost/gcc/ld, `:684..826`) не портирована — selfhost-кодоген не
        имеет I/O, драйвер отдаёт сборку C++-бэкенду. Подробности —
        NEXT.md, «часть 10».
     - **05.10 (часть 11): `tryLinuxNetCall` ЗАКРЫТ** — портированы
       `detectNetSockExpr/Block/Stmt/Usage` (`codegen_net.cpp:36..99`)
       в `src/cg_elf.z` (вызов в `cgGenerateWide` **перед**
       `detectVkUsage`/`buildLinuxImportData`, как в
       `codegen.cpp:8645..8656`) и весь `cgTryLinuxNetCall` с хелперами
       (`codegen_net_linux.cpp:31..569`) в конец `src/cg_expr.z`; в
       `cgFreshState` добавлен выход детекта `cgNetSocksUsed = 0`.
       Общие хелперы `cgVkLeaRip`/`cgVkGuard`/`cgVkMovToR12`/`cgVkSetNeg1`
       переиспользованы Vulkan-портом. Пойманная ошибка: в
       `net_tcp_send/recv`, `net_udp_recv` C++ после pops делает
       `4C 89 D8` (`mov rax, r11`) — пропустил, фикс
       `cgNetFinishRestoreR11`; в `net_udp_send` его нет и в эталоне.
       Тест `tools/cgemit/net_linux1_b.z` — 14/14 (режим A), 15/15
       (режим B, whole-TU `_text`). Контейнерный харнесс расширен до
       **6 контейнеров**: `srcF` в `src/_cgimg.z` (единственный с
       `cgNetSocksUsed=1`, четыре слота `.data`). ГЛАБНАЯ грабль юнита:
       selfhost-парсер **не сбрасывал конфигурационные глобалы** в
       `parseRun` (в C++ `Parser::parse()` строит свежий `Program prog;`
       на каждый вызов) — липкий `gKoDriver` после img5 (`app linux
       driver`) уезжал в `H_FLAGS & CGF_KODRIVER` и img6 собирался как
       ET_REL; фикс — `resetProgConfig()` (24 дефолта из `ast.h:274..310`).
       Вторая грабль: новая функция в `.z` ломает `test-front` → нужен
       `make golden` (дампы — авторитет C++-фронтенда). Подробности —
       NEXT.md, «часть 11».

     - **05.10 (часть 12): `codegen_httpdl.cpp` ЗАКРЫТ** — портированы
       `isHttpDlName`/`detectHttpDlExpr/Stmt/Block/Usage` (`:29..102`) в
       конец `src/cg_expr.z`, `emitHttpDlBlob` (`:108..123`) в новый
       модуль `src/cg_httpdl_blob.z` (`use cg_httpdl_blob` после `use
       cg_type`) и весь `tryHttpDlCall` (`:125..277`) в конец
       `src/cg_expr.z` + ветка в диспетчере сразу после
       `cgTryLinuxNetCall` (codegen.cpp:5524). Вызовы в
       `cgGenerateWide`: `cgDetectHttpDlUsage()` между `cgDetectNetSockUsage`
       и `cgDetectVkUsage`, `cgEmitHttpDlBlob()` (guard `cgHttpDlUsed &&
       cgLibOutput==0`) **перед** `cgFixupSectionRVAs`; в `cgFreshState`
       — сбросы `cgHttpDlUsed`/`cgHttpDlBlobEmitted`/`cgHttpDlEntryLabel`.
       **Байты blob'а (477784) вшиты в 8 строковых литералов по 64 КиБ** —
       для этого подняты капы `STR_CAP` 262144→4194304 (`selfhost/lexer.z`)
       и `STR_CAP_AST` 2097152→4194304 (`selfhost/ast.z`); доказано, что
       весь конвейер сохраняет NUL внутри литерала (лексер — `slen=w`,
       парсер `tokStr` копирует по длине токена, C++ `t.text.assign(p,tl)`).
       Генератор `tools/gen_httpdl_blob_z.py` (chunk 65536, экранирование
       `\0 \t \n \r \" \\`) пишет `src/cg_httpdl_blob.z`; добавлен
       bulk-эмиттер `cgCodeAppend(p,n)` в `src/cg_emit.z`.
       Тест **img7** в `src/_cgimg.z` + `tools/cgimg_check.py` (7-й
       контейнер, plain ELF): `len=491550 h=-3185870257842899445 OK`.
       cgemit-тест **намеренно НЕ добавлен**: режим A не видит
       `cgLabelPos[entry]` (blob не эмитится), а `cgFixPos` не входит в
       маску `pbMask`; режим B упирается в капы печатных буферов
       (16384 в `pbLit`, 8192 в `gTmp`) на ~962-КБ hex-строке. Подробности
       — NEXT.md, «часть 12».

     - **05.10 (часть 13): `codegen_wl_linux.cpp` ЗАКРЫТ** — портированы
       `detectWLExpr/Block/Stmt/Usage` (`:38..96`) и весь
       `tryLinuxWLCall` с хелперами `cgWlLeave`/`cgWlDecWrite`
       (`:104..444`) в конец `src/cg_expr.z`; ветка в диспетчере сразу
       после `cgTryHttpDlCall`. Отличия детекта от net/httpdl зеркалим
       дословно: **Unary обходится через `f1`** (не `f0` — там id
       оператора), Assign/Switch **отсутствуют**, имя — по префиксу
       `wl_`. `cgDetectWLUsage()` в `cgGenerateWide` — между
       `cgDetectVkUsage` и `cgDetectVkSurfaceUsage`; `cgWlUsed = 0` в
       `cgFreshState`. `leaRip`/`svc` переиспользуют `cgVkLeaRip`/
       `cgNetSvc`. Шесть оконных билтинов (`wl_create_window` и др.)
       уходят в не портированный `tryLinuxWLWindowCall`
       (`codegen_wl_window.cpp`, 773 строки) — ветка пока не написана,
       поведение как до юнита. Тест **img8**: `len=16914
       h=-1404876951840641508 OK`. Подробности — NEXT.md, «часть 13».

     - **05.10 (часть 14): `codegen_shader.cpp` + `spvasm.cpp` ЗАКРЫТЫ**
       — SPIR-V в selfhost. Таблицы опкодов/енумов выгружены генератором
       `tools/gen_spvtab_z.py` в **`src/cg_spvtab.z`** (83 опкода, 124 енума,
       15 result-first; `cgSpvEnumVal` — порядок обязателен, `Uniform` → 2,
       а не 26). Новый модуль-**лист** **`src/cg_shader.z`** (888 строк,
       `use cg_spvtab`): ассемблер (`tokenize`/`pass1`/`pass2`/`assemble`,
       `parseString`/`parseHex`/`parseDec`), `cgDetectShaderExpr/Block/Stmt/
       Usage`, `cgRegisterShaderCall`, `cgEmitShaderModules`,
       `cgTryShaderCall`. Лимиты — жёсткие литералы в типах (константы
       размера массива `.z` не читает): 4096/512/4096/4096/16384/8192/64.
       Ветка в диспетчере — сразу **после** `cgTryLinuxWLCall`;
       `cgDetectShaderUsage()` в `cgGenerateWide` — **между
       `cgDetectWLUsage` и `cgDetectVkSurfaceUsage`**; `cgShaderUsed`/`cgShN`
       в `cgFreshState`; стаб `cgEmitShaderModules()` из `cg_elf.z` удалён
       (иначе Duplicate function). **`shader_file` не читает файлы**
       (`zffi_readFile` только в `main.z`) — падает как C++ при отсутствии
       файла; **`tryShaderCall` без общего выходного шаблона** (C++
       не трогает `regsUsed`, `cgLinResReg` может быть −1). Пойманная
       ошибка порта: `cgCallArg` возвращает **узел**, strId у `N_STRING` —
       в **`f0`** (иначе SIGSEGV в `cgSpvSplitLines`). Тест **img9**:
       `len=12318 h=-1251378926652827548 OK`. Подробности — NEXT.md,
       «часть 14».

     - **05.10 (часть 15): `codegen_wl_window.cpp` ЗАКРЫТ** — окно и
       shm-фреймбуфер. Лямбды C++ вынесены в `cgWw*`-функции в конце
       `src/cg_expr.z` (`cgWwOut32/OutReg32/OutHeader`, `cgWwWriteOut/
       WriteLen/WriteOutCheck/WriteOutFd`, `cgWwLeaEvent`,
       `cgWwMovToR12/R13/R14`); `cgTryLinuxWLWindowCall` перенесён
       построчно (механический конвертер, правка только байтовым
       паритетом). Вызов — **изнутри** `cgTryLinuxWLCall`, ДО
       `isWLBuiltin`, как в `codegen_wl_linux.cpp:110..113`. Раскладка
       `.data`/`.rdata` не менялась (слоты уже были). Тест **img10**:
       `len=16914 h=-2520265942535671238 OK`.

      **ГРАБЛЬ (перекрёстный):** в 20:36 другой агент дописал в
      `src/codegen_elf.cpp` `argc/argv` в `_start` (+12 байт) и пересобрал
      `build/linux/zenith` — `make test` стал красным **по всем** img, хотя
      длины совпадали (выравнивание `.text` маскирует +12). Портировали их
      правку в `src/cg_elf.z` (9 `emit8` после `cgEmitMixCrt0Call()`);
      локализовали временным `src/_cgdiag.z` (дамп `@offset:hex`, первое
      расхождение 0x119c). Алгоритм и вывод — NEXT.md, «часть 15».

     - **05.10 (часть 16): семейство `detect*Usage` ПОРТИРОВАНО + img11**
       — пять обходчиков из `codegen.cpp:8646..8656` (`Network`,
       `Sound`, `Tls`, `Js`, `Disasm`) со всеми `*ExprUsage`/`*Block`/
       `*Stmt` и хелперами имён; **633 строки** в `src/cg_expr.z`,
       подключены в `cgGenerateWide` (`src/cg_elf.z:3398..3408`) в
       C++-порядке. В `cgFreshState` — сбросы `cgHttpGetUsed`,
       `cgSoundUsed`, `cgTlsUsed`, `cgJsUsed`, `cgDisasmUsed` **и
       `cgVkUsed`** (последний выставлялся, но не сбрасывался). Тест
       **img11** (`srcK`, звук): `len=13858
       h=5303463847172874656 OK`, харнесс `src/_cgimg.z` и
       `tools/cgimg_check.py` расширены до **11 контейнеров**.

       **Два пойманных бага (NEXT.md, «часть 16»):** (1) builtin `sin`
       — x87 `fsin` поверх float32, а эталонная LUT — `std::sin` в
       `double`: одно расхождение на i=462, таблица зашита литералом
       `cgSoundLutAppend()` (`tools/gen_soundlut_z.py`, маркеры BEGIN/END
       в `src/cg_elf.z`); (2) **главный** — локальный `chain: [4096]int`
       в `cgBuildELF`/`cgBuildELFLib` не инициализируется, а `chain[0]`
       читается в эмиттере `.hash` (в C++ это `std::vector` = нули) →
       мусор со стека предыдущего контейнера попадал в `chains[0]`.
       Ловится только многосборочным харнессом (бисект: ломает img7);
       лечение — заливка `chain[0..nsym-1]=0`, оба сайта.

     - **09.10 (часть 17): `tryDisasmCall` + disasm-блоб ПОРТИРОВАН + img12**
       — `src/cg_disasm_blob.z` (29432 байта `kDsBlob`, entry `0x6230`,
       генератор `tools/gen_disasm_blob_z.py`, чанки по 8192) + `cgTryDisasmCall`
       и хелперы `cgDs*` в `src/cg_expr.z` (диспетч `codegen.cpp:5610`:
       Linux + X86_64 + `!koDriver`), вызов `cgEmitDisasmBlob()` в
       `src/cg_elf.z` после httpdl-блоба и до `cgFixupSectionRVAs`/
       `cgResolveJmpFixups` + сбросы `cgDisasmBlobEmitted`/`cgDisasmEntryLabel`
       в `cgFreshState`. Тест **img12** (`srcL`: `disasm` с 5/6/7 аргументами,
       `disasm_one`, `alloc`/`free`): `len=36894
       h=-7805999705305791640 OK`, харнесс `src/_cgimg.z` и
       `tools/cgimg_check.py` расширены до **12 контейнеров**.

       **Два пойманных бага (NEXT.md, «часть 17»):** (1) выравнивание
       `.text` перед disasm-блобом в C++ — `emit8(0)`, а не NOP (NOP
       укрался из httpdl-блоба; длина и структура при этом совпадают,
       отличаются ровно N байт padding'а); (2) **главный** — все 21 место
       `cgPushHeapFix` пушат sentinel-константу `0xFFFFFF00`/`0xFFFFFE00`/
       `0xFFFFFD00`, тогда как C++ везде пушит **переменные** `heapAreaRVA`
       и т.п. (уже посчитанные: `buildImportData()` идёт до emit-цикла),
       а цикл резолюции sentinel'ов (`codegen_elf.cpp:502..504`) мёртв —
       идёт раньше появления фикстур. Итог: `disp32` ведёт в `0x3FFF00`
       вместо `0xA000`, ровно 38 байт в `.text`; ломается только контейнер
       с реальным `alloc`/`free` (img12 — первый такой).

     - **09.10 (часть 18): `tryTlsCall` + TLS-блоб ПОРТИРОВАН + img13**
       — `src/cg_tls_blob.z` (генератор `tools/gen_tls_blob_z.py`, чанки
       по 8192, 113272 байта `kTlsBlob`, entry `0x7680`, выравнивание
       **NOP `0x90`** — как httpdl, но не как disasm) + `cgTlsGuard`,
       `cgTlsEntryCall`, `cgEmitTlsIoInit`, `cgTryTlsCall` в
       `src/cg_expr.z` (диспетч `codegen.cpp:5593`, **до** js и disasm) +
       хук `cgEmitTlsBlob()` в `src/cg_elf.z` в **C++-порядке**
       (`codegen.cpp:8711`: tls → httpdl → js → disasm, tls ПЕРЕД
       httpdl) + сбросы `cgTlsBlobEmitted`/`cgTlsEntryLabel` в
       `cgFreshState`. Тест **img13** (`srcM`: `tls_connect` литералом и
       через обёртку-параметр ради inline-`strlen`-ветки, `tls_send`,
       `tls_recv`, `tls_close`, `tls_last_error`): `len=122918
       h=8704592932605507178 OK`; `src/_cgimg.z` и `tools/cgimg_check.py`
       расширены до **13 контейнеров**.

       **Пойманный баг (NEXT.md, «часть 18») — самый дорогой:**
       `edit`-инструмент Unicode-ом правил `src/cg_elf.z`, который **не
       UTF-8** (литерал sin-LUT в `cgSoundLutAppend` содержит сырые
       `0x92`…): 455 байт превратились в U+FFFD. Симптом — img11
       (звук) упал спустя три юнита после зелёной проверки, **с той же
       длиной и другой суммой**. Лечение: `python3
       tools/gen_soundlut_z.py`. Правило: `cg_elf.z` и все
       `cg_*_blob.z` править только bytes-путём
       (`errors="surrogateescape"`).

       **Грабли:** `loop` — зарезервированное слово (`TLoop`), вместе с
       `from` список растёт; `tlsFixups`/`importCallFixups` на Linux
       **не резолвятся** (их патчит только `buildPE`), `disp32` нулевой
       в обеих сторонах.

     - **09.10 (часть 19): `tryJsCall` + JS-блоб ПОРТИРОВАН + img14**
       — `src/cg_js_blob.z` (генератор `tools/gen_js_blob_z.py`, чанки
       по 8192, 189816 байт `kJsBlob`, entry `0x2AD00`, **bss-pad
       17633128 нулей** → контейнер на 17.9 МБ, выравнивание блоба
       **нули**, 14 Linux-слотов `kJsHostLinux`) + `cgJsGuard`,
       `cgJsEntryCall`, `cgTryJsCall` в `src/cg_expr.z` (диспетч
       `cg_expr.z:7219`, между tls и disasm, `cgKoDriver() == 0`) +
       хук `cgEmitJsBlob()` в `src/cg_elf.z` в **C++-порядке**
       (`:8711` → комментарий `:3450`: tls, httpdl, js, disasm) +
       сбросы в `cgFreshState`. Фикстура **img14** (`srcN`: `js_reset`,
       `js_eval` литералом и через обёртку `runJs(code)`, `js_result`,
       `js_error`): `len=17949726 h=-4845514970219923369`;
       `src/_cgimg.z` и `tools/cgimg_check.py` расширены до **14
       контейнеров**.

       **Пойманный баг юнита — bump-хип против libc heap:**
       `alloc()` в Zenith для Linux-таргета эмитит **bump-хип в `.bss`
       эмитируемой программы (64 МиБ, `codegen.cpp:3022`)**, а не
       malloc; рост `cgImg` до 33.5 МиБ под js-блоб упирался в потолок
       (`alloc(33554432)` → `0`), а сумма шагов удвоения ≈ 67 МиБ
       съедала кучу сама по себе. Лечение: буферы кодогена переведены
       на `extern func realloc` (`src/cg_emit.z`) — `realloc(0,n)` =
       malloc, `realloc(p,n)` копирует и освобождает сам, ручные
       `cgCopyBytes`+`free` выкинуты из пяти `*Ensure`; паритет не
       задет, буферы живут только внутри драйвера. Вторая беда:
       **`eprintln(число)` → SIGSEGV** (работает только `println(int)`)
       — диагностика маскировала OOM. Третье: временные `println(N)`
       ломают `cgimg_check.py` (все `len` читаются как `100`, хеши
       совпадают) — 20 штук снято перед финалом.

       **Грабли:** `free` нельзя переопределить extern'ом (builtin,
       `codegen.cpp:3076`, проверяется раньше `extern func`); блоб-пейдинг
       у каждого свой — disasm/js = нули, httpdl/tls = NOP; в
       `_cgimg.z` остаются безобидные `[ZT-BUG016]`/`[ZT-BUG002]`
       предупреждения багчекера (4 шт.).

     - **09.10 (часть 20): фронтенд в без-libc ELF — `_lexdrv`,
       `_astdrv`, `_parsdrv`** — цель `test-cgfront` (входит в `test`),
       чекер `tools/cgfront_check.py`: пара путей REF
       (`build/linux/zenith --no-opt`) и SELF (харнесс `src/_cgfront.z`,
       сплайс `srcprep_dump` → `parseRun` → `cgBind` →
       `cgGenerateWide()`), сверка `(len, FNV-64)` + запуск обоих
       `.elf` + статичность артефакта (2 program headers, нет
       PT_INTERP/PT_DYNAMIC: `write(1)`, `exit_group`, bump-хип в
       `.bss`). Новый драйвер `selfhost/_lexdrv.z` (34 токена, пассивный
       прогон с ошибкой лексера, `ZLEX toks=/errs=`), golden
       `selfhost/golden/selfhost__lexdrv.dump` → 16 `front-end … match`.

       **Пойманный баг главный — дубликат глобала last-wins против
       first-wins:** `gStrUsed` объявлен и в `selfhost/lexer.z:126`, и в
       `selfhost/ast.z:126`; C++ (`codegen_elf.cpp:492`) перетирает
       `std::unordered_map` **последним**, порт пушит все и `cgGoFind`
       берёт **первого** → ссылки AST шли в слот лексера, дельта ровно
       944 байта (93 якоря подряд, длина идентична). Лечение в
       `src/cg_elf.z` (цикл раскладки глобалов): `gof = cgGoFind(...)`,
       найден → перетереть `cgGoOff[gof]`, иначе append. Правка —
       bytes-путём (файл не UTF-8).

       **Инцидент:** `src/cg_elf.z` (untracked в git) обнулён параллельным
       агентом в 18:36, восстановлен реплейом из `opencode.db`
       (`part.data` со всеми вызовами инструментов); после — 3609 строк,
       0x92 cp1251 на месте, U+FFFD нет.

       **Грабли:** фиксированные пути IN/OUT гоняются с параллельным
       `make all` (эталон временно удалён → «нет эталона», гонка за
       `cgfront_out.elf` → `FileNotFoundError`) — перегонять при пустом
       `pgrep Makefile.linux`; порт `src/cg_*.z` не в git — обнулённое
       восстанавливать только из `opencode.db`.

      **Проверка (финал дня):** `timeout 2400 make -f Makefile.linux
      test` → **`MAKE_RC=0`**, **0 MISMATCH**, `codegen-smoke
      src/_cgtest.z: OK`, `codegen-image src/_cgimg.z: OK`
      (**img1..img14, 14 контейнеров**), `codegen-front
      selfhost/lexer+parser+ast: OK` (3 драйвера, 37919142/40268766/
      37786686 байт), **268 `OK`/`match`**, 16 `front-end … match`,
      `codegen-parity(b) tools/cgemit/net_linux1_b.z: OK`; U+FFFD по
      `src/*.z` — пусто. Закрыты все три Linux-эмиттера:
      `tryDisasmCall` (часть 17), `tryTlsCall` (часть 18),
      `tryJsCall` (часть 19) и **фронтенд-драйверы (часть 20)**.
      Следующий шаг — **директива «только syscall»** → порт оптимизаций
      → слой 2 с WinPE. (Директива закрыта **10.10, часть 21** — см. п.22
      и NEXT.md; следующий — порт оптимизаций, затем `.ko` и `zenite`.)
