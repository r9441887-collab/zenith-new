# NEXT_STEPS.md — план на завтра (создан 2026-10-02, ночь)

## 0. Где остановились (короткий статус)

Миграция «лексер компилятора → selfhost» почти закончена:

- [x] `selfhost/lexer.z` — полный порт `src/lexer.cpp` (сообщения об ошибках,
      `lexNext`, аксессоры `lexKindAt/lexLineAt/lexColAt/lexIntAt/lexFloatAt/
      lexTextPtrAt/lexTextLenAt` для C++).
- [x] `selfhost/lextool.z` + `tools/lextool_main.cpp` → бинарь `tools/lextool`
      (собран, работает: читает `ZT_LEX_SRC`, пишет dump `ZTLX` в `ZT_LEX_OUT`).
- [x] `src/lexbridge.cpp` — `lexSource(src, out, err)`: спавнит lextool
      (ищет через `ZT_LEXTOOL` → рядом с exe `/proc/self/exe` → `tools/lextool`
      → PATH), времники в /tmp, парсит dump в `vector<Token>`.
- [x] `src/lexer.h` — объявлена `lexSource(...)`; class Lexer оставлен (нужен
      только эталону).
- [x] `src/main.cpp` — 3 сайта (`~891, ~1085, ~1388`) переведены на lexSource;
      `tools/bugfind_test.cpp` (~468) тоже.
- [x] `git mv src/lexer.cpp → selfhost/reference/lexer.cpp`; include в нём
      поправлен на `../../src/lexer.h`; `selfhost/lexref.cpp` включает
      `reference/lexer.cpp`.
- [x] `Makefile.linux`: `all: $(BIN) $(LEXTOOL)`, правило регенерации
      `tools/lextool`, bugfind_test линкует `src/lexbridge.cpp` вместо
      `src/lexer.cpp`, тесты зависят от `$(LEXTOOL)`.
- [x] Полная пересборка компилятора проходит; регенерация lextool новым
      компилятором работает; `lexdiff` — **ALL OK, 30 cases, 12371 токен**;
      compile из произвольного cwd работает (exe-relative поиск); oop_smoke=0.

## 1. ГЛАВНЫЙ БЛОКЕР: `make test` падает на кейсе bugfind 013

```
FAIL 013 float-precision-cmp   missing ZT-BUG013 (got ZT-BUG002)
```

**Root cause (диагностика уже сделана, дебаг-принт из bugfind.cpp УДАЛЁН):**

- Кейс: `var a: float = 0.1 + 0.2; if a == 0.3` — ждём `[ZT-BUG013]`
  (double vs float32 rounding меняет результат сравнения).
- Старый лексер: `selfhost/reference/lexer.cpp:126` → `std::stod(numStr)` =
  точный double `0.29999999999999999`. Тогда в `bugfind.cpp:1110-1123`
  `d = (l.fv == r.fv)` = false, `f = ((float)==)` = true → `d != f` → BUG013
  выстреливает, BUG002 глушится (`v.reported`).
- Новый selfhost лексер: `selfhost/lexer.z:9 var floatVal: float` (z float =
  **f32**) → `0.3` становится `0.30000001192092896` → `d == f` → BUG013 не
  срабатывает, а foldCmp (`bugfind.cpp` cmpF) даёт «always true» → BUG002.
- **Причина, почему lexdiff ALL OK не поймал:** сравнение float в
  `selfhost/lexdiff.z:36-45,93,195` идёт через `closeF()` (допуск) и
  `refFloat` кастит в `(float)` — точность f32-vs-f64 замаскирована.

**Фикс (план, минимум движений):**

1. `tools/lextool_main.cpp` (~строка 76): для токенов `TFloatLit` (kind == 2 по
   `src/lexer.h:15` — проверить фактическое значение enum!) перепарсить текст
   токена через `strtod(text)` и писать в dump **этот точный double** вместо
   `(double)lexFloatAt(i)`. Семантика `stod`/`strtod` одинаковая — поведение
   старого компилятора восстанавливается. (Включить `src/lexer.h` для
   `TokenKind::FloatLit` или захардкодить число — лучше include.)
2. Пересобрать lextool: `make -f Makefile.linux tools/lextool` (новый zenith
   возьмёт старый lextool — цикла нет).
3. Пересобрать zenith: `make -f Makefile.linux` (изменится только
   lextool_main → lextool; zenith пересоберётся если что).
4. Проверка: `./build/linux/zenith /tmp/opencode/c013.z -o /tmp/opencode/c013`
   должен печатать `[ZT-BUG013]` и НЕ печатать `[ZT-BUG002]`.
5. Прогнать `make -f Makefile.linux test` ЦЕЛИКОМ (test-irbugfind и test-js
   ещё ни разу не запускались после миграции — make упал раньше).
6. Опционально (хорошо бы): в `selfhost/lexdiff.z` добавить кейс с
   `0.1 0.2 0.3 1.5 0.30000001` и рядом комментарий, что точная f64-точность
   проверяется интеграционно через test-bugfind 013, а closeF — потому что
   z float = f32.

**ВАЖНО:** после фикса убедиться, что `refFloat`/lexdiff всё ещё ALL OK
(не сломать).

## 2. Финальные шаги миграции (когда 013 зелёный)

- [ ] `git worktree remove /tmp/opencode/oldwt` (+ прибрать
      `/tmp/opencode/base_wt` — помечен prunable: `git worktree prune`).
      (Worktree'ы создавались только для диагностики A/B.)
- [ ] Полный прогон: `make -f Makefile.linux test` → всё зелёное.
- [ ] Ещё раз selfhost-регенерация: `make -f Makefile.linux tools/lextool`.
- [ ] НЕ коммитить самому. Перечислить пользователю, что коммитить:
  - новый: `src/lexbridge.cpp`, `selfhost/lextool.z`, `tools/lextool_main.cpp`,
    `tools/lextool` (бинарь ~630 КБ — обязателен для свежего клона, иначе
    zenith не сможет компилировать .z!), `selfhost/reference/lexer.cpp`,
    `selfhost/lexer.z`, `selfhost/lexdiff.z`, `selfhost/lexref.cpp`,
    `NEXT_STEPS.md`;
  - изменённый: `src/lexer.h`, `src/main.cpp`, `tools/bugfind_test.cpp`,
    `Makefile.linux`, `selfhost/reference/lexer.cpp` (include),
    `src/codegen_builtins_linux.cpp` (билтины eprint/eprintln);
  - удалённый (staged rename): `src/lexer.cpp` → `selfhost/reference/lexer.cpp`.
- [ ] Внимание: в репо НЕЗАКОММИЧЕНЫ чужие правки (ast.h, codegen*.cpp и т.д.,
  статус ~93 файла) — НЕ затронуть, не коммитить мусором.

## 3. НОВАЯ ЗАДАЧА ПОЛЬЗОВАТЕЛЯ (уточнить завтра, прежде чем писать код!)

Цитата: «для проверки лексера на самом себе написанном сделай целую OS и
прошивку для STM32 — не каркас а полноценную: 1) с ExitBootServices,
2) змейку знаешь, но минимальную».

Смысл: написать большой код на Zenith (OS + прошивка), который и будет
стресс-тестом selfhost-лексера. Вопросы, которые надо задать:

1. **ExitBootServices — это UEFI (x86-64), а не STM32.** Что именно:
   UEFI-приложение (`app efi`), которое вызывает ExitBootServices и дальше
   работает как ОС (framebuffer, прерывания, своя MEMORY_MAP)?
2. **STM32:** какая конкретно плата/чип (F103 blue pill? F4 discovery?) и
   куда «змейка» — на UART-терминале? SPI-LCD? На чём рисовать?
3. Или змейка — в UEFI-ОС на framebuffer, а STM32-прошивка — отдельно?
4. Масштаб «полноценной OS»: что обязательно (прерывания? планировщик?
   FS? shell?) — договориться о MVP и порядке итераций.
5. Проверить в коде (НЕ в release/документация — она устарела!): какие
   `app efi` / `app stm32` / `app bios` возможности реально есть в
   codegen_efi.cpp / codegen_stm32.cpp / codegen_bios.cpp (что за рантайм,
   какие вызовы доступны, есть ли уже примеры в tools/).

## 4. Напоминки / грабли

- Комменты в Zenith: только `#` и `\ ... \`. НЕ `//`.
- `println/print/printLn` — ровно 1 аргумент. Формата `"x=%d", x` в языке
  НЕТ (codegen даёт «call to undefined function»). Печатать конкатенацией или
  отдельными вызовами.
- Унарный минус не работает: `0 - x`.
- `for i = a, b` = `[a, b)`. Сравнение строк `==` сравнивает указатели.
- `make -f Makefile.linux` может упасть на регенерации `src/asm_blob.h`
  (`symbol 'txt_abs' not defined` — сломано в репо, не трогали) → обход:
  `touch src/asm_blob.h`.
- Не смотреть `release/документация/` (устарела) — источник истины в коде.
- lextool спавнится через `system()`; ошибки лексера он печатает в свой
  stderr (наследуется) в формате `Lexer error at line N: ...` — как старый
  C++ лексер.
- Пользователь параллельно правит репо — перечитывать файлы перед правкой.
