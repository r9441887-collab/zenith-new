# Zenith → Linux .ko — заметки для продолжения (2026-09-13)

> Задача: генерация загружаемых модулей ядра (.ko) из языка Zenith, с
> import'ом символов ядра (kalloc/kfree/ktime_ns/jiffies), ring-0 builtin'ами
> и выводом драйвера на чёрном консольном экране при загрузке Linux.

## Окружение
- Путь проекта: `/media/ruslan/D64ED4304ED40ADF/Users/user/Desktop/b/zenith`
  (НЕ `~/Desktop/b/zenith` — home у пользователя `/home/ruslan`, проект на диске).
- Сборка компилятора: `make -f Makefile.linux` → `build/linux/zenith`
- Компиляция драйвера: `./build/linux/zenith asm_driver.z -o asm_driver.ko`
- Ядро: `6.12.95+deb12-amd64` (Debian 12.15); headers `/usr/src/linux-headers-6.12.95+deb12-amd64`
- Экспорты ядра есть в `/lib/modules/6.12.95+deb12-amd64/build/Module.symvers`

## Синтаксис языка (подводные камни)
- Комментарии: `#` (строка) и `\...\` (блок). `//` НЕ поддерживается → lexer error.
- В `if/while` НЕТ `then`: `if <expr>` новая строка, тело, `end`.
- Нет бинарных `&` `>>` `<<` — только арифметика (делить на 16/брать `%16` для BCD).
- ASCII only (типографские кавычки/апострофы → ошибка).
- CLI: `-o <file>` задаёт имя выходного файла (позиционный 2-й аргумент игнорируется).

## СДЕЛАНО И РАБОТАЕТ
1. ring-0 builtin'ы в `tryKOCall` (codegen_builtins_linux.cpp): `rdtsc()`, `io_delay()`,
   `inb(port)`, `outb(port,val)`. Добавлены в `tryKOCall`, т.к. `tryBuiltinCall`
   для Linux/kernel НЕ вызывается.
2. Новые мнемоники `asm {}` (codegen.cpp `emitAsmInstr`): `rdtsc, rdtscp,
   lfence, mfence, sfence, clts, swapgs, clc, stc, cmc, cld, std, lock, xchg`.
3. Импорт символов ядра (механизм `koExtCallFixups` + NEW `koDataFixups`):
   - `kalloc(n)` → `__kmalloc_noprof(n, 0xCC0 /*GFP_KERNEL*/)` (EXPORT_SYMBOL)
   - `kfree(p)` → `kfree` (EXPORT_SYMBOL)
   - `ktime_ns()` → `ktime_get_boot_fast_ns` (EXPORT_SYMBOL_GPL)
   - `jiffies()` → `mov rax,[rip+disp32]` чтение данных ядра (STT_OBJECT UND)
   - `cpu_id()` убран (`smp_processor_id` — макрос заголовка, не символ).
   - UND-символы добавляются в codegen_ko.cpp (~стр. 292-294).
   - `.modinfo` модуля уже содержит `license=GPL` (codegen_ko.cpp), GPL-символы ок.
4. `asm_driver.z`: бенчмарк простых чисел + rdtsc + CMOS RTC — МОДУЛЬ ГРУЗИТСЯ
   И РАБОТАЕТ (count=1229 PASS, циклы 5.0M/5.6M, секунды из CMOS 44/9).
5. `install_boot_driver.sh` (с `--uninstall`): ставит asm_driver.ko в
   `/lib/modules/<ver>/updates`, дописывает `/etc/initramfs-tools/modules`,
   `update-initramfs -u`, убирает `quiet` из GRUB_CMDLINE_LINUX_DEFAULT, `update-grub`.

## ТЕКУЩИЙ БАГ: drv_imports.ko падает при insmod (Ooops)
Симптомы:
- `insmod drv_imports.ko` → «Убито»; в dmesg Oops: `RIP=CR2=0x72e1bfde595`
  (адрес из userspace — стек разъехался), `note: insmod[...] exited with irqs disabled`,
  `rmmod: ERROR: Module drv_imports is in use` (застрял до перезагрузки).

### Причина (найдена по objdump -d)
В `drv_imports.z` строки 20 и 22 написано:
```
20: print(poke32(p))
22: print(poke32(p + 60))
```
`poke32` требует ДВА аргумента (addr, val) → вызываеться как ЧТЕНИЕ нельзя.
С одним аргументом builtin не матчится → компилятор генерирует обычный `call`
к несуществующей функции. В KO-режиме relocation для неё пропускается
(`fnSymIndex() == -1`, codegen_ko.cpp:319) → остаётся `E8 00 00 00 00`
(вызов next-instruction), а return-адрес со стека никто НЕ снимает.
Два таких вызова = +16 байт к стеку → `ret` в конце main прыгает в мусор.

Диз-ассемблер подтверждает: на 0xb6 и 0xf4 голые `call` без релокаций
(не inline, т.к. из `poke32` обычно инлайнится: `9d` и `ba` — это правильные
`poke32(p,val)` и `poke32(p+60,7)`).

### Как чинить (по приоритету)
1. (СРОЧНО, просто) В `drv_imports.z` заменить `poke32(p)` → `peek32(p)`
   и `poke32(p + 60)` → `peek32(p + 60)`. Оба builtin'а (peek32 codegen.cpp:4210,
   poke32:4262) существуют и инлайнятся. Пересобрать и insmod.
2. (Защита компилятора) В `codegen_ko.cpp` fcall: если `fnSymIndex < 0` —
   сейчас молча пропускает (строка 319). Правильнее: `std::cerr` с ошибкой
   "unknown function 'X'" + throw, ИЛИ хотя бы эмитить сбалансированный стек
   (`xor eax,eax` + `ret`-заглушка). Сейчас тихий E8-в-себя ломает стек.
3. После фикса пересобрать оба драйвера и перегрузиться, чтобы выгрузить
   застрявший модуль (или после перезагрузки `insmod drv_imports.ko`).
4. Затем возврат к boot-консоли: `sudo ./install_boot_driver.sh` + перезагрузка.

## ФАЙЛЫ
- `src/codegen_builtins_linux.cpp` — tryKOCall: inb/outb/io_delay/rdtsc + kalloc/kfree/ktime_ns/jiffies
- `src/codegen_ko.cpp` — сборка ET_REL: syms, UND-символы (kalloc..jiffies),
  callFixups/koExtCallFixups/koDataFixups → relas (R_X86_64_PC32 addend −4),
  fcall с ВАЖНЫМ местом-кандидатом на починку (строка 319)
- `src/codegen.cpp` — emitAsmInstr (~стр. 6119+), peek/poke builtin'ы (4143-4270),
  диспетчер Linux/KO (4764-4781)
- `asm_driver.z` — рабочий демо-драйвер (критерий регрессии)
- `drv_imports.z` — тест импортов ядра (с багом poke32→peek32)
- `install_boot_driver.sh` — установка драйвера в initramfs + снятие quiet

## СЛЕДУЮЩИЙ ШАГ
1. Отредактировать `drv_imports.z`: `poke32`→`peek32` (строки 20, 22).
2. Пересобрать: `make -f Makefile.linux` и `./build/linux/zenith drv_imports.z -o drv_imports.ko`.
3. Обновить релиз: `./build/linux/zenith asm_driver.z -o asm_driver.ko`.
4. (по желанию) починить fcall на стр.319 codegen_ko.cpp, чтобы тихие
   несуществующие вызовы не разбивали стек.
</content>