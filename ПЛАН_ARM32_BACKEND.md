# План: бэкенд `src/irasm_arm.cpp` (STM32F1, Thumb-2, через IR)

Дата: 2026-09-15. Ничего ещё не написано в `irasm_arm.cpp` — это план/памятка.

## Цель
Дописать заглушку `src/irasm_arm.cpp` в полноценный IR-бэкенд: плоский `.bin` для QEMU
`stm32vldiscovery` (STM32F100), консоль через USART2 (0x40004400), "full minimum" — только int32.
Floats/импорты/прочее — `throw runtime_error` (main.cpp ловит и падает в классический бэкенд).
После реализации: обновить `документация/16_stm32.txt` + `17_arm64.txt` (по-русски) и закоммитить.

## Команды
- Сборка: `make -f Makefile.linux` (сейчас зелёная).
- Дампа IR: `ZT_DUMP_IR2=1 ./build/linux/zenith --ir /tmp/opencode/t_ir_stm32.z`
- Тест-программа уже есть: `/tmp/opencode/t_ir_stm32.z` (копия t_ir_a64.z, `app stm32`,
  глобал `counter`, функции add/fact/mod17, print-выводы). Ограничения: нет `?:` (тернарника),
  нет массивов `int[]`, нет floats.
- Запуск в QEMU: `qemu-system-arm -machine stm32vldiscovery ...` — способ загрузки
  (-kernel в 0x08000000?) и факт, что USART2 висит на серийном chardev, **проверить эмпирически**.

## Доказанные кодировки (capstone, base 0x08000000)
16-битные (Thumb-1):
- movs rd,rm = `0x0000|((rm&7)<<3)|(rd&7)`
- movs_imm rd,v = `0x2000|((rd&7)<<8)|(v&0xFF)` (v 0..255, только r0–r7)
- movh rd,rm (MOV rd,rm, любой регистр) = `0x4600|(((rd>>3)&1)<<7)|((rm&0xF)<<3)|(rd&7)`
  (bit6 = старший бит rm, bit7 = старший бит rd; mov sp,r0=0x4685, mov r0,sp=0x4668)
- adds rd,rn,rm = `0x1800|((rm&7)<<6)|((rn&7)<<3)|(rd&7)` (только r0–r7!)
- subs = `0x1A00|...`
- adds_imm8 rd,v = `0x3000|((rd&7)<<8)|(v&0xFF)`; subs_imm8 = `0x3800|...`
- ands rd,rm=`0x4000|((rm&7)<<3)|(rd&7)`; eors=`0x4040`; orrs=`0x4300`; muls=`0x4340`;
  rsbs=`0x4240`; mvns=`0x43C0` (все только r0–r7, rd=rn)
- cmps rn,rm = `0x4280|((rm&7)<<3)|(rn&7)`; cmp_imm rn,v = `0x2800|((rn&7)<<8)|(v&0xFF)`
- lsls_reg rd,rm=`0x4080`; lsrs_reg=`0x40C0`; asrs_reg=`0x4100` (только r0–r7)
- ldr_off rt,rn,off = `0x6800|(((off/4)&31)<<6)|((rn&7)<<3)|(rt&7)` (слово, imm5*4);
  str_off = `0x6000`; ldrb_off=`0x7800|((off&31)<<6)|...`; strb_off=`0x7000`;
  ldrh_off=`0x8800|(((off/2)&31)<<6)|...`; strh_off=`0x8000`
- ldr_sp rt,off = `0x9800|((rt&7)<<8)|(off/4)` (off ≤ 1020, кратно 4);
  str_sp = `0x9000`
- add_sp imm7 = `0xB000|(imm7&0x7F)` (imm7 = байты/4); sub_sp = `0xB080|(imm7&0x7F)`
- push mask(lr) = `0xB400|(lr?0x100:0)|(mask&0xFF)`; pop = `0xBC00|(pc?0x100:0)|(mask&0xFF)`
  push {lr}=0xB500, pop {pc}=0xBD00; push {r4,lr}=0xB470, pop {r4,pc}=0xBD70;
  push {r4,r5,r6,r7,lr}=0xB5F0, pop {r4,r5,r6,r7,pc}=0xBDF0
- bx rm = `0x4700|((rm&15)<<3)`; blx rm = `0x4780|((rm&15)<<3)`
- b = `0xE000|(imm&0x7FF)`; b_cc = `0xD000|((cc&15)<<8)` + байт imm; imm=(target-(pos+4))/2;
  диапазоны: cond imm ∈ [-128,127]; uncond imm ∈ [-1024,1023]
- спин = `0xE7FE` (b .)
- ВАЖНО: все 16-битные 3-регистровые ALU — ТОЛЬКО r0–r7; с r8+ обязательны T2 (32-битные).

32-битные T2 (hw2-поля везде `(rd<<8)|rm`, выбирает capstone — НЕ копировать старый «обмен»
из codegen_stm32 для add_w_r/sub_w_r/and_w/orr_w/eor_w/bic_w/mvn_w!):
- movw rd,v = `[0xF240|(i<<10)|imm4, (imm3<<12)|((rd&15)<<8)|imm8]`; movt = `0xF2C0`
  (`i=(v>>11)&1, imm4=(v>>12)&0xF, imm3=(v>>8)&7, imm8=v&0xFF`)
- add_w rd,rn,imm12 = `[0xF200|(i<<10)|(rn&15), (imm3<<12)|((rd&15)<<8)|imm8]`; sub_w=`0xF2A0`
- add_w_r rd,rn,rm = `[0xEB00|(rn&15), (rd<<8)|rm]` (hw2 = (rd<<8)|rm!)
- sub_w_r = `[0xEBA0|(rn&15), (rd<<8)|rm]`
- and_w=`0xEA00`, orr_w=`0xEA40`, eor_w=`0xEA80`
- mvn_w rd,rm = `[0xEA6F, (rd<<8)|rm]` (hw2 = (rd<<8)|rm!)
- cmp_w_r rn,rm = `[0xEBB0|(rn&15), 0x0F00|(rm&15)]`
- cmp_w_imm rn,imm12 = `[0xF1B0|(i<<10)|(rn&15), (imm3<<12)|(0xF<<8)|imm8]` (imm12=i:imm3:imm8; куски ≤0xFFF)
- lsl_w=`[0xFA00|(rn&15),0xF000|((rd&15)<<8)|(rm&15)]`; lsr_w=`0xFA20`; asr_w=`0xFA40`
- mul_w=`[0xFB00|(rn&15),0xF000|((rd&15)<<8)|(rm&15)]`
- sdiv_w=`[0xFB90|(rn&15),0xF000|((rd&15)<<8)|0xF0|(rm&15)]`; udiv_w=`0xFBB0`
- mls_w rd,rn,rm,ra = `[0xFB00|(rn&15),(ra<<12)|((rd&15)<<8)|0x10|(rm&15)]`
- ldr_w rt,rn,imm12 = `[0xF8D0|(rn&15),((rt&15)<<12)|(imm12&0xFFF)]`; str_w=`0xF8C0`;
  ldrb_w=`0xF890`, strb_w=`0xF880`; ldrh_w=`0xF8B0`, strh_w=`0xF8A0`; ldrsb_w=`0xF990`
  (rn=13 SP работает)
- ite(cc) = `0xBF00|((cc&15)<<4)|0x0C`; НО лучше НЕ использовать IT вообще — Cmp делать ветками.
  IT single = `0xBF08`.

Условия ARM (те же цифры, что в arm64-бэкенде ccForOp): eq=0 ne=1 cs=2 cc=3 mi=4 pl=5 vs=6 vc=7
hi=8 ls=9 ge=10 lt=11 gt=12 le=13 al=14. Инверсия = XOR 1.

## Модель IR (из irgen.cpp — важно!)
- Слоты ВИРТУАЛЬНЫХ регистров — по 8 байт (Int fieldSize=8, смещения членов в байтах).
  → Фрейм = 8*maxSlot байт (как в arm64-бэкенде), но все load/store — 32-битные слова.
  8-байтный шаг слотов обязателен, чтобы смещения структур (0,8,16...) и индекс*8 массивов
  совпадали с расчётами IRGen. Старшие 4 байта слотов не используются.
- Целочисленные операции на 32-битной цели: IROp::Load/Store/GLoad/GStore = 32-битные загрузки/сохранения.
- Семантика (подтверждено дампом и arm64-бэкендом):
  - Store: значение из слота b.reg → [слот a.reg + in.label] (не как в комментарии ir.h!)
  - Load: a.reg = [слот b.reg + in.label]
  - GStore: b.reg → [глобал a.name + in.label]; GLoad: a.reg = [глобал b.name + in.label]
  - Br -> b.label; BrZ/BrNZ (a.reg==0) -> b.label; BrCC (a.reg op b.reg) -> c.label, cond в in.cond
  - Cmp: a.reg = (b.reg op c.reg) ? 1 : 0, op в in.cond
  - Arg: a.imm=номер, значение в b.reg; за ним Call/ICall (c.imm=nargs)
  - Call: a.reg = результат; PrintStr: a.kind StrIdx => a.strIdx (иначе Reg — указатель)
  - PrintInt: печатает a.reg; Exit; Ret: результат в a.reg (если Reg)
  - ICall: только `halt` -> __zt_halt, прочее — throw
- Kunfts «Op»: см. enum IROp (Nop=0, Func=1, EndFunc=2, Label=3, Const=4, FConst=5, Str=6,
  Mov=7, LeaGlobal=8, LeaSlot=9, Load=10, Load32=11, Store=12, Store32=13, GLoad=14, GStore=16,
  Arg=28, Add=29 ... Ret=67). Load32/Store32/GLoad32/GStore32 = то же 32-битное слово.
  PLoad/PLoad32/PLoad32Z = 32-битная загрузка по указателю(+off); PLoadW=ldrh, PLoadB=ldrb;
  PStore/PStore32=str_w; PStoreW=strh, PStoreB=strb.

## Регистровый план (соглашение)
- r0–r3: аргументы (nargs <= 4, иначе throw), r0 — результат. Вызовы КЛОББЕРЯТ r0–r3, r12, lr.
  Между вызовами нельзя держать живые значения в r0–r3.
- r4–r11: сохраняемые вызываемым (callee-saved). Хелперы сохраняют то, что используют.
- r6 = opA/результат (low), r7 = opB (low) → дешёвые 16-битные ALU;
  r8 = адрес (high, только T2), r10/r11 = temps, r12 = целевой адрес вызова/дальнего перехода.

## Структуры AsmBuf (по образцу irasm_arm64.cpp, но с релаксацией)
- Эмиссия полусловами; единицы `Item {kind: H(2), B(ветка), L(метка), D(movw/movt под патч)}`.
- B: pos, label, cc, cond, far. Летка: zero-size, ставит labelPos.
- D: dfx[pos, rt, kind(DfStr/DfGlobal/DfFunc/DfLabel), strIdx/name/extra/label].
- FJ (дальние переходы): pos, label — патч абсолютного адреса на этапе сборки образа.
- relayout(): считает pos всех Item (H=2, B=2 либо far: cond=12/uncond=10, L=0, D=4),
  заполняет labelPos и позиции D/FJ.
- relaxBranches(): цикл «пока меняется»: если B не в диапазоне и !far → far=true, relayout().
  Терминируемо (far не откатывается). Диапазоны по формуле imm=(target-(pos+4))/2.
- encode(): H -> полуслово; B: если !far — b/b_cc с imm; если far —
  cond: b.!cc skip(imm8=4, метка = pos+12) + movw r12,0 + movt r12,0 (FJ) + blx r12 (12 байт);
  uncond: movw+movt+blx (10 байт); L ничего; D — заготовки movw/movt под dfx.

## Функция (ArmFn) — эмиссия тел
- Пролог: `push {lr}` (0xB500); если frame>0 `sub_w(13,13,frame)` (frame=8*maxSlot, ≤4095 иначе throw);
  копирование параметров: `str_w(v,13,v*8)` для v<nparams (v≤3).
- Эпилог (Ret и fall-through): если frame>0 `add_w(13,13,frame)`; `pop {pc}` (0xBD00).
- loadSlotTo(rt,slotReg,extra): off=8*slot+extra;
  rt≤7 && off≥0 && !(off&3) && off≤1020 -> ldr_sp; иначе off 0..4095 -> ldr_w rt,13;
  иначе addrNew(off) (r8 = sp±кусками ≤0xFFF) + ldr_w rt,8.
- storeSlotFrom(slotReg,extra,rt): аналогично str_sp/str_w.
- loadOperandR6(o): Reg->loadSlotTo(6); Imm: v 0..255 -> movs_imm(6,v), иначе movw/movt r6.
- loadOperandR7(o): аналогично (v 0..255 -> movs_imm(7,v)).
- Бинарные: Add=adds(6,6,7); Sub=subs; Mul=muls; And=ands; Or=orrs; Xor=eors (16-бит);
  IDiv=sdiv_w(6,6,7); UDiv=udiv_w(6,6,7);
  IMod=sdiv_w(10,6,7)+mls_w(6,10,7,6); UMod=udiv_w(10,6,7)+mls_w(6,10,7,6);
  Shl=lsl_w(6,6,7); Shr=lsr_w; Sar=asr_w (T2, сдвиги маска 0..31).
- Neg=rsbs(6,6); Not=mvns(6,6) (16-бит r0–r7).
- Const: число → r6 (далее store).
- Mov: loadSlotTo(6)+storeSlotFrom.
- Str: dfx(DfStr,rt=8)→r8, store a.reg; LeaGlobal: dfx(DfGlobal,rt=8)→r8, store;
  LeaSlot: addrNew(8, 8*slot+off), store.
- Load: loadSlotTo(6, b.reg, in.label)+store a.reg. Load32 — то же.
- Store: loadSlotTo(6,b.reg,0)+storeSlotFrom(a.reg, in.label, 6). Store32 — то же.
- GLoad: dfx(DfGlobal,rt=8,b.name,extra=in.label)+ldr_w(6,8,0)+store a.reg. GLoad32 — то же.
- GStore: loadSlotTo(6,b.reg,0)+dfx(DfGlobal,rt=8,a.name,extra=in.label)+str_w(6,8,0). GStore32 — то же.
- PLoad/PLoad32/PLoad32Z: addrOfPtr(b.reg,b.off) (r8); ldr_w(6,8,0); store a.reg.
  PLoadW: ldrh_w; PLoadB: ldrb_w.
- PStore/PStore32: loadSlotTo(6,b.reg,0); addrOfPtr(a.reg,a.off); str_w(6,8,0).
  PStoreW: strh_w(6,8,0); PStoreB: strb_w(6,8,0).
- FLoad/FStore/FGLoad/FGStore/FConst/FAdd..F2I/FPStore/PrintFlt: throw runtime_error.
- Arg: if a.off!=0 throw; pendingArgs.push(b.reg).
- Call/ICall: if a.off!=0 throw; target=b.name (ICall: только "halt"->__zt_halt);
  nargs=c.imm; nargs>4 throw; for k<nargs: loadSlotTo(k, pendingArgs[k], 0); clear;
  emit 10 байт: movw r12,0 + movt r12,0 (dfx DfFunc) + blx r12;
  if a.kind==Reg: movh(6,0); storeSlotFrom(a.reg,0,6).
- PrintStr: StrIdx -> dfx(DfStr,rt=0)→? верну в r0: movw/movt r0; Reg -> loadSlotTo(0);
  call __z_print_string (dfx DfFunc).
- PrintInt: loadSlotTo(0,a.reg); call __z_print_int.
- Exit: call __zt_halt.
- Cmp: loadOperandR6(b); loadOperandR7(c); cmps(6,7); cc=ccForOp(in.cond);
  movs_imm(10,0); b_cc(cc^1, Lskip); movs_imm(10,1); Lskip: storeSlotFrom(a.reg,0,10).
- Br: b(b.label). BrZ/BrNZ: loadSlotTo(6,a.reg); cmp_imm(6,0); b_cc(eq/ne, b.label).
- BrCC: a->r6, b->r7; cmps(6,7); b_cc(cc, c.label).

## Хелперы (строятся как AsmBuf, вызывают друг друга через movw/movt+blx r12)
- `__z_putc` (r0=char, leaf): movw r1,#0x4400; movt r1,#0x4000;
  `Lw: ldr r2,[r1,#0]` (SR); `lsls r2,r2,#24` (TXE bit7 -> bit31/N); `bpl Lw`;
  `strb r0,[r1,#4]` (DR); `bx lr`.
- `__z_puts` (r0=ptr): `push {r4,lr}`(0xB470); `movh(4,0)`;
  `L: ldrb r0,[r4,#0]`; `cmp_imm(0,0)`; `beq Ld`; call putc; `adds_imm8(4,1)`; `b L`;
  `Ld: pop {r4,pc}`.
- `__z_print_string`: `push {lr}`; call puts; movs_imm(0,0x0D)+call putc; movs_imm(0,0x0A)+call putc; `pop {pc}`.
- `__z_print_int` (r0=int32): `push {r4,r5,r6,r7,lr}`(0xB5F0); `sub_sp(4)`(0xB084, 16 байт);
  `movh(4,0)` (n); `movs_imm(5,0)` (sign); `cmp_imm(4,0)`; `bge Ld`; `rsbs(4,4)`; `movs_imm(5,1)`;
  `Ld: movh(6,13)` (buf); `cmp_imm(5,0)`; `beq Ldig`; movs_imm(7,0x2D); strb_off(7,6,0); adds_imm8(6,1);
  `Ldig: movs_imm(1,10)`; `Lloop: udiv_w(2,4,1)` (q, БЕЗЗНАКОВОЕ деление — чтобы INT_MIN считался
  как 2147483648); `mls_w(3,2,1,4)` (r=n-q*10); `adds_imm8(3,0x30)`; `strb_off(3,6,0)`;
  `adds_imm8(6,1)`; `movh(4,2)`; `cmp_imm(4,0)`; `bne Lloop`; `movs_imm(7,0)`; `strb_off(7,6,0)`;
  `movh(0,13)`; call puts; puts «\r»; puts «\n»; `add_sp(4)`(0xB004); `pop {r4,r5,r6,r7,pc}` (0xBDF0).
  (Буфер 16 байт: до 10 цифр + '-' + NUL — влезает.)
- `__zt_halt`: `0xE7FE` (b .).

## Стартовый код (в compile(), после векторной таблицы)
Векторная таблица (64 байта, 16 слов): [0x20002000 (SP), reset|1, 14×(spin|1)].
Старт (по смещению 64):
- SP=0x20002000: movw r1,#0x2000; movt r1,#0x2000; movh(13,1).
- RCC APB1ENR: movw r1,#0x1000; movt r1,#0x4002; ldr_w(2,1,0x1C);
  movw r3,#0; movt r3,#0x0002; orrs(2,3); str_w(2,1,0x1C).
- USART2=0x40004400: movw r1,#0x4400; movt r1,#0x4000; movw r2,#4; str_w(2,1,8) (BRR);
  movw r2,#0x200C; str_w(2,1,0x0C) (CR1 = UE|TE|RE).
- Копирование глобальных в SRAM (числовые значения из образа): r0=IMAGE_BASE+dataStart (заглушка),
  movw r1,#0; movt r1,#0x2000 (SRAM_BASE=0x20000000), r2=globalBytes (заглушка);
  `L: cmp_imm(2,0); beq Ld; ldr_w(3,0,0); str_w(3,1,0); adds_imm8(0,4); adds_imm8(1,4);
  subs_imm8(2,4); b L; Ld:` (данные по 4 байта, выровнены в 4).
- Вызов entry: movw r12,#lo(entry); movt r12,#hi(entry) (заглушка); blx r12; `0xE7FE` (спин).
Заглушки (src,size,entry) патчатся после сборки образа. dataStart выровнять на 4 (пады 0xB000).

## Сборка образа (compile)
1. Хелперы (5 шт) -> img+dfx; nameIdx. 2. Функции пользователя -> img (bytes+dfx+FJ); entryIdx.
3. Исключение, если entry нет. 4. Раскладка данных: глобальные (по 8 байт, выравнивание 8),
   затем строговый пул (strOff). 5. Сборка: векторная таблица + старт + хелперы + функции + данные + строки.
6. Патчи: стартовые (src/size/entry); dfx (DfStr: IMAGE_BASE+dataStart+poolBase+strOff;
   DfGlobal: SRAM_BASE+gOff+extra — глобалы ЖИВУТ в SRAM после копии; DfFunc: IMAGE_BASE+imgStart[name];
   DfLabel: IMAGE_BASE+imgStart[fn]+labelPos); FJ то же.
7. Глобалы в образе: intValue (младшие 4 байта); isString — 32-битный указатель IMAGE_BASE+pool(strOff);
   вся область глобальных копируется в SRAM стартом (для строк — то же значение указателя).
8. Запись .bin.

## Проверка
1. `make -f Makefile.linux`.
2. `ZT_DUMP_IR2=1 ./build/linux/zenith --ir /tmp/opencode/t_ir_stm32.z -o /tmp/opencode/fw32` -> fw32.bin.
3. QEMU: найти способ загрузки .bin в stm32vldiscovery (-kernel в 0x08000000?) и убедиться, что
   USART2 идёт на серийный порт (-nographic / -serial). Ожидаем:
   `Hello from Zenith STM32 IR!`, `x=7`, `fact6=720`, `mod=4`, `counter=11`.
4. Разобрать/проверить пару инструкций capstone-ом при расхождении.

## После работы
- Обновить `документация/16_stm32.txt` (раздел про IR-бэкенд: консоль через USART2, ограничения)
  и `документация/17_arm64.txt`, закоммитить.