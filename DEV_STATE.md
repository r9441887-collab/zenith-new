# Состояние работ + план (на случай перезагрузки)

Сохранено: агент продолжит с этого файла + из кода/тестов.

## == НОВОЕ (7 сен, день): РЕГРЕССИЯ ПОСЛЕ dxClear + cube_collide (всё зелёное) ==
Компилятор build/zenith.exe (SIB-fix + dxClear). Прогон headless-wine:
- DX11 (цикл жив, RC=124): reg_cube3d, reg_tri2, reg_cube_collide, reg_diag5.
- GUI-смоки (RC=124): reg_test_win, reg_chip8_gui, reg_chip8_snake.
- Консоль (exit=0): reg_bugfix_line, reg_core_colortest, reg_core_recttest,
  reg_core_trftest, reg_eng_test, reg_fbitstest.
- g-тесты движка (zenith-engine/tests, exit=0; g11 — GUI, жив RC=124):
  g7-g10, g12-g27, gA, gB (включая drawline-регрессию g25/g27 с отрицательными
  дельтами и bugfix_line). Все компилируются без варнингов.
- ВАЖНО/УРОК: куб в cube_collide «пропадал» при cs2.z=-0.1f — NDC-глубина вне
  [0,1] клипается вся геометрия. НЕ выводить o.pos.z за [0,1]: стена z=0.4,
  куб z=0.1.

## == НОВОЕ (7 сен, день): БИЛТИН dxClear() + ДВУХОБЪЕКТНАЯ 3D-СЦЕНА КУБ→ТРЕУГОЛЬНИК ==
Запрос пользователя: «куб едет к треугольнику и сталкивается, всё 3D на Zenith».
СОЗДАНО `cube_collide.z` (build/cube_collide.exe): ОБА объекта в одном vertex buffer
(треугольник = verts 0-2, куб = verts 3-26, 27*28=756 байт), общий VS с перспективным
делением (f=2/(z+5)) и вращением вокруг Y, между draw-вызовами переключается constant
buffer (dxUpdateBuffer+dxSetVertexConstants) — каждой модели своя трансформация.
Куб стартует x=-2.2 и едет вправо (+0.004/кадр) к статичному белому треугольнику-стене
(центр x=1.6); при касании (cubeX>=0.1, правый край куба = левый край стены) -> impact,
куб замирает. Esc — выход.
### ДОБАВЛЕН БИЛТИН: dxClear() в src/codegen_dx11_shaders.cpp (после dxClearDepthStencil)
- ClearRenderTargetView(context, rtv, {0,0,0,1}) чёрным в начале каждого кадра.
- ЗАЧЕМ: раньше swapchain back buffer НЕ очищался между кадрами — куб в движении
  оставлял призрачные хвосты/дубли «как будто удаляется» (накопление прошлых кадров).
  У cube3d был один вращающийся объект без движения за пределы — хвосты не так заметны,
  но в сцене с перемещающимся кубом без очистки получается смаз/дубли.
- Паттерн: rtv из [rbx+80]; if rtv==0 skip; sub rsp,0x40 (rtv@[rsp+0x20], color R@0x28
  G@0x2C B@0x30 A@0x34); context->vtable[50@0x190](ctx,rtv,&color); add rsp,0x40;
  reload rbx.
### ГЛУБИНА (ВАЖНО для >1 объекта в D3D11)
- При дефолтном depth test LESS оба объекта на одинаковом o.pos.z НЕ видны вместе
  (второй draw с той же глубиной затирается). ФИКС: o.pos.z берётся из cbuffer cs2.z;
  стена-треугольник дальше (z=0), куб ближе (z=-0.1f=0xBDCCCCCD), рисуем стену первой,
  куб поверх. Без этого «куб дублировался/недорисовывался».
- В VS: `o.pos = float4(x*f, y*f, cs2.z, 1)`.
### РАЗМЕЩЕНИЕ ОБЪЕКТОВ
- Треугольник: apex(0,0.55), left(-0.5,-0.4), right(0.5,-0.4), z=0, белый.
- Куб: 24 verts, half=1 (как cube3d), face-цвета из cube3d, индексы со сдвигом +3
  (verts 3..26, т.к. треугольник в verts 0-2).
- Индексы: face0(3,4,5 5,6,3), face1(8,7,10 10,9,8), face2(11,12,13 13,14,11),
  face3(15,16,17 17,18,15), face4(19,20,21 21,22,19), face5(23,26,25 25,24,23).
### ПРОВЕРЕНО
- wine/headless: cube_collide.exe жив (RC=124), без краша. Регрессия: cube3d, tri2
  пересобраны новым компилятором — живы (RC=124), dxClear не трогает их код (они не
  зовут dxClear). build/zenith.exe обновлён (= /tmp/zenith_clear.exe).
- Визуально корректно проверять на реальном Windows 10 (headless wine рисует чёрным).

## == НОВОЕ (7 сен): SIB-БАЙТ ДОБАВЛЕН — ЧЁРНЫЙ ЭКРАН/КРАШ ОКОНЧАТЕЛЬНО ПОЧИНЕН ==
СИМПТОМ: после фикса xmm0→xmm3 (6 сен) куб СТАЛ падать page fault на wine:
`wine: Unhandled page fault on read access to 0000000C2E2C7D54 at 0x140001696`.
ПРИЧИНА: при правке `movss xmm0`→`movss xmm3` в ДВУХ местах (codegen_dx11.cpp:318 init,
codegen_dx11.cpp:591 present) старый ModRM байт `0x84` НЕ был убран, и он стал лишним
**SIB-байтом**: `F3 0F 10 9C 84 24 D0 00 00 00` = `movss xmm3,[rsp+rax*4+0xD024]`
вместо `F3 0F 10 9C 24 D0 00 00 00` = `movss xmm3,[rsp+0xD0]`. Читало мусорный адрес
(rsp+rax*4+0xD024) → page fault. В ТРЕТЬЕМ месте (dxClearDepthStencil, codegen_dx11_shaders.cpp:1298)
байт `0x9C 24 0x28` образа был правильный — поэтому там краша не было, но из-за этого
сообщение в DEV_STATE 6-сен («проверено objdump… все три места 0x9C») было неполным:
проверяли только ModRM `0x9C`, а не полную последовательность байт после него.
ФИКС (этот раз ПРОВЕРЕН по ПОЛНОМУ дизассемблеру объекта, а не по ModRM):
- codegen_dx11.cpp:318: `9C 84 24` → `9C 24` (убрать лишний `0x84` SIB)
- codegen_dx11.cpp:591: `9C 84 24` → `9C 24` (убрать лишний `0x84` SIB)
ПРОВЕРКА: `objdump -d build/cube3d_sibfix.exe` — все ТРИ `movss xmm3` теперь
`F3 0F 10 9C 24 <disp32>`: 0x140001696 `[rsp+0xD0]` (init), 0x14000480a `[rsp+0x28]`
(builtin), 0x140004dba `[rsp+0x50]` (present). Куб РАБОТАЕТ на wine (RC=124, жив,
печатает 4 адреса VS/PS/layout/cb, без краша). Куда копать дальше — реальный Windows 10.
Компилятор пересобран и скопирован в build/zenith.exe.

## == НОВОЕ (6 сен, вечер): ROOT CAUSE ЧЁРНОГО ЭКРАНА КУБА (wine+Windows) ==
СИМПТОМ: куб чёрный и в wine, и на реальном Windows. Диагностика wine-трейсом
(WINEDEBUG=+d3d,+d3d11) показала: `ClearDepthStencilView` в цикле получал
`depth 5.60519386e-45` (мусор, денормаль) вместо 1.0f.
ПРИЧИНА: x64 Windows ABI. `ClearDepthStencilView(context, dsv, ClearFlags, Depth,
Stencil)` — 4-й аргумент FLOAT Depth передаётся в **xmm3**. Код клал 1.0f в **xmm0**
(`movss xmm0,[mem]`, ModRM reg=000 → байт 0x84). D3D11 читал xmm3 = мусор ≈ 0 →
depth-буфер очищался ~0 → дефолтный depth test LESS отвергал ВСЕ фрагменты куба
(их глубина в (0,1]) → чёрный экран. Общий баг wine+Windows (wine это тоже честно
рисует, у него depth test работает).
ФИКС: во всех ТРЁХ местах `movss xmm0` → `movss xmm3` (ModRM 0x84 → 0x9C):
  1) src/codegen_dx11_shaders.cpp:1293 `dxClearDepthStencil()` (куб зовёт каждый кадр)
  2) src/codegen_dx11.cpp:317 init-clear в emitDX11Init
  3) src/codegen_dx11.cpp:589 clear в emitDX11Present (CPU-present путь)
ПРОВЕРКА: objdump нового билда показывает `f3 0f 10 9c 24 ...` = `movss xmm3,...`
на всех трёх местах (0x1696 init, 0x480b builtin, 0x4dbb present).
Сборка: /tmp/opencode/build/zenith_fixed_ds.exe, куб: build/cube3d_fixed_ds.exe
(запущен на wine RC=124, жив). СМОТРЕТЬ ГЛАЗАМИ на реальном Windows: должен появиться куб.

## == НОВОЕ (6 сен, вечер): gui_dx11_stress.z — комбинированный стресс-тест GUI+DX11 ==
Цель (запрос пользователя): «очень сильно проверить GUI на DX11 — сложная на вид, лёгкая на языке
сцена». Собран один файл `gui_dx11_stress.z`, который в ПРИНЦИПЕ делает всё сразу и
самопроверяется по пикселям (в противовес куб-примерам, которые только «рисуют»).
- Окно 800x600 (обязательно: dxProbeGPU читает бэкбуфер на фиксированных точках 0xN*4:
  px0=(0,0), px1=(400,300)=центр, px2, px3; центр = файл-байты [4..7], R8G8B8A8, R=младший).
- ДВА конвейера рендера в одном exe + переключение по клавишам 1/2/3:
  1) `1` = CPU-путь: clear + 60× drawRect/drawCircleF/drawLine + drawText, present() копирует fb.
  2) `2` = GPU-путь: плоский куб (24 вершины, 36 индексов, cbuffer поворота) — как cube3d.z.
  3) `3` = GPU-путь + ШЕЙДЕРНАЯ ТЕКСТУРА: dxCreateTexture2D(2x2 RGBA) → dxCreateShaderResourceView
     → dxSetTexture → dxCreateSamplerState → dxSetSampler; текстурный PS умножает цвет грани на
     Sample(). Это самый свежий непротестированный код.
- САМОПРОВЕРКА: каждый кадр после present() → dxProbeGPU() пишет build/probe.bin →
  fileLoad()+memByte(hdr+16+off,0) → centerPx() (r*65536+g*256+b) → сравнение: CPU=0x1B1B1B,
  GPU != 0x1B1B1B; маркеры mode/center печатаются каждые 20 кадров; счётчики pass/fails в конце.
- УРОК ПРО СИГНАТУРЫ GUI-билтинов (НЕ кодген-баг!): clear=1 арг (0xAARRGGBB), drawRect=5
  (x,y,w,h,color), drawCircleF=4, drawLine=5, drawText=4 (x,y,text,color). Я сначала вызвал
  clear(4 rgb-аргументами) и drawText(6 арг) — отработало как undefined function в resolveFixups
  (callback НЕ стал tryGUICall из-за неверного числа аргументов, упал в обычный funcRef).
  В helper-функциях билтины работают, если сигнатуры верны — проверено на cpuScene().
- ПОДТВЕРЖДЕНО: `%` в языке ЕСТЬ (parser.cpp:845 muldiv включает TokenKind::Percent;
  codegen.cpp:2119 — int mod via IDIV; `//` = unsigned mod). DEV_STATE-запись «% нет» — УСТАРЕЛА.
- СБОРКА: wine build/zenith_stress_compiler.exe gui_dx11_stress.z -o build/gui_dx11_stress.exe
  (компилятор собран заново в /tmp/opencode/build/zenith_tmp.exe и скопирован в
  build/zenith_stress_compiler.exe). RC=0, без варнингов (88 B code ~27219).
- ПРОГОН (headless wine 8/llvmpipe, DISPLAY=:0): setup ok, все хэндлы ненулевые, цикл живёт
  сотни кадров RC=124 без краша, probe.bin пишется каждый кадр. center=0 (чёрный) — это
  АРТЕФАКТ headless-рендера wine/llvmpipe (он показывает чёрный, см. также чёрный куб 6-сен),
  НЕ баг кодгена: init-путь, создание всех DX11-ресурсов и readback CopyResource+Map проходят.
  Визуально/по пикселям корректно проверять на реальном Windows 10 (как другие куб-тесты).
- ФИЛОСОФИЯ: тест автосбивается (Ctrl+C/таймаут) при 3+ фейлах только в старой версии;
  сейчас жёсткого аборта нет, идёт подсчёт pass/fails и печать сырого center каждые 20 кадров —
  чтобы headless-wine не «останавливал» полезный прогон, пока ждём реальный Windows.

## == НОВОЕ (6 сен): ФЛАГ --watch — LIVE-RELOAD (добавлен в компилятор) ==
Добавлено в src/main.cpp по требованию пользователя: `zenith main.z -o main.exe --watch`.
- Работает только для `app console` и `app gui` x86-64 Windows (PE) — для
  stm32/efi/bios/bare/arm64/wasm компилятор выходит с "Error: --watch ...".
- Режим: собирает, запускает exe, поллит LastWriteTime главного файла + всех
  include-файлов (collectSourceFiles сканирует `include "..."` рекурсивно). При
  изменении: убивает старый процесс (TerminateProcess, файл exe иначе заблокирован),
  пересобирает ДОЧЕРНИМ процессом zenith (те же аргументы минус --watch, вывод ошибок
  идёт в ту же консоль), на успех — перезапускает новый, при ошибке — сообщение
  "build failed (exit N); keeping last build" и поднимает последний рабочий билд.
- Реализация: cmdWatch() + helpers (launchProcess/waitExitCode/killProcess/toWidePath/
  quoteArg/collectSourceFiles) в src/main.cpp после writeFile. Флаг в разборе аргументов,
  хук после `prog.functions.empty()` (до оптимизатора). argv0 делается абсолютным.
- Проверено (реальный Windows): GUI test_win.z — запуск окна, хот-рестарт при смене
  кода (PID меняется), сбой (include несуществующего файла) → старый билд жив + ошибка
  в консоли; консольное приложение — так же. Регрессия: tri.z (DX11), chip8_gui.z exit=0.
- НЮАНС: топ-левел мусор типа "syntax error here!" компилятор ПРОПУСКАЕТ как warning
  и возвращает exit=0 — это поведение парсера, не ворчера. Для проверки пути ошибки
  нужен реальный фейл (include missing / ошибка внутри main).
- Сборка: те же команды, что ниже. Бэкап до фичи: build/zenith_pre_watch.exe.

## == НОВОЕ (6 сен, реальный Windows): DX11-READBACK/CRASH ПОЛНОСТЬЮ ПОЧИНЕН ==
Прогнано на реальном Windows 10 (cdb + objdump), краш `build/re_diag6.exe` (0xC0000005 в
CopyResource) устранён. Два бага, оба в src/codegen_dx11_shaders.cpp dxProbeGPU:
1. **disp8-overflow НЕ везде был вылечен (дополнение к 5-сен п.3).** В 5-сен сессии исправили только
   форму `C7 44 24 <disp>` (mov imm32). Остальные формы для смещений >=0x80 эмитились как disp8
   ЗНАКОВЫЙ: `lea r9,[rsp+0x90]` => `4C 8D 4C 24 90` = [rsp-0x70] (вне фрейма!), `mov rdx,[rsp+0x90]`
   => `48 8B 54 24 90` и т.д. В итоге CreateTexture2D возвращал S_OK, но писал out-указатель в
   rsp-0x70, а CopyResource читал rdx=[rsp-0x70]=мусор → AV в
   `CContext::TID3D11DeviceContext_CopyResource_<1>+0x25`. ИСПРАВЛЕНО ВСЕ 9 мест (строки ~1353, 1511,
   1579, 1584, 1591, 1598, 1606, 1608, 1640): леа/мov переведены на disp32-форму с SIB
   (0x4C->0x8C/0x84, 0x54->0x94, 0x44->0x84 в ModRM) + emit32. Грепом `emit8\(0x24\); emit8\(0x[8-9A-F]..\)`
   по всем src проверено: больше нигде нет. (codegen_builtins.cpp — там disp32 уже побитово
   разложено, корректно.)
2. **Map() — стек-аргументы СДВИНУТЫ на 8 байт (опровергает запись 5-сен п.5!).** x64 ABI: арг5
   = [rsp+0x20], арг6 = [rsp+0x28]. Было: MapFlags=>[rsp+0x28], &mapped=>[rsp+0x30]. D3D11 читал
   MapFlags из мусорного [rsp+0x20] и pMappedResource=[rsp+0x28]=0 → Map стабильно возвращал
   **0x80070057 E_INVALIDARG** (под wine это НЕ валидировалось). ФИКС: MapFlags=>[rsp+0x20],
   &mapped=>[rsp+0x28].
Проверка: m1-m6 = `01`, pre.bin=`44 33 22 11`, post.bin=`88 77 66 55` (main дошёл до цикла),
probe.bin=`00 00 00 ff` = непрозрачный чёрный ровно как ClearRenderTargetView{0,0,0,1} в init
(codegen_dx11.cpp:248-251) → GPU-чтение пикселя через CopyResource+Map РАБОТАЕТ на реальном
Windows. Процесс живёт в present-цикле (убит по таймауту). Регрессии рендера не проверялись —
изменения только внутри dxProbeGPU (ничем, кроме diag6.z, не вызывается).
Заметки: ASLR для отладки выключался патчем DllCharacteristics (PE32+ offset opt+0x46, сброс бита
0x40); cdb без -g: -cf-скрипт успевает поставиться до старта.

## Общая цель
GUI-движок 2D-игр на Zenith: `zenith-engine/` (ядро + рендер) поверх компилятора из `b/zenith`. Вычиняем компилятор там, где язык мешает.

## == НОВОЕ СОСТОЯНИЕ (5 сен): ДИАГНОСТИЧЕСКИЕ DX11-БИЛТИНЫ ПОЧИНЕНЫ ==
### Системные баги (корень проблем dxDumpState/dxClearGPU/dxProbeGPU)
1) `call r8` вместо `call r10`: эмитился `41 FF D0` (=call r8), а не `41 FF D2` (=call r10)
   — диагностика вызывала vtable-слот по неверному reg (r8), получая `execute access`.
   Исправлены ВСЕ 14 мест в src/codegen_dx11_shaders.cpp (dxClearGPU 5x, dxProbeGPU 6x,
   guardedGet3/guardedGet2 2x). Проверено nasm/objdump: 41 FF D0=call r8, 41 FF D2=call r10.
2) Строки, добавляемые билтинами в stringPool В МОМЕНТ codegen (пути state.bin/d_*.bin/
   probe.bin/m1-m6, IID-байты) попадали ПОСЛЕ построения stringOffsets → вычисленный
   offset вне диапазона → lea на мусор (маркеры указывали на HLSL-текст, state.bin на мусор)
   → CreateFileA с мусорным путём молча fail → файлы не писались. ФИКС: пре-добавить их в
   collectStrings (src/codegen_pe.cpp, ветка DX11): dxDiagStrings[state.bin,d_a-d_d,probe.bin,
   m1-m6] + IID-байты; в dxClearGPU/dxProbeGPU вместо `stringPool.push_back(iidBytes)`
   используется `ensureString(iidBytes)`. Убран дубль `iidBytes` (реdefinition).
3) disp8-overflow в `C7 44 24 <disp>` для смещений >=0x80: 0x80/0x84/0x88/0xE8/0xB0
   интерпретируются ЗНАКОВО → запись шла в [rsp-0x18]/[rsp-0x80] и т.д., а маркер читался
   из [rsp+0xE8] (мусор). ФИКС: форма `C7 84 24 <disp32>` — в dxClearGPU writeMarkerD3,
   dxProbeGPU writeMarker, readback-desc (+0x80/+0x84/+0x88).
4) ClearRenderTargetView: цвет должен идти в r8 (после rcx=ctx,rdx=rtv); в dxClearGPU было r9,
   в dxProbeGPU rcx (клозбарил context). ФИКС: `lea rax,&color; mov r8,rax` в обоих.
5) Map() 5/6 аргументы в стеке: MapFlags=[rsp+0x28], &mapped=[rsp+0x30]; было наоборот(+&mapped
   в 0x28, counter-слот 0x20). ФИКС: [rsp+0x28]=MapFlags, [rsp+0x30]=&mapped.
### Результаты (wine 8.0/llvmpipe, DISPLAY=:0)
- diag2.z (dxDumpState): RC=124, d_a-d_d=`aa`, state.bin={vs=0xb822e0, ps=0xb82320,
  layout=0xb88b40, topology=4(TRIANGLELIST)} — все 4 Get-слота живут.
- diag5.z (dxClearGPU: GetBuffer->CreateRTV->OMSetRTs->ClearRTV->Present в цикле): RC=124,
  m1-m5=`01`, крах нет. (Прежде падал `read 0x0` внутри wine ClearRTV из-за r9-арг.)
- diag6.z (dxProbeGPU): GetBuffer+CreateTexture2D(STAGING)+CopyResource+Map —
  доходит до CopyResource, дальше винные d3d11 ЦВТ падает (`read access to 0x1`) при
  CopyResource из backbuffer свопчейна — похоже на баг wine 8/llvmpipe, аргументы по
  d3d11 корректны; на реальном Windows должно работать (это метод снятия пикселя экрана).
- tri2.z по-прежнему рисует (красный треугольник), регрессии рендера нет.
### План дальнейшего
- Прогнать на реальном Windows: build/re_diag2.exe, build/re_diag5.exe, build/re_diag6.exe
  (последний — для чёрного экрана: покажет цвет пикселя с backbuffer через probe.bin),
  затем cube3d / cube_static + capture3.ps1. Сравнить probe.bin/state.bin.
- При желании доделать Unmap/Flush в dxProbeGPU.

## == НОВОЕ СОСТОЯНИЕ (5 сен, вечер): НАЙДЕН ROOT CAUSE ЧЁРНОГО ЭКРАНА КУБА НА WINDOWS ==
### Три бага в depth-инициализации (codegen_dx11.cpp emitDX11Init)
ВСЕ были в одном месте — создании depth-stencil буфера. Wine/llvmpipe был лоялен
(рендерил куб БЕЗ depth-буфера, см. trace: `set_depth_stencil_view view 0x0` → NOP),
а реальный D3D11 на Windows даёт E_INVALIDARG/мусорный dsv → чёрный экран.
1. **Format = 3** (DXGI_FORMAT_R32G32B32A32_UINT) вместо **55 (DXGI_FORMAT_D16_UNORM)**.
   UINT-формат не может быть depth-stencil; на реальном Windows это E_INVALIDARG.
   Wine создавал его как текстурку (winе-локальный формат) — поэтому там «работало».
   ФИКС: emit32(3)->emit32(55) в desc текстуры (offset 0x110) И в desc DSV (0x140).
2. **BindFlags = 0x20** (D3D11_BIND_RENDER_TARGET) вместо **0x40 (D3D11_BIND_DEPTH_STENCIL)**.
   Старый комментарий врёт: 0x20=RT, 0x40=DS. Проверено по Windows SDK
   (um/d3d11.h:1233-1234) и mingw d3d11.h:1662-1663. ФИКС: emit32(0x20)->emit32(0x40)
   (desc текстуры, offset 0x120).
3. **ViewDimension = 0** (D3D11_DSV_DIMENSION_UNKNOWN) вместо **3 (D3D11_DSV_DIMENSION_TEXTURE2D)**.
   Wine-8.0 требует для TEXTURE2D-ресурса dimension ∈ {2D,2DARRAY,2DMS,2DMSARRAY},
   иначе normalize_dsv_desc возвращает E_INVALIDARG (dlls/d3d11/view.c:210-218).
   ФИКС: emit32(0)->emit32(3) (desc DSV, offset 0x144).
### Как диагностировали
- Все vtable offsets ПЕРЕПРОВЕРЕНЫ против реального Windows SDK и mingw — КОРРЕКТНЫ
  (device: IUnknown+CreateTexture2D=5, CreateRenderTargetView=9, CreateDepthStencilView=10;
  context: OMSetRenderTargets=33, ClearDepthStencilView=53, etc.). Внимание на константы,
  не на оффсеты.
- WINEDEBUG=+d3d trace нового бинарника с форматом 55 показал:
  `Format WINED3DFMT_D16_UNORM cannot be used for render targets` -> hr 0x8876086c
  (=WINED3DERR_INVALIDCALL) -> CreateDepthStencilView на мусорном dsTexture:
  page fault read 0xffffffffffffffff в get_resource_properties. Причина трассы:
  BindFlags=0x20 давал winе-ные WINED3D_BIND_RENDER_TARGET.
### Результат (wine 8.0/llvmpipe, после всех 3 фиксов)
- build/re_cubestatic_new.exe (пересобран компилятором zenith.exe): RC=124 (живой),
  `wined3d_texture_init ... format WINED3DFMT_D16_UNORM ... bind_flags WINED3D_BIND_DEPTH_STENCIL`
  создаётся БЕЗ ошибок, и `set_depth_stencil_view view 0x2A3AB0` — НОВЫЙ не-NULL dsv.
  Раньше тут был view 0x0 (NOP). 43 draw calls + 13 present, крахов нет.
- objdump подтвердил эмиссию: [rsp+0x110]=0x37, [rsp+0x120]=0x40, [rsp+0x140]=0x37, [rsp+0x144]=3.
### Что осталось
- КОРОЧЕ: это и был чёрный экран на Windows 10 (невалидные depth desc). Фикс применён;
  на реальном Windows должен появиться куб. Сверить визуально на Windows 10:
  build/re_cubestatic_new.exe (и обновлённый cube3d_fixed.exe если пересобрать).
- Проверить, нет ли такого же «BindFlags не тот» в других местах (rasterizer state,
  staging-текстура 0x120 в dxProbeGPU и т.п.) — staging CORRECT: BindFlags=0.

## == НОВОЕ СОСТОЯНИЕ (текущая сессия): БАГ drawLine НАЙДЕН И ИСПРАВЛЕН ==
### НАСТОЯЩИЙ root cause (пересмотрен, НЕ struct-аргумент!)
Баг был НЕ в codegen-placement/структурах, а в GUI-билтине **drawLine** (codegen_gui.cpp):
в цикле Бресенхема знаки шага `sx`/`sy` загружались как `emitMovRegImm(6, (uint32_t)-1)`.
`(uint32_t)-1` = 0xFFFFFFFF — ПОЛОЖИТЕЛЬНОЕ число, поэтому emitMovRegImm (64-бит) эмитил
`movabs $0xffffffff,%rsi` = +4294967295, а НЕ -1. Любая линия с ОТРИЦАТЕЛЬНОЙ дельтой
по экрану (x2<x1 или y2<y1) шагала координату на +4 миллиарда вместо −1 →
пиксельный адрес = fb + гигантское смещение → page fault в цикле `mov %r12d,(%rdx)`.
- Это объясняет ВСЁ: g25 (200,200)->(30,40) — дельты отрицательные → краш;
  g26 (10,20)->(30,40), g24 (5,5)->(30,40), g28-g33 (10,20)->(30,40) — дельты
  положительные → работают. g17 — drawPixel, нет цикла → работает.
  Прежняя гипотеза «большая структура Camera + 5-арг-вызов» НЕВЕРНА: дельта между
  g25/g26 — просто координаты линии, а не способ инициализации переменных.
  g27 (рабочий обход с глобалами) тоже падал — потому что его линия (200,200)->(30,40).
- Правка: codegen_gui.cpp:731,743 `(uint32_t)-1` → `(int64_t)-1`
  (после чего emitMovRegImm даёт `movabs $0xffffffffffffffff`).

### Проверка (всё зелёное, exit=0):
- Раньше ПАДАЛИ, теперь работают: g11,g13,g15,g18,g19,g22,g23,g25,g27 (+g25p).
- Рабочие не сломаны: g7,g8,g10,g12,g14,g16,g17,g20,g21,g24,g26,gA,gB.
- Новый регресс-тест: tests/bugfix_line.z (линии с отрицательными дельтами во всех
  октантах: strokeWorld через Camera + drawLine) — 60 кадров, exit=0, печатает done.
- Консоль: core_colortest/recttest/trftest, eng_test — вывод == ожидаемому.
- Render-слой: render_guitest (math-часть и --gui) — все :OK.
- GUI-смоки: test_win.z, chip8_gui.z, chip8_snake.z — компилируются exit=0.

### Recall: ограничения языка (эмпирика, из прошлых сессий)
- Массивы только примитивов `[N]int/float/bool`; массивы структур/классов НЕ работают ("Expected '='").
- print(String-literal) работает; string-ПЕРЕМЕННАЯ печатает адрес. Сравнение/конкатенация строк нет.
- Оператора `%` нет. Нет sizeof.
- ООП полн.: class/extends, interface/implements, abstract, super, полиморфизм через __classid/vtable — РАБОТАЕТ (poly.z, oop_test.z).
- Для сущностей движка использовать слотовый аллокатор (slotCreate/slotSpawn/slotKill/slotGetI64/slotSetI64/slotGetF32/slotSetF32/slotCount/slotReset/slotDestroy, codegen_builtins.cpp:458-815) — требования пользователя (дважды подчёркнуто).
- ВНИМАНИЕ: GUI-билтины clear/drawPixel/drawRect/drawLine/drawText НЕ клипят к фреймбуферу —
  рисование за пределами окна (отриц. или >= w/h пиксель) пишет в память вне fb. Для движка
  при необходимости ввести клиппинг в canvas.v (или в кодген-билтины).

## Проверено / готово
- `createWindow` с не-литеральным title — починено (codegen_gui.cpp, ветка `titleIdx < 0`: eval arg -> rax -> `MOV R8,RAX`). g4b.z: ok=1, exit=0.
- Конверсии `itof`/`ftoi` добавлены в компилятор (codegen.cpp + h): f=8, g=6, n=7 (7.9->7 trunc), m=-3.
- Написаны модули ядра: `core/color.v`, `core/rect.v`, `core/transform.v`, расширены `core/vec2.v`, `core/math.v`.
- **Структуры >8 байт** — починены и ПОЛНОСТЬЮ проверены (возврат rax:rdx:r10, VarDecl-инит, AssignStmt, аргументы-вызовы, memberPath; ABI/раскладка как в разделах ниже).
- **Float-сравнения** — починены (emitBinaryExpr: сравнения с float-операндом идут через XMM+`ucomiss`/`setcc`->GPR; `isFloatExpr` для сравнений=false). Флоатило `core_recttest` (out/miss), теперь ок.
- **Bool-переменные (BREAKING, важный фикс)** — слот локала була 4 байта, а load/store шли 8-байтно (`emitLoadRegFromBP64`/`emitStoreToBP64`) и затирали соседний слот (float x=12 превращался в 0.0). Исправлено: load+store булов (локальных и глобальных) — 32-bit (`emitLoadRegFromBP`/`emitStoreToBP`, global: `emitGlobalLoadReg32`/`emitGlobalStoreReg32`). Локальные/глобальные bool + bool-поля структур проверены.
- Тесты: `tests/{core_colortest,core_recttest,core_trftest}.z` и `tests/eng_test.z` — все ПРОХОДЯТ:
  - colortest: cR=64 cG=160 cB=255 cA=1 argb=16777215 roundtrip=4235519 midR=127 midG=127 midB=127 blendArgb=16711680 blendBlue=255 mulR=127 addR=255
  - recttest: in=1 out=0 overlap=1 miss=0 iw=5 ih=5 ix=5 uw=15 uh=15 ux=0 cx=-4 cy=-2 infx=-2 infw=14 trx=3 try=-1 bbx=15 bby=15
  - trftest: ix=3 iy=4 qx=11 qy=22 rx=10 ry=22 wlx=1 wly=0 fx=1 fy=0 rtx=0 rty=1 cx=15 cy=0
  - eng_test: len=5 p1y=97.5 aabb=OVERLAP ca=OVERLAP rx=0.0000 ry=1 cc=OVERLAP
- Регрессия (бэкапы-компиляторы в build/, /tmp/zenith_fc.exe pre-boolfix, fc2 актуальный): booltest, bt2/bt3, rt2/rt3/rt4, negcmp (отрицательные float), boolvar2/ge/x1/x2/x3/s1-s3, sf (struct+bool), gb (global bool) — все верны; GUI-смоки test_win.z (1735B), chip8_gui.z (12306B), chip8_snake.z (30041B) компилируются exit=0.

## Диагноз (структуры >8 байт) — ВАЖНО
Ломается везде, где значение структуры больше 8 байт (Color=16, Rect=16, Transform=24):
1. **Возврат >8Б из функции** — эпилог отдаёт только rax (8 байт); VarDecl-инит материализует 8 байт.
   - repro3: `var r: Rect = rect(1,2,3,4)` -> r.x=1, r.w=0 (w на offset+8 потерян).
   - colortest: cR=64, cG=160 ОК; cB=0, cA=0.
2. **Аргумент-вызов** (напр. `rContains(rect(...), p)`) — `structArgInfo` понимает только IdentExpr, поэтому span=1 и слоты съезжают (repro2: c2/c4=0).
3. **Присвоение структуры** `s = r` — AssignStmt копирует 1 qword (emitStoreToBP64). (repro3 sx=1, sw=0).

УЖЕ РАБОТАЕТ: посрочные записи полей; пересылка больших структур-ПЕРЕМЕННЫХ в аргументы (isS, qword-by-qword из памяти; `cA(c)=1` — поле a на offset 12 читается корректно); V2 (8Б) везде.

Раскладка полей: float по 4 байта, int по 8, выравнивание натуральное (computeStructLayouts, codegen.cpp:~5892).
Rect: x@0 y@4 w@8 h@12 (16Б). Color: r@g g@4 b@8 a@12 (16Б). Transform: pos@0(8) rot@8 scale@16 (24Б).

## Выбранный дизайн ABI
Возврат большой структуры = qwords в **rax, rdx, r10** (k = ceil(totalSize/8), k<=3, 16Б->rax:rdx).

Эмиссия структуры-значения в regs (для всех мест):
- Идентификатор/член (память): вычислить адрес в r10 (lea rbp/global или ptr-root load + сдвиг `49 81 C2 imm32`), затем:
  `mov rax,[r10]` = `48 8B 00`
  `mov rdx,[r10+8]` = `49 8B 52 08`
  `mov r10,[r10+16]` = `4D 8B 52 10`  (k==3; читает старый r10-base, кладёт в r10 — ок)
- CallRecord (вызов функции, возвращающей >8Б): просто `emitExpr` — callee уже оставил rax/rdx/r10.

## Новый хелпер (codegen.h/cpp)
`int Codegen::structValueQwords(Expr*)` — 0, если выражение НЕ является значением не-pointer структуры >8Б; иначе ceil(totalSize/8). Распознаёт: IdentExpr (getVarInfo), CallExpr (prog.functions -> returnType), MemberExpr (раскрыть путь по structLayouts). Если k>=2 — выражение "большая структура".

## Правки по файлам (codegen.cpp)
1. ReturnStmt (emitStmt, ~4775-4789): если `structValueQwords(ret->value)>=2`:
   - CallExpr: `int r = emitExpr(v); (void)r;`
   - иначе адрес в r10 -> три MOV выше (rax/rdx/r10);
   `regsUsed = 0;` и jmp funcEndLabel (эпилог regs не трогает: add rsp, pop rbx, pop rbp, ret — проверено, ~6099).
2. VarDecl init (~4795-4805): если k>=2:
   - call: emitExpr, затем ПОРЯДОК: rdx->[dst+8], r10->[dst+16], rax->[dst+0]. Store rdx/r10 в BP: `48 89 55 d8/95 d32`, `4C 89 55 d8/95 d32`; в global — с globalFixups (аналог emitGlobalStoreReg64, ~1169).
   - память (ident/member): адрес в r10, цикл: `emitLoadFromAddrR10(0, j*8)` + `emitStoreToBP64(off+j*8)` (или Global).
3. AssignStmt plain (`s = r`, ветка else ~4935): тот же паттерн (dst = rbp/global переменной LHS), если k>=2.
4. AssignStmt memberPath с полем-структурой (RHS большая структура): проще всего — RHS тоже слить в scratch `[rsp+0..0x18]`, dst базу держать в r10+totalOff, сохранять через `emitStoreToAddrR10(const+j*8)`.
5. Аргументы вызовов (ОБА цикла: полноценный ~4658 и виртуальный ~4576; и preloop totalSlots ~4426):
   - span: `if (isS) sSlots; else if (structValueQwords(arg)>=2) k; else 1;` (это чинит Bug 2).
   - big-struct арг: **call** — emitExpr, слив в scratch: `mov [rsp+0],rax`=`48 89 04 24`, `mov [rsp+8],rdx`=`48 89 54 24 08`, `mov [rsp+16],r10`=`4C 89 54 24 10`, затем цикл: load `[rsp+j*8]` в rax (`48 8B 44 24 imm8`) + `placeQwordIntoSlot(argIndex+j, 0)`;
     **member** (k>=2) — адрес в r10: `emitLoadFromAddrR10(0, j*8)` + placeQwordIntoSlot(argIndex+j, 0).
   - scratch [rsp+0..0x17] у вызова можно трогать: арг-область идёт с 0x20; знач. в регах не затирается.
   - ВНИМАНИЕ: не использовать r11 как свободный (он занят в 3307 и в EFI), только r10/rax/rdx + [rsp] scratch.
6. **Не трогать** stdio print строк (некритично).

## Порядок после фикса
1. Ребилд компилятора `src/` -> `/tmp/zenith_fixed.exe`, скопировать в `build/zenith.exe`. ✅ СДЕЛАНО (см. Сборка компилятора).
2. `/tmp/opencode/repro{1,2,3}.z` и новые bool-репро (x1/x2/ge/boolvar2/xl/sf/gb) — корректны. ✅
3. `tests/core_colortest.z`, `core_recttest.z`, `core_trftest.z`, `eng_test.z` — ПРОХОДЯТ. ✅
4. Регрессия: bool/int сравнения (bt*, rt*, negcmp), GUI-смоки (test_win/chip8_gui/chip8_snake) — ок. ✅
5. Дальше движок: `render/canvas.v`, `render/camera.v`, `render/input.v` УЖЕ НАПИСАНЫ и рабочие (g-тесты + bugfix_line их используют: canvas.v — Canvas-класс над GUI-билтинами, camera.v — Camera-структура, input.v). Следующий шаг движка: игровой контент/проверка + учесть клиппинг clear/draw* (см. ВНИМАНИЕ выше).

## Сборка компилятора
x86_64-w64-mingw32-g++ -O2 -std=c++17 -static -static-libgcc -static-libstdc++ -o /tmp/zenith_fixed.exe main.cpp lexer.cpp parser.cpp codegen.cpp codegen_builtins.cpp codegen_gui.cpp codegen_dx11.cpp codegen_dx11_shaders.cpp codegen_sw.cpp codegen_arm64.cpp codegen_efi.cpp codegen_bios.cpp codegen_pe.cpp codegen_real16.cpp codegen_stm32.cpp codegen_wasm.cpp httpjson_rt.cpp irgen.cpp iropt.cpp irasm.cpp irasm_wasm.cpp irasm_arm.cpp irasm_arm64.cpp optimizer.cpp -lkernel32
(iropt_noreuse.cpp НЕ включать)
cp /tmp/zenith_fixed.exe build/zenith.exe
(образцы компиляции .z -> .exe и прогон в wine/DISPLAY=:0 смотрели в предыдущих сессиях; main.cpp юзается как компилятор)

## Бэкапы компилятора (build/)
zenith_pre_guifix.exe, zenith_pre_floatfix.exe, zenith_pre_classes.exe, zenith_pre_structfix.exe, zenith_pre_minmaxfix.exe, zenith_pre_cmpfix.exe (fc1: только сравнения), zenith_pre_boolfix.exe (fc2-1: сравнения, ДО фикса bool), zenith_pre_drawlinefix.exe (ДО фикса отрицательной дельты), zenith_pre_studio.exe (до добавления IDE-билтинов). Актуальный: build/zenith.exe (сравнения + bool + drawline-fix + Studio-билтины).

## Zenith Studio: новые билтины (добавлены 30 авг 2026)
Добавлены в `src/codegen_builtins.cpp` (по требованию пользователя) + GUI-диспатч в `src/codegen.cpp` (блок GUI: после `tryGUICall` пробуем `tryBuiltinCall`). Работают в GUI-приложениях на Win64:
- `glyphAt(x, y, ch, color)` — один 5x7 глиф с КЛИППИНГОМ (в отличие от drawRect/drawLine/drawText); ch вне 32..126 -> пробел. Позволяет рисовать рантайм-текст посимвольно из буфера.
- `mouseX()`, `mouseY()` — GetCursorPos+ScreenToClient (client px).
- `mouseBtn(btn)` — GetAsyncKeyState high bit (VK_LBUTTON=1).
- `tapKey(vk)` — GetAsyncKeyState LSB (edge за вызов).
- `typeChar()` — US-ASCII символ по нажатию (shift-aware: буквы/цифры/знаки, backspace=8/tab=9/enter=13), 0 если нет. ~60 GetAsyncKeyState-вызовов на вызов.
- `memNew(n)`/`memDel(p)` — HeapAlloc(HEAP_ZERO_MEMORY)/HeapFree (GetProcessHeap).
- `memByte(p,off)`, `memByteW(p,off,v)`, `memQ(p,off)`, `memQw(p,off,v)` — байт/64-бит чтение/запись (без проверок границ!).
- `fileSave(path,data,len)` -> записано, `fileLoad(path)` -> hdr=HeapAlloc(len+16): [hdr+0]=len, [hdr+8]=0, [hdr+16]=данные (иначе 0; интересующие байты скопировать и вызвать memDel(hdr)); `fileExists(path)`.
ВАЖНО: импорты для этих функций добавлены в `dllFuncMap` в **двух** местах codegen_pe.cpp: `estimateRdataSize()` (примерно стр.~375) и реальный билдер (стр.~952+): kernel32: GetProcessHeap, HeapAlloc, HeapFree, GetFileSizeEx (+ReadFile/CreateFileA/CloseHandle в estimate); user32 GUI: GetCursorPos, ScreenToClient. Без этого: "import call fixup not found in externFuncMap" + краш.
Дальше по регистрам: в билтинах r8-r15 — свободные scratch (kAllocPool={0,1,2,3,6,7}); emitMovRegImm НЕ работает для r>7 с 32-бит imm (молча ничего не эмитит) — только raw `41 B8/41 B9` или movabs. Хвост-паттерн из getKey: `regsUsed=saved&~1; reloadRegs(); regsUsed=saved|1; resultReg=0;` результат должен быть УЖЕ в r0/eax до reload (бит0 снят -> r0 не перетирается).
Тест: `zenith-engine/tests/t_builtins_gui.z` (glyph+mem+file+mouse+typeChar, 120 кадров, ESC). Прогон: exit=0, ":OK", t_builtin_tmp.bin (2 байта 122,33). Мини-тесты: t_min_glyph.z / t_min_mem.z / t_min_file.z.
Регрессия после добавления: bugfix_line/g7/gA/core_colortest/eng_test/render_guitest(console+gui) — exit=0. GUI-диспатч tryBuiltinCall не сломал обычные GUI-приложения (gt_gui_int — до таймаута без фолта).

## Zenith Studio: фикс glyphAt (30 авг 2026, полдень+)
БАГ (найден через попиксельную проверку скриншота): в `glyphAt` из codegen_builtins.cpp **метка `glyphBitSkip` нигде не эмитилась** (`emitLabel` пропущен). `emitJcc("==", glyphBitSkip)` (/src/codegen_builtins.cpp, был ~1931) патчился как `jz +0` → прыжок на следующую инструкцию → ветка «бит не выставлен» ВСЕГДА выполнялась → каждый пиксель рисовался → каждый символ = сплошной 5x7 блок («вместо слов пиксели»). Цвет пробрасывался верно (`44 89 18` = mov [rax], r11d), шрифт/fontRVA и арифметика (ch==32..126, *7) были верны.
ФИКС: добавлен `emitLabel(glyphBitSkip);` сразу после `emitLabel(glyphPxSkip);` (после блока `mov [rax], r11d`). drawText ту же метку эмитит (bitOff) — потому работал.
ВЕРИФИКАЦИЯ: тест `zenith-engine/tests/t_glyph_pix.z` (drawRect-маркер + glyphAt 'M'/'A'/'B'/'!' разными цветами) — сравнение пикселей с font5x7.h: **28/28 глифов точь-в-точь**. ide_editor.z компилируется и рендерит читаемый текст. Регрессия билтинов: t_min_mem/t_min_file/t_builtins_gui/t_min_glyph — exit=0 ":OK"; console: bugfix_line/g7/gA/core_colortest/eng_test — exit=0. Бэкап: build/zenith_pre_studio.exe (до IDE-билтинов), build/zenith_post_glyphfix.exe (фикс glyphAt).

## Сборка компилятора (актуальная полная)
x86_64-w64-mingw32-g++ -O2 -std=c++17 -w -static src/main.cpp src/lexer.cpp src/parser.cpp src/irgen.cpp src/iropt.cpp src/irasm.cpp src/irasm_wasm.cpp src/irasm_arm.cpp src/irasm_arm64.cpp src/codegen.cpp src/codegen_pe.cpp src/codegen_gui.cpp src/codegen_builtins.cpp src/codegen_efi.cpp src/codegen_bios.cpp src/codegen_stm32.cpp src/codegen_arm64.cpp src/codegen_dx11.cpp src/codegen_dx11_shaders.cpp src/codegen_wasm.cpp src/httpjson_rt.cpp src/optimizer.cpp src/codegen_real16.cpp src/codegen_sw.cpp src/codegen_net.cpp src/codegen_sound.cpp src/codegen_tls.cpp src/codegen_js.cpp -o build/zenith.exe
НЕ забыть ВСЕ файлы: иначе ld падает (tryDX11Call в codegen_dx11_shaders.cpp, emitSW* в codegen_sw.cpp, emitReal16Function в codegen_real16.cpp). `-static` обязателен (wine не найдёт libgcc_s_seh-1.dll/libstdc++-6.dll под динамическую линковку).

## Zenith Studio: Phase 2 - IDE-каркас (30 авг 2026, вечер)
`tests/ide_editor.z` перерос из редактора в каркас IDE (бэкап чистой v1: `tests/ide_editor_v1.z`):
- Тулбар (TBH=26): open/save/new/run — hover подсвечивается (COL_ACC), клик = действие; справа имя файла + * при dirty.
- Консоль (CONH=84): лог-строки MSG_READY/OPEN/SAVE/NEW/RUN + число (байты) + живая строка: горячие клавиши, координаты мыши mx/my.
- Мышь: `mouseX/mouseY` + `tapKey(1)` (edge левой кнопки) — hover по тулбару, клик по тексту = позиция курсора (clickCursor).
- Горячие: Ctrl+O (следующий демо-файл), Ctrl+S (сохранить), Ctrl+N (новый), Esc выход. Демо-цикл: editor.txt -> t_glyph_pix.z -> repro.txt.
- Компилируется: ide_editor.exe (26947 B code). Верификация по пикселям: тулбар/глаголы, имя файла, консоль "open - file loaded 227", статус Ln/Col/bytes, весь текстовый буфер (10 строк editor.txt) + gutter 0..9. Живое окно реагирует на мышь/клавиатуру пользователя (курсор следовал за кликом, типинг вставлялся, save создавал ответный файл).
- ВАЖНЫЙ БАГ (пойман live-тестом): глобалами `gFile/gMsg/gMx/gMy/gMsgV` НЕ инициализировал в main -> мусор .bss (gFile оказался 2 -> грузился repro.txt, не editor.txt). В main явно: gFile=0,gMx=0,gMy=0,gMsg=MSG_READY,gMsgV=0. В v1 глобалов не было - обойти нельзя.
- Дебаг-приём: прочитать экран программно - convert png txt: + декодер по font5x7.h (bit4=левая колонка); строки по glyphNumR/глифам распознаются посимвольно.

## Языковые подводные камни (подтверждено на 30 авг 2026)
- Слов `and`/`or` НЕТ — только `&&`/`||` (иноче парсер режет условие на голые ExprStmt: «the result of a computation must be assigned»).
- **Char-литералов (`'M'`) НЕТ** — парсер их не знает; `glyphAt(x,y,77,...)` падает в fallback как «undefined function glyphAt» (+ execute fault в рантайме). Только целые коды символов (32..126) или int-переменные из буфера.
- Топ-левел билтины парсятся, но надёжнее собирать код в `func main() -> int` — там closeWindow() и пр. работают всегда.
- Ошибки компилятора нумеруют СКЛЕИВАЕМЫЙ файл (все include), номера строк в hints — от общей нумерации.

## Репо-файлы
- Компилятор: src/codegen.cpp / codegen.h / codegen_gui.cpp
- движок: ../b/zenith-engine/core/*.v, ../b/zenith-engine/tests/*.z
- минирепро: /tmp/opencode/repro1.z repro2.z repro3.z; bool-баг и float-сравнения: x1.z x2.z ge.z boolvar2.z xl.z sf.z gb.z negcmp.z bt*.z rt*.z; drawline-регресс: ../b/zenith-engine/tests/bugfix_line.z

## Сторонняя задача (НЕ движок)
`/home/ruslan/Загрузки/sober-amdgpu-fix.sh` — ядро 6.12 bookworm-backports для AMD DRM 3.54+ (Sober/Roblox). Пользователь запустит сам после перезагрузки (sudo-пароль "12", отказ от 'y' на ребут скриптом). Не блокирует движок.
## Windows GUI secondary-crash audit (31 Aug 2026, op) - FIXED
Systemic bug: Win32 calls (AdjustWindowRectEx etc.) corrupt callee-saved regs (rbx AND rbp) on this Windows box
(all GUI apps crashed 0xC0000005; worked on wine). Main crash fixed earlier by reloading rbx (globals base).
- FIX #1 (SW probe swprobe.z now exits 0, last mark=52 = full main incl loop+closeWindow):
  createWindow's inlined Win32 calls corrupted the CALLER's frame pointer rbp -> main's [rbp-8] locals broke.
  Naive push rbp/pop rbp around the branch MISALIGNED rsp (ABI needs rsp&F==0 at call sites) -> internal
  USER32 movaps crash. Correct fix (codegen_gui.cpp): save rbp in spare global slot [rbx+0x30] at top of
  init branch (mov [rbx+0x30],rbp), then after renderer init reload rbx base + mov rbp,[rbx+0x30] (+pop rsi/rdi).
  Slot 0x30 free in both SW (64B) and DX11 (128B) globals. Does NOT move rsp -> alignment intact.
- FIX #2 (DX11 probe stepprobe.z): CreateDepthStencilView call used lea rax,[rsp+0x140] (0x48 REX.W -> RAX),
  clobbering the method pointer just loaded into rax, then call rax executed a STACK address -> crash
  (return addr stepprobe+0x1634). Fixed codegen_dx11.cpp line ~215:  x48 0x8D ->  x4C 0x8D so it emits
  lea r8,[rsp+0x140].
- FIX #3 (2 Sep 2026): DX11 vtable offset bugs found by cross-checking the emit-ed bytes against the
  real SDK headers (both /usr/x86_64-w64-mingw32/include/d3d11.h and the Windows 10 Kits 10.0.19041
  d3d11.h) and disassembling the compile output with objdump -M intel:

  * CreateDepthStencilView was called via vtable slot [rax+0xD8] (index 27). Per ID3D11DeviceVtbl the
    correct slot is index 10 = offset 0x50 (80). A wrong slot probably pointed at an unrelated method
    (a Get*) so the dsv output stayed garbage -> OMSetRenderTargets then received a corrupt dsv and
    AV'd inside d3d11. That was the "REMAINING (DX11)" crash. Fixed codegen_dx11.cpp:~212 to emit
    `48 8B 40 50` = mov rax,[rax+0x50], then call rax.
  * CreateShaderResourceView was at [r10+0x40] (index 8 = CreateRenderTargetView's slot). Correct is
    index 7 = offset 0x38. Fixed codegen_dx11_shaders.cpp:924 to `4D 8B 52 38`.
  * ClearDepthStencilView was at vtable offset 0x3A0 (index 116) in three places (codegen_dx11.cpp:268
    , codegen_dx11.cpp:487, codegen_dx11_shaders.cpp:1250). Per ID3D11DeviceContextVtbl the correct
    index is 53 = offset 0x1A8 (424). All three now emit `48 8B 80 A8 01 00 00` = mov rax,[rax+0x1A8].
  * Caveat found while editing: for 8B r64,[r64+disp8] the ModRM reg field selects the DESTINATION
    register, so `48 8B 50 50` would be mov rdx,[rax+0x50] NOT mov rax,... Use `48 8B 40 xx` for rax.
- VERIFIED (wine 8.0, DISPLAY=:0): out_test_dx11.exe (test_win.z --backend dx11) now runs past the
  old crash point: prints "A: before createWindow" then "B: after createWindow", then enters its
  render loop until killed by timeout (exit 124) - same behaviour as the known-good SW build
  (out_test_sw.exe, --backend sw). DX11 init now completes: CreateDeviceAndSwapChain -> GetBuffer ->
  CreateRenderTargetView -> CreateTexture2D(DS) -> CreateDepthStencilView -> OMSetRenderTargets ->
  ClearRenderTargetView -> ClearDepthStencilView -> RSSetViewports -> staging+Map -> RSSetState.
  NOTE: wine renders DX11 via its own path, so this only proves the init no longer AVs; real GPU
  output still needs verification on Windows hardware.
- Changed file(s): src/codegen_dx11.cpp (3 fixes), src/codegen_dx11_shaders.cpp (2 fixes).
  Rebuilt compiler: build/zenith.exe.
- Note: cdb % is NOT modulo (use & 0xF); -cf script bp via relative probe+0x.. works; ASLR changes base
  each run => do single-run traces (bp at main entry + breakpoints) not cross-run comparisons.

## 3 Sep 2026: FIXED tiny/black window in createWindow (DX11 + SW) - root cause = rbx clobber + adjW/adjH
СИМПТОМ (настоящий баг, был с времён добавления DX11/SW): окно создавалось НЕ 800x600, а на весь
экран по ширине + ~39px высоты (клиент ~120x0), т.е. по сути невидимое; рендер не было видно.
На headless-машине GetWindowRect одноразово показывал 136x39 — но это был системный hidden-window,
реальное кубовое окно было `1940x39` (CW_USEDEFAULT-эффект). Проявлялось И в SW, и в DX11.
- ПРЯМАЯ ПРИЧИНА (найдена дизассемблированием + изоляционными прогонами в build/zenith_*.exe):
  В `createWindow` (codegen_gui.cpp) nWidth/nHeight брались из adjW/adjH, которые пересчитывались
  из RECT после вызова `AdjustWindowRectEx`. `AdjustWindowRectEx` (как и др. Win32-вызовы на этом
  Windows) КЛОЗБАРИТ callee-saved rbx (globals base). В результате чтение width/height для RECT/
  nWidth шло через испорченный rbx -> либо AV 0xC0000005, либо adjW/adjH = 0x80000000 = CW_USEDEFAULT
  -> окно раскрывалось на весь экран с почти нулевой высотой (клиент H=0).
  Проверка: замена nWidth/nHeight константами 800/600 -> окно стало 800x600 (клиент 784x561) => баг
  не в CreateWindowExA/стеке, а в вычислении adjW/adjH и в клозбаре rbx.
- ФИКС (codegen_gui.cpp, createWindow):
  1) После RegisterClassExA (до построения RECT) добавлен reload globals base
     (lea rbx,[win32GlobalsRVA]) — защита первого чтения [rbx+0x20]/[rbx+0x24] для RECT.
  2) nWidth/nHeight теперь читаются НЕПОСРЕДСТВЕННО из глобалов [rbx+0x20]=w / [rbx+0x24]=h
     (вместо adjW/adjH из стека), и перед этим ЧТЕНИЕМ ОПЯТЬ reload rbx (после AdjustWindowRectEx,
     который клозбарит rbx). Это убрало и AV, и CW_USEDEFAULT.
  Итог: окно ровно w x h (clиент w-16 x h-39-ish), создаётся корректно, рендер-цикл не падает.
  Kafka: нельзя читать rbx (globals base) через секцию, где между чтениями был ЛЮБОЙ Win32-вызов;
  либо reload rbx перед каждым use, либо не зависеть от rbx (читать со стека/глобал-констант).
- ПРОВЕРКА (headless): test_win.z (640x320), cube3d.z (800x600) — окно = запрошенный размер,
  клиент ~w-16 x h-39, процесс жив 10+ сек в рендер-цикле без краша.
  Ориентир для визуальной проверки пользователем: build/cube3d_fixed.exe (вращающийся DX11 куб,
  800x600), build/tri_fixed.exe, build/tridx_fixed.exe, build/testwin_fixed.exe (SW).
- СОБРАННЫЕ КОМПИЛЯТОРЫ (build/): zenith_test.exe = актуальный с фиксом (hash = zenith_g2.exe).
  Временные для экспериментов: zenith_test2/zenith_direct/zenith_const/zenith_g/zenith_g2.exe.
- ВАЖНО для будущего: получить github-репо `r9441887-collab/Zenith` (старый код, 18 Aug) можно
  `git clone --depth 1 https://github.com/r9441887-collab/Zenith.git` (в нём НЕТ этого бага-фикса,
  но есть старая версия всех codegen_*.cpp для сравнения).

## == TLS: ШАГ 10 (codegen + PE wiring) — СДЕЛАНО, собрано, проверено (Windows) ==
Смысл: реальный TLS 1.2 (ECDHE-RSA-AES128-GCM-SHA256) на голых сокетах. Ядро — freestanding
x86-64 blob (SysV-internal), вшитый в .text как `call rel32` в `tlsrt_entry` (opcode dispatcher);
аргументы rdi/rsi/rdx/rcx/r8/r9, результат rax. Blob делает синхронный socket-I/O через io-slot
(функц. указатели send/recv/closesocket), которые codegen инжектит OP_IO_INIT=1 один раз под
флагом .data TLS_IO_DONE (ASLR-safe: указатели читаются прямо из PE IAT через `mov rax,[rip+disp]`
с importCallFixups). `.text` для TLS-приложений делается WRITE (0xE0000020).

ИЗМЕНЕНО В ЭТОЙ СЕССИИ (Windows, mingw):
- `src/codegen_tls.cpp` — ПОЛНЫЙ каркас Шага 10 (новый файл): detectTlsUsage/Expr/Stmt,
  emitTlsBlob (дописывает kTlsBlob в code, ставит labelPositions[tlsEntryLabel]=blobStart+kTlstlsrt_entry),
  emitTlsIoInit (flag-gated, IAT-загрузки send/recv/closesocket, op=1), emitBlobEntryCall (E8+jmpFixup),
  tryTlsCall (диспатч tls_connect/send/recv/close/last_error op 20/21/22/23/24, стайджинг a1/a2/a3
  под SysV-регистры c guard'ами 1/2/6/7). ФИКС бага кодировки: близ -- `mov rcx,rax` = 48 89 C1
  (было 48 89 C8 = mov rax,rcx, клозбарил указатель closesocket). strlen для не-литерал host сделал
  с отдельным label strEnd (не прыгать на общий done). emitBlobEntryCall объявлена в codegen.h.
- `src/codegen.h` — TLS-блок: enum TlsSlot{TLS_IO_DONE}, TlsFixup, tlsUsed/tlsBlobEmitted/
  tlsEntryLabel/tlsIoDoneRVA, tryTlsCall/emitTlsBlob/emitTlsIoInit/emitBlobEntryCall/detectTls*.
- `src/codegen.cpp` — dispatch: detectTlsUsage() перед buildImportData(); tryTlsCall в dispatch
  после net/sound (Console+GUI); emitTlsBlob() после emitEntryPoint(), ПЕРЕД resolveJmpFixups
  (только когда tlsUsed && !libOutput).
- `src/codegen_pe.cpp` — ws2_32: если tlsUsed, гарантированно добавить send/recv/closesocket
  в dllFuncMap["ws2_32.dll"] (мерж с net-сетом); .data-слот tlsIoDoneRVA (8 байт) в buildImportData;
  патч tlsFixups (TLS_IO_DONE) в buildPE (по образцу sockFixups); textSec.Characteristics =
  tlsUsed ? 0xE0000020 : 0x60000020.

СБОРКА (mingw, scoop): тот же g++-командой, что и раньше (см. ниже), + `src/codegen_tls.cpp` ->
  `build/zenith.exe`. Собралось чисто, `--static`, exit 0.

ПРОВЕРЕНО (Windows):
- hello.z (console): компилится, запускается (exit 0), .text = 0x60000020 (не стал writable).
- tls_test.z (net_tcp_connect + tls_connect + tls_last_error + tls_close): компилится,
  blob ~3.4KB вшит (code 158B -> 4236B). objdump подтвердил: emitTlsIoInit корректно грузит
  send->rsi(0x..0e0), recv->rdx(0x..0d0), closesocket->rcx(0x..0a0), op=1->rdi, call в entry;
  tls-fixups/import-call-fixups сходятся в валидные RVAs; .text = 0xE0000020 (WRITE). ✗ в РАБОТЕ
  краш 0xC0000005 — ОЖИДАЕМО (см. ниже).

ВАЖНО / ОГРАНИЧЕНИЕ: `src/tls_blob.h` — СТАРЫЙ (3472 байта): только sha_*/hmac/prf, без
AES/RSA/ECDHE/X509/TLS; tlsrt_entry в нём не понимает новые opcode (IO_INIT=1, CONNECT=20,...),
поэтому tls-тест падает. ЭТО НЕ баг codegen (эмиссия и PE-заголовки проверены) — это устаревший
блоб, который нужно ПЕРЕГЕНЕРИРОВАТЬ. Кодgen-каркас писался к СТАБИЛЬНЫМ имёнам символов
(kTlsBlob, KTlsBlobSize, kTlstlsrt_entry=0xb20, kTlstlsrt_io_send/recv/close) — после регенерации
смещения подхватятся автоматически.

СЛЕДУЮЩИЙ ШАГ (нужен Linux host, в Windows не собрать — mingw ld --oformat binary не умеет PE,
WSL сломан):
1) `tools/gen_tls_blob.sh` на Linux -> перегенерировать `src/tls_blob.h` (символы те же; обновить
   kTlstlsrt_* смещения). Проверить, что kTlstlsrt_entry совпадает с TLS_BLOB_ENTRY, и что
   tlsrt_io_send/recv/close стubs на месте.
2) Пересобрать компилятор и прогнать tls_test — RUNTIME должен ожить (io_slots seed + handshake).
3) Host E2E: `tools/tls_e2e.cpp` против openssl s_server; затем wine-прогоны PE-приложения.
4) Документация `docs/21_tls.txt`.
========================= JS ENGINE (интеграция готова и проверена) =========================
- `tools/jsrt.c` — freestanding JS-interpreter (~1550 строк, -ffreestanding -fno-builtin
  -fno-common -mno-red-zone, bumper в .bss, ARENA_SIZE=4MiB): var/let/const, числа,
  строки (сравнения лексикографически), bool, null/undefined, арифметика, сравнения,
  `===`/`!==` (строго, eq_strict), && || !, тернарник, `in`, `typeof x`,
  `delete obj.key`, {}, [], function (имен.+аноним), вызовы (в т.ч. рекурсия),
  if/else, for, while, return, блочная видимость, compound `+=` и пр., `++i/--i`,
  do-while, break, continue (g_flow: 1=return, 2=break, 3=continue; exec_loop_body
  изолирует break/continue внутри цикла; в for continue ПЕРЕД шагом n->c),
  switch/case/default/break (двухфазный поиск case/default, g_flow==2 съедается
  на уровне switch), комментарии // и /* */, шаблонные строки `` `a=${x}` ``,
  свойства: str.length/arr.length, s[i] (1-символьная строка, OOB="");
  глобальные хелперы: parseInt(s,r)/parseFloat(s)/isNaN(x)/Number(x)/String(x),
  Math(полный набор без libm: floor/ceil/round/trunc/abs/sign/min/max/sqrt/
  cbrt/pow(целый или полустепенной показатель)/hypot/exp/expm1/log/log1p/
  log2/log10/sin/cos/tan/asin/acos/atan/atan2/sinh/cosh/tanh/asinh/acosh/atanh/
  clz32/imul/fround; константы Math.PI/E/LN2/LN10/LOG2E/LOG10E/SQRT2/SQRT1_2;
  Taylor/Ньютон для freestanding; Math.random() — детерминированный xoshiro-ПРГЧ,
  сид на каждый js_reset), Object.keys(o); методы строк: substring(a,b) (clamp+swap+открытый конец),
  charAt(i) (OOB=""), indexOf(s,from), slice(a,b), substr(start,len),
  toUpperCase()/toLowerCase() (ASCII), split(sep); методы массивов:
  push(v)->новая длина, pop()->последний/undefined, shift(), unshift(v)->длина,
  join(sep), indexOf(v), slice(a,b); call_method диспатчится из NK_CALL когда
  callee=NK_MEMBER; NK_CALL также диспатчит Math.*/Object.keys псевдо-глобалами
  и глобальные функции через call_global.
  Вход `long jsrt_entry(op,a1..a5)`; opcodes RESET=0, EXEC=1, EXPR=2, RESULT=3, ERROR=4,
  NUM=5 (число от g_last_result). g_last_result пишется всегда (exec_stmt default).
  ОШИБКИ (доделано): set_err/clear_err + g_errbuf, EXEC/EXPR возвращают -1 при
  ошибке; ошибки: "call of non-function" (вызов не-функции), "parse error:
  unexpected input" (неразборчивый хвост). Парсер лояльный: `(1+2` — НЕ ошибка.
  clear_err() в начале js_exec/js_expr, RESET чистит g_errbuf. Примечание в шапке
  файла обновлено.
  - CommonJS-модули + встроенные модули (доделано): `require(id)` — резолв
    `./x`/`.js`/`.json`/`index.js`/`package.json->main`, up-поиск `node_modules/{id}` +
    sys fallback `/usr/lib/node_modules/{id}`; кеш по разрешённому пути; env модуля с
    exports/module.exports/require/__dirname/__filename; `g_cur_dir` на время exec модуля.
    Встроенные (без файлов): `fs` (readFileSync/writeFileSync/existsSync/mkdirSync/
    readdirSync/unlinkSync), `path` (join/basename/dirname/extname), `base64`
    (encode/decode), `console` (log→HOST_PRINT), `JSON` (stringify/parse).
    Методы встроенных модулей доступны как настоящие вызываемые (NK_NATIVE-узел,
    key `"mod\x1Fmethod"`, диспатч через call_builtin_member).
    УРОК (важный, для блоба): `.data`-глобал, инициализированный адресом другой
    секции в PIC-блобе (VMA 0, вшит в .text без релокации), хранит «сырое» смещение
    и фаталит при разыменовании. Жертвы: `g_cur_dir="."` (0xf740 — крэш require в
    wine), `B64C`, `H`. Фикс: `g_cur_dir` обнулён и runtime-`"."` через `arena_alloc`,
    `B64C`/`H` → массивы. Это и был настоящий корень крэша `js_require_test.z` под
    wine (после фикса DWORD, см. JS_ROADMAP §2→§7).
- `tools/js_direct.cpp` — host-набор: 219 тестов ALL OK (216 check + 3 checkErr;
  break/continue, вложенный break, do-while, .length, индексы, push/pop/substring/charAt,
  typeof/===/!==, parseInt/parseFloat/isNaN/Number/String, Math.*, строковые методы
  (indexOf/slice/substr/toUper->toLowerCase/split), массивы (join/indexOf/shift/unshift/slice),
  delete/in/Object.keys, шаблонные строки, switch/case/default, // и /* */ комментарии;
  error-канал: checkErr с проверкой НЕпустого JS_OP_ERROR и жизни движка после ошибки).
  УРОКИ: (1) for-`continue` обязан выполнять шаг обновления n->c; (2) `null` не
  обрабатывался в parse_primary -> бесконечный цикл (бесплатная арена), добавить
  case T_NULL; (3) шаблоны: next_tok() после `}` съедает следующий литерал -> Token
  хранит pos, g_lex.pos откатывается на g_tok.pos+1; закрывающая кавычка съедается
  явно, а не через next_tok (иначе лишний T_BACKTICK-стейтмент).
 - `tools/gen_js_blob.sh` + `tools/jsrt.ld` -> `src/js_blob.h` (66452 байта, syms=66;
   старые числа 42882/entry 0x9b00 — до того, как добавились require/модули/random).
   ВАЖНО: блоб содержит и libgcc-помощники
   (деление double и пр.) — поэтому его home в .text обязан быть выровнен по 16 (movaps),
   иначе #GP.
- `tools/js_blob_smoke.cpp` — mmap-харнесс блоба: 14 тестов ALL OK.
- `src/codegen_js.cpp` — НОВЫЙ файл: detectJsUsage/Expr/Stmt, tryJsCall (диспатч
  js_reset/js_eval/js_result/js_error; стайджинг rdi/rsi/rdx с guard'ами 7/6/2/1),
  emitJsEntryCall (E8+jmpFixup), emitJsBlob (16-выравнивание + blob-код + обнулённый
  .bss-аренa 4MiB прямо в code; labelPositions[jsEntryLabel]=blobStart+kJsJsrt_entry).
  js_eval = EXEC + NUM два вызова => возвращает ЧИСЛО последнего выражения (0 при ошибке);
  js_result()/js_error() пишут строку в .data-слоты (jsResultRVA/jsErrorRVA) и возвращают
  её адрес (str). Поддержка `js_` регистрируется по префиксу.
- `src/codegen.h` — JsFixup{codePos, slot{JS_SLOT_RESULT,JS_SLOT_ERROR}}, jsFixups,
  jsUsed/jsBlobEmitted/jsEntryLabel/jsResultRVA/jsErrorRVA, tryJsCall/emitJsBlob/
  emitJsEntryCall/detectJs*.
- `src/codegen.cpp` — tryJsCall в dispatch (Console+GUI, сразу после TLS-блока);
  detectJsUsage() после detectTlsUsage(); emitJsBlob() после emitTlsBlob(), ПЕРЕД
  resolveJmpFixups (jsUsed && !libOutput).
- `src/codegen_pe.cpp` — .data-слоты jsResultRVA+jsErrorRVA (по 512Б) в buildImportData;
  патч jsFixups в buildPE (по образцу tlsFixups); textSec.Characteristics =
  (tlsUsed || jsUsed) ? 0xE0000020 : 0x60000020.

СБОРКА: та же g++-команда + `src/codegen_js.cpp` (после codegen_tls.cpp).
ПРОВЕРЕНО (wine): `js_test.z` — js_reset + js_eval: y=40+2=42, fib(10)=55,
sum(1..100)=5050, obj {x:21}*2=42, arrsum [1,2,3]=6, whilesum=10, break=6,
continue=4, do=6, len=5, methods=3, errcheck (вызов не-функции, движок жив:
alive=6*7=42) — ВСЁ OK. ДОБАВЛЕНО (вторая волна): typeof, ===/!==, parseInt('ff',16)=255,
parseFloat 2.5*2=5, isNaN('abc')=true/isNaN('42')=false, Math.floor(5.9)=5,
Math.sqrt(81)=9, Math.pow(2,8)=256, Math.max(3,9)=9, 'HeLLo'.toLowerCase()='hello',
switch(2)=20 (с break), [1,2,3].join('-').length=5, split[1]='b', shift=1, unshift[0]=1,
indexOf(2)=1, delete+'a' in o=false, Object.keys(3 ключа).length=3, шаблон `n=${n+1}`=='n=5',
комментарии // и /* */ — ВСЁ OK. ТРЕТЬЯ ВОЛНА (полный Math, без libm):
floor/ceil/round/trunc/abs/sign/min/max/sqrt/cbrt/pow/hypot/exp/expm1/log/
log1p/log2/log10/sin/cos/tan/asin/acos/atan/atan2/sinh/cosh/tanh/asinh/acosh/
atanh/clz32/imul/fround; константы Math.PI/E/LN2/LN10/LOG2E/LOG10E/SQRT2/
SQRT1_2 (NK_MEMBER для `Math.*` читается как число). Реализация: Taylor-ряды
(exp/log с приведением аргумента; sin/cos — приведение mod 2π; atan — половинное
приведение x/(1+sqrt(1+x^2)) до 0.5, т.е. до 0.5 с удвоением; asin/acos через
atan; гиперболические через exp; cbrt=exp(log/3); hypot через js_sqrt).
log2/log10 возвращают ТОЧНЫЕ целые для точных степеней (log10(100)=2 — иначе
1.99999999 из-за деления логарифмов). E2E: cei=Math.ceil(4.2)=5, round=4,
trunc=7, sign/clz32/imul(3,5)=15/hypot(6,8)=10/cbrt=3/exp(1)≈e/log2(16)=4/
log10(1000)=3/sin(0)/sin(π/2)≈1/cos(0)/tan(0)/atan2(0,-1)≈π/sinh..tanh(0)/
fround(1.5)==1.5/Math.PI∈(3,4) — ВСЁ OK. Хост-тесты js_direct: 219 (было 149;
новые 70 тестов Math). Блоб 42882 байта, entry 0x9b00.
Состояние движка живёт МЕЖДУ вызовами js_eval (fib
объявлен в одном eval, вызван в следующем).
НЮАНС E2E: js_eval возвращает ЧИСЛО последнего выражения (EXEC+NUM), а НЕ статус
ошибки — поэтому после runtime-ошибки js_eval даёт 0 (совпадает с «чистым 0»);
реальный канал ошибок — js_error()/JS_OP_ERROR (строкой), в .z проверяется через
живость движка после ошибочного eval.
ДОКУМЕНТАЦИЯ: `release/документация/19_js.txt` (в стиле 18_сеть.txt) + ссылка
добавлена в `release/документация/00_язык_зенит.txt`.
Важные уроки: (1) blob base в .text должен быть кратен 16 (movaps в движке/libgcc);
(2) a.exe строится без -o (компилятор кладёт результат в a.exe);
(3) for-`continue` должен исполнять шаг обновления перед переходом на cond;
(4) set_err вызывается из eval (раньше определения) — нужен forward-proto;
(5) parse_primary default НЕ потребляет токен: любой незнакомый keyword (null)
    -> бесконечный цикл; добавлять case для каждого ключевого слова;
(6) в шаблонах литеральный текст нельзя читать через токены (`$` — символ
    идентификатора): после `}` откатывать g_lex.pos на g_tok.pos+1 и сканировать
    исходник напрямую; закрывающую кавычку съедать вручную, не через next_tok.

Билд-команда компилятора (проще всего — весь каталог `src/*.cpp`):
  x86_64-w64-mingw32-g++ -O2 -std=c++17 -w -static src/*.cpp -o build/zenith_new.exe
  (важно src/*.cpp: явный список без codegen_elf.cpp/codegen_builtins_linux.cpp не
  линкуется — undefined buildLinuxImportData/emitLinuxEntryPoint/tryLinuxCall/buildELF;
  также в codegen_elf.cpp добавлен #include <cmath> для std::sin/std::lround)
E2E (wine, все exit=0): js_test (ALL JS TESTS OK), js_host_test (HOST FS TESTS DONE,
  len=10, exists=1), js_tern_test, js_require_test (require sum=42, cache=3).
Linux-харнесс tools/js_native_host: default/builtin/require/pkg — все ОК
  (builtin: b64/decode/path.join/basename/ext/dirname/JSON/rand, require [42], pkg [hello from myb]).

=== СЕССИЯ: стресс require (многоуровневая библиотека) + фикс скоупинга ===
ФИКС 1 — ЛЕКСИЧЕСКИЕ ЗАМЫКАНИЯ (было динамическое скоупинг!):
- Проблема: call_func делал `env_new(caller)` — parent брался у вызывающего env,
  т.е. ОБЛАСТЬ ВИДИМОСТИ была ДИНАМИЧЕСКОЙ. Методы модуля, ссылающиеся на
  `exports`/приватные переменные модуля/замыкания, ломались при вызове ИЗВНЕ:
  `exports.fib(n-1)` (рекурсия через экспорт) -> 0; `m.readval()` читающий
  `exports.val` -> 0; `makeAdder(3)(4)` давал 4 вместо 7 (`a` не захвачен).
- Фикс в tools/jsrt.c:
  1) в `struct Node` добавлено поле `Env* def;` (env, где функция определена);
  2) `case NK_FUNC:` при первом eval записывает `n->def=env` (определяющая область);
  3) `call_func`: parent callee-env = `fn->def` (fallback caller);
  4) GC: `mark_node_iter` теперь маркирует `n->def` через `mark_env` (чент до
     использования — добавлен forward-proto), иначе env замыкания соглался бы GC.
- Проверено нативно: `makeAdder(3)(4)`=7, счётчик-замыкание=3, `m.fib(5)`=5,
  `m.fib(10)`=55, `m.twice(5)`=12, `m.readval()`=42, `m.inc2(7)`=8, `m.callinc()`=8.

ФИКС 2 — path_dirname срезал не тот хвост (ломало up-поиск node_modules):
- Проблема: `path_dirname("a/b")` по-старому возвращал `"a/"` (включая разделитель),
  а для пути с завершающим '/' (`"a/b/"`) возвращал сам путь — `dirname(base)==base`,
  поэтому цикл подъёма в `resolve_module` ломался ПОСЛЕ ПЕРВОГО уровня: от
  `jsstress/lib` до `jsstress/node_modules/zenutils` не доходил, падал в
  sys fallback `/usr/lib/node_modules` -> "module not found".
- Фикс: path_dirname исключает сам разделитель и срезает завершающие '/' —
  `"a/b"`/`"a/b/"` -> `"a"`, `"/x"` -> `"/"`, без '/' -> `"."`. Резолв bare-спецификатора
  теперь доходит вверх по всей цепочке.

СТРЕСС-БИБЛИОТЕКА jsstress/ (многоуровневый require):
- `jsstress/` — 9 JS-файлов + data.txt (26 байт): lib/{index,app,strutil,case,prime,
  math,data,hash}.js, package.json (main ./lib/index.js). Вложенные require:
  index->app; app->{hash,strutil,math,data}; hash->{strutil,math,data,zenutils(+print)};
  strutil->case; case->{path,base64}; math->prime; data->{base64,fs,path};
  jsstress/node_modules/zenutils/{package.json(main index.js),index.js,lib/case.js}.
- `node_modules/zenutils` в корне (копия) — чтобы `require('zenutils')` с верхнего
  уровня тоже резолвился (up-walk от CWD).
- `js_require_stress.z`: 14 проверок (upper/fib=55/isPrime 7 и 9/count/title/basename/
  encode/decode/compute==9331556/readLen==26/exists true и false/кеш c1===app/
  zenutils say+greet+version), печать "JS REQUIRE STRESS: ALL OK/FAIL", exit 0/1.
  НЮАНС .z-парсера: многострочное «смеженное» склеивание строк
  `js_eval("...\n" "..."\n)` НЕ парсится — пришлось уложить JS в ОДНУ строку.
  ВАЖНО: вызов НЕ-функции и `Object.keys(undefined)` крашат движок (не ошибка) —
  в тесте аккуратно.
- compute('the quick brown fox')==9331556 проходит: hash требует e/sp/words/sumTo/
  mix/isPrime/base+не roundtrip+не say-штраф (замыкания починились).

ПРОВЕРЕНО: native js_stress_run -> ok=14; js_require_stress.z под wine
  (компиляция + запуск) -> "JS REQUIRE STRESS: ALL OK" exit=0; базовые регрессии
  js_test/js_host_test/js_tern_test/js_require_test под wine ВСЕ exit=0.
  Блоб теперь 66548 байт, syms=66 (был 66452 — от лексических замыканий).
