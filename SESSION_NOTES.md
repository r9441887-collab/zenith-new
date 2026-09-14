# Zenith — сессия Wayland/Vulkan (заметки для продолжения)

> Сохранено 2026-09-11. Цель: починить Wayland (окна не появлялись) и добавить
> полноценный Vulkan-рендеринг в окно Wayland (raw x86-64, без libwayland/libvulkan).

## Окружение и сборка
- Путь: `/media/ruslan/D64ED4304ED40ADF/Users/user/Desktop/b/zenith`
- Сборка компилятора: `make -f Makefile.linux -j$(nproc)` → `build/linux/zenith`
- Компиляция .z: `./build/linux/zenith wltest.z` → `a.elf` (после этого `chmod +x a.elf`!)
- Запуск: `./a.elf`. Живой Wayland: `XDG_RUNTIME_DIR=/run/user/1000`, `WAYLAND_DISPLAY=wayland-0` (GNOME/Mutter)
- gdb/strace есть. Диск NTFS (nosuid,nodev) → chmod обязателен.

## СДЕЛАНО и проверено
1. Wayland-баг (`wl_list_globals` печатал мусор и SEGV) — ИСПРАВЛЕН.
   Причина: x86-64 `syscall` клобберит `rcx`/`r11` (rcx = RIP после syscall). Указатель
   на событие `&inbuf[r12]` держался в rcx через `write()` → чтение `[rcx+8]` брало
   байты кода из .text. Найдено через gdb (`rcx=0x401421`).
   Фикс в `src/codegen_wl_linux.cpp`: 3 вставки `lea rcx,[r8+r12]` (`4B 8D 0C 04`)
   перед чтением name `[rcx+8]`, slen для version `[rcx+12]`, size `[rcx+6]`.
2. Тест `wltest.z` (корень проекта): `wl_open` → fd 3; `wl_list_globals` печатал ВСЕ
   24 глобала GNOME (wl_compositor:1:5, wl_shm:3:1, wl_seat:14:8, xdg_wm_base:9:4, ...),
   `globals=24`, `wl test done`, exit=0. (Пользователь запускал `a.elf` — работает.)
3. Vulkan-бэкенд headless изучен (см. ниже).

## ВАЖНЫЕ МЕХАНИКИ КОДА
- Аллокатор регистров: пул `{0=rax,1=rcx,2=rdx,3=rbx,6=rsi,7=rdi}` (kAllocPool кодgen.cpp:16).
  r12/r13/r14 аллокатор НЕ выдаёт — можно использовать как персистентные scratch.
  volatile-регистры нельзя держать со значениями через `emitExpr` (может выдать 0-3,6,7).
- Паттерн хендлера builtin (см. `tryLinuxWLCall`, codegen_wl_linux.cpp:104+):
  `saved=regsUsed; spillRegs(); regsUsed=0;` → `sub rsp,8` + push rdi,rsi,r12,r13,r14 →
  код → `wlLeave(done)` (pop+add+jmp) → общий exit: `regsUsed=0; freeReg(1,2,3); r=allocReg();
  mov r0; regsUsed = saved ~(1<<r); reloadRegs(); regsUsed = saved|(1<<r); resultReg=r; return true;`
- `wlLeave` lambda уже есть в codegen_wl_linux.cpp; `leaRip(r,rva)`, `svc(nr)`, `emitDecWrite`
  тоже там. Для нового кода скопировать эти лямбды (или читать оттуда их байты).
- `globalFixups.push_back({code.size(), rva}); emit32(0);` → RIP-фикс для слотов.
- detectWLExpr уже помечает ЛЮБОЕ имя `wl_` как used → `wl_create_window`/`wl_present`/... 
  автоматически попадут в buildLinuxImportData (слоты аллоцируются в codegen_elf.cpp).

## СЛОТЫ УЖЕ ДОБАВЛЕНЫ (codegen.h + codegen_elf.cpp .data)
wlWNameRVA, wlXdgNameRVA, wlShmNameRVA (4B поим registry global'а),
wlSurfIdRVA=6, wlXdgIdRVA=7, wlTopIdRVA=8, wlShmIdRVA=9, wlPoolIdRVA=10, wlBufIdRVA=11
(4B объект-айди), wlFbPtrRVA (8B mmap), wlBufFdRVA (8B memfd), wlWinWRVA/HRVA (4B),
wlConfiguredRVA (4B), wlClosedRVA (4B), wlOutRVA (256B скретч для запросов).
Строки в .rdata: wlCompositorStrRVA, wlXdgWmBaseStrRVA, wlShmStrRVA,
wlMemfdNameRVA="z-wl-fb", wlAppIdRVA="zenith-app".
Декларация в .h: `bool tryLinuxWLWindowCall(CallExpr*, int&);` — ФАЙЛ
`src/codegen_wl_window.cpp` ЕЩЁ НЕ СОЗДАН (call не диспатчится в tryLinuxWLCall!).

## ПЛАН: Wayland-окно (объект-айди и opcode'ы — ПРОВЕРЕННАЯ схема)
Выделены: display=1, registry(_global)=2, sync-callback=3, compositor=4, xdg_wm_base=5,
surface=6, xdg_surface=7, toplevel=8, wl_shm=9, pool=10, buffer=11, discovery registry=20.

Байты события/запроса: заголовок 8B = u32 id, u16 opcode, u16 size.
Строка в проводе: u32 length(BYTE-COUNT ВКЛ NUL) + байты + пад до 4. Под macOS:
offset len @8, bytes @12, align4(12+len) = конец строкового блока.

wl_create_window(w,h,title) -> 0|-1:
1. Проверка fd (wlFdRVA>0), обнулить wlConfiguredRVA/wlClosedRVA.
2. Discovery: в wlOutRVA собрать get_registry(new_id=20)+sync(new_id=3) (общий 24B,
   как в wlInitReqRVA) → write(fd). Читать события, в registry.global (id=20 op0:
   name @[+8], slen @[+12], bytes @[+16], version после align4) сравнивать интерфейс
   с "wl_compositor"(14)/"xdg_wm_base"(12)/"wl_shm"(7) и сохранить name в слот;
   при callback.done (id=3) — выйти.
3. bind: registry(2) opcode=0: name, строка-интерфейс, version, new_id.
   Размер = align4(16+len)+8. compositor vers=4 (id 4), xdg vers=4 (id5), shm vers=1 (id9).
4. create_surface: id4 op0 size12 (id6).
   get_xdg_surface: id5 op2 size16 args(7,6). get_toplevel: id7 op1 size12 args(8).
   set_title: id8 op2, runtime-build: len=strlen+1 @8, байты @12, size=align4(12+len).
   set_app_id: id8 op3 "zenith-app" (len11, align4(23)=24).
5. Фреймбуфер: memfd_create("z-wl-fb",0)=319; ftruncate(fd, len)=77;
   mmap(0,len,PROT_RDWR=3,MAP_SHARED=1,fd,0)=9; len=align4(w*h*4), stride=w*4.
   create_pool: id9 op0 size20 args(memfd, len, new_id=10).
   create_buffer: id10 op0 size32 args(offset=0, w, h, stride, ARGB8888=0x34325241, new_id=11).
6. Первый present: attach(id6 op1 size20 args(11,0,0)) → damage( id6 op9 size24
   args(0,0,w,h) ) → commit(id6 op6 size8).
7. ждать xdg_surface.configure (id7 op0, serial @[+8]) → ack_configure(id7 op4 size12
   serial) + commit → wlConfiguredRVA=1, вернуть 0. По пути отвечать на
   xdg_wm_base.ping(id5 op0 → pong id5 op3 size12 serial).

wl_present: attach+damage(w,h из слотов)+commit, вернуть 0.
wl_process: recv(fd, wlInRVA, 4096, MSG_DONTWAIT=0x40) syscall45(r10=флаги) циклом;
   id8 op1 (toplevel.close) → wlClosedRVA=1, вернуть 0; id5 op0 (ping) → pong;
   иначе вернуть 1 (работает).
wl_close_window: destroy surface(id6 op0 size8), buffer(id11 op0), pool(id10 op1);
   munmap(fb, len)=11 (len=align4(w*h*4)); close(memfd)=3; close(display fd)=3, обнулить fd.
wl_fb -> указатель на framebuffer (загрузка [wlFbPtrRVA]).

Дисциплина регистров в новом эмиттере: r13 = &wlOutRVA (база скретча), r14 = свободный
scratch, в циклах чтения r12d = смещение в событии, r8 = &wlInRVA, rbx = n байт.
ПОМНИТЬ: после каждого syscall перезагружать rcx (lea rcx,[r8+r12])!

## ПЛАН: Vulkan → окно Wayland
- Сейчас codegen_vulkan.cpp headless: vk_api_version/vk_instance_version/vk_instance_create/
  vk_destroy_instance/vk_gpu_count/name/api/vendor/device. libvulkan.so.1 через ELF-импорты,
  functions level instance кешируются через vkGetInstanceProcAddr в .data.
- Решение по архитектуре НЕ принято (нужно спросить пользователя):
  (a) полноценный WSI VK_KHR_wayland_surface — нереально/хрупко, требует подделки
      структур libwayland (wl_display*, wl_surface*) для vkCreateWaylandSurfaceKHR;
  (б) GPU-рендер в свой VkImage → blit/readback в shm-фреймбуфер (wl_fb) → present
      через wl_surface.commit — проще и надёжно (РЕКОМЕНДУЕТСЯ).

## ФАЙЛЫ
- `src/codegen_wl_linux.cpp` — исправленный бэкенд, base для окон (копировать лямбды)
- `src/codegen_wl_window.cpp` — НЕ СОЗДАН, создать: эмиссия оконных builtins
- `src/codegen.h` + `src/codegen_elf.cpp` — слоты уже добавлены
- `src/codegen_vulkan.cpp` — headless Vulkan (расширять, если (б))
- `src/codegen_gui.cpp` — паттерн createWindow (Windows) строка ~216
- `Makefile.linux`, `wltest.z` (рабочий), `vktest.z`
- Тестовые .z в корне; tools/ — C/C++ смоки.

## СЛЕДУЮЩИЙ ШАГ (после загрузки)
1. Создать `src/codegen_wl_window.cpp`: tryLinuxWLWindowCall с прологом (как
   tryLinuxWLCall) и 5 хендлерами (wl_create_window/wl_present/wl_process/
   wl_close_window/wl_fb). Диспатчить в tryLinuxWLCall в начале: имена window →
   tryLinuxWLWindowCall.
2. Собрать; тест: .z файл, который создаёт окно, рисует градиент в wl_fb, present,
   loop wl_process, на close — exit. Проверить, что окно появляется на GNOME.
3. Затем Vulkan (вариант б): vk_instance_create + extensions не нужен без WSI,
   vkEnumeratePhysicalDevices, create device/queue, VkImage (достаточно для CPU
   write или GPU draw), затем рендеринг.

## Готовый тест-код для .z (набросок)
```
import std
const w=800; h=600
var fd = wl_open()
var win = wl_create_window(w, h, "Test Window")
if win != 0 { ... }
var fb:u64 = wl_fb()
for y in range(0, h) { for x in range(0, w) { ... fb[y*800+x] = color }}
wl_present()
var running = 1
while running == 1 {
    running = wl_process()
}
wl_close_window()
wl_close(fd)
```