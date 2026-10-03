#include "codegen.h"
#include "syslibs.h"
#include <algorithm>
#include <cstring>
#include <cstdio>
#include <cmath>
#include <fstream>
#include <iostream>
#include <map>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <string>

// ============================================================================
// Linux target (app linux): ELF64 executable emitter + SysV runtime support.
//
// RVA model (internal, base = 0):
//   RVA(.text)  = textRVA  = 0x1000
//   RVA(.rdata) = rdataRVA = textRVA + 0x1000 = 0x2000
//   RVA(.data)  = dataRVA  = rdataRVA + 0x1000 = 0x3000
// The machine code vector `code` occupies .text; `rdata` and `data` hold the
// string pool / read-only data and writable globals / GOT respectively. All
// RIP-relative disp32 fixups emitted by the shared x86 backend are computed
// as (targetRVA - (textRVA + codePos + 4)), which stays identical under the
// base-0 ELF mapping — so resolveFixups() output is reused as-is.
//
// The actual load base is LOAD_BASE, added to every VA written into the ELF
// header / program headers (e_entry, p_vaddr, p_paddr). Modern Linux kernels
// (>= ~4.5, mmap_min_addr) reject ET_EXEC whose survivable LOAD starts below a
// minimum address (default 0x10000); 0x1000-loaded binaries segfault at exec.
// Because every code reference is RIP-relative, shifting the whole image by a
// constant base requires changing ONLY the header VAs, never any disp32.
//
// OS access (print, memory, files, sockets, GUI, graphics, sound) is either a
// raw Linux syscall or a call through a GOT slot. C-library imports (libX11,
// libvulkan, libasound, libc) go through .dynsym/.rela/.dynamic + PT_INTERP:
// the kernel hands the program to ld.so, which resolves the GOT slots
// (R_X86_64_64) from the DT_NEEDED libraries before control reaches _start.
// Console/cpu-only programs (no imports) keep the fully static layout.
// ============================================================================

namespace {

// ---- ELF64 constants (no external headers needed) ----
constexpr uint8_t  EI_NIDENT = 16;
constexpr uint8_t  ET_EXEC   = 2;
constexpr uint8_t  ET_DYN    = 3;   // shared object (dlopen-able .so)
constexpr uint64_t EM_X86_64 = 62;
constexpr uint8_t  ELFCLASS64 = 2;
constexpr uint8_t  ELFDATA2LSB = 1;
constexpr uint8_t  EV_CURRENT = 1;
constexpr uint8_t  ELFOSABI_SYSV = 0;

constexpr uint32_t PT_LOAD = 1;
constexpr uint32_t PT_DYNAMIC = 2;
constexpr uint32_t PT_INTERP = 3;
constexpr uint32_t PF_X = 1;
constexpr uint32_t PF_W = 2;
constexpr uint32_t PF_R = 4;

// .dynamic tags (glibc elf.h).
constexpr uint64_t DT_NULL = 0;
constexpr uint64_t DT_NEEDED = 1;
constexpr uint64_t DT_STRTAB = 5;
constexpr uint64_t DT_SYMTAB = 6;
constexpr uint64_t DT_RELA = 7;
constexpr uint64_t DT_RELASZ = 8;
constexpr uint64_t DT_RELAENT = 9;
constexpr uint64_t DT_STRSZ = 10;
constexpr uint64_t DT_HASH = 4;
constexpr uint64_t DT_SYMENT = 11;
constexpr uint64_t DT_INIT = 12;       // .init_array-style initializer function address

// ELF64 symbol / relocation constants.
constexpr uint64_t R_X86_64_64 = 1;        // S + A
constexpr uint64_t R_X86_64_COPY = 5;      // copy data from shared object
constexpr uint64_t R_X86_64_RELATIVE = 8;  // B + A (load-base-relative)
constexpr uint8_t  STB_GLOBAL = 1;
constexpr uint8_t  STT_FUNC = 2;
constexpr uint8_t  STT_OBJECT = 1;

// Load base for the ELF image (conventional non-PIE text start, same as gcc).
// Must be >= mmap_min_addr (default 0x10000); use 0x400000 for safety.
constexpr uint32_t LOAD_BASE = kLinuxLoadBase;

void put16(std::vector<uint8_t>& v, uint16_t x) {
    v.push_back(x & 0xFF); v.push_back((x >> 8) & 0xFF);
}
void put32(std::vector<uint8_t>& v, uint32_t x) {
    v.push_back(x & 0xFF); v.push_back((x >> 8) & 0xFF);
    v.push_back((x >> 16) & 0xFF); v.push_back((x >> 24) & 0xFF);
}
void put64(std::vector<uint8_t>& v, uint64_t x) {
    for (int i = 0; i < 8; i++) v.push_back((x >> (8 * i)) & 0xFF);
}

} // namespace

// ============================================================================
// Detect which subsystems the program uses. Mirrors detectSoundUsage etc. but
// must NOT create PE-only import state. Called after collectStrings().
// ============================================================================
static void scanExpr(Codegen* self, Expr* e, bool& http, bool& sock, bool& snd);
static void scanStmt(Codegen* self, Stmt* s, bool& http, bool& sock, bool& snd);

void Codegen::detectLinuxNeed() {
    // Placeholder: current Linux backend resolves OS imports lazily through
    // elfImportFixups, so no PE-style pre-detection is required. Left as a hook
    // for future syscall-slot preallocation.
}

// ============================================================================
// buildLinuxImportData: fills .rdata/.data exactly like the tail of
// buildImportData() (string pool, class name/font, heap, globals, sound/net/
// tls/js slot state), but without any PE import descriptors. Uses the same
// RVA conventions so the shared fixup patching in buildELF / resolveFixups
// continues to work unchanged.
// ============================================================================
void Codegen::buildLinuxImportData() {
    rdata.clear();
    data.clear();

    auto writeDQ = [](std::vector<uint8_t>& buf, uint64_t val) {
        for (int i = 0; i < 8; i++) buf.push_back((val >> (8 * i)) & 0xFF);
    };

    // Ensure newline string is in the pool for print()
    bool hasNl = false;
    for (auto& s : stringPool) if (s == "\r\n") { hasNl = true; break; }

    // String pool — pool-relative offsets (mirrors PE buildImportData tail).
    uint32_t stringPoolStart = (uint32_t)rdata.size();
    stringRVA = rdataRVA + stringPoolStart;
    for (auto& s : stringPool) {
        stringOffsets.push_back((uint32_t)rdata.size() - stringPoolStart);
        for (char c : s) rdata.push_back((uint8_t)c);
        rdata.push_back(0);
    }
    while (rdata.size() % 16 != 0) rdata.push_back(0);

    if (prog.appType == AppType::GUI) {
        classNameRVA = rdataRVA + (uint32_t)rdata.size();
        const char* cn = "ZenithWnd";
        for (const char* p = cn; *p; p++) rdata.push_back((uint8_t)*p);
        rdata.push_back(0);
        while (rdata.size() % 16 != 0) rdata.push_back(0);
    }

    // Heap offset + free-list head + rand seed (in .data).
    heapOffsetRVA = dataRVA + (uint32_t)data.size();
    for (int k = 0; k < 8; k++) data.push_back(0);
    heapFreeHeadRVA = dataRVA + (uint32_t)data.size();
    for (int k = 0; k < 8; k++) data.push_back(0);
    randSeedRVA = dataRVA + (uint32_t)data.size();
    for (int k = 0; k < 8; k++) data.push_back(0);

    // Socket / sound / tls / js slot state (same layout & order as PE).
    if (netSocksUsed) {
        sockWsaStartedRVA = dataRVA + (uint32_t)data.size();
        for (int k = 0; k < 8; k++) data.push_back(0);
        sockWsadataRVA = dataRVA + (uint32_t)data.size();
        for (int k = 0; k < 416; k++) data.push_back(0);
        sockPeerRVA = dataRVA + (uint32_t)data.size();
        for (int k = 0; k < 16; k++) data.push_back(0);
        sockPeerLenRVA = dataRVA + (uint32_t)data.size();
        for (int k = 0; k < 8; k++) data.push_back(0);
        // Linux net: last-error slot + peer IP string buffer (PE uses wininet/wsa
        // instead; these two are only referenced by codegen_net_linux.cpp).
        linNetErrRVA = dataRVA + (uint32_t)data.size();
        for (int k = 0; k < 8; k++) data.push_back(0);
        linNetIpBufRVA = dataRVA + (uint32_t)data.size();
        for (int k = 0; k < 16; k++) data.push_back(0);
    }
    if (soundUsed) {
        soundOpenedRVA = dataRVA + (uint32_t)data.size();
        for (int k = 0; k < 8; k++) data.push_back(0);
        soundHwoRVA = dataRVA + (uint32_t)data.size();
        for (int k = 0; k < 8; k++) data.push_back(0);
        soundFmtRVA = dataRVA + (uint32_t)data.size();
        for (int k = 0; k < 24; k++) data.push_back(0);
        soundBpfRVA = dataRVA + (uint32_t)data.size();
        for (int k = 0; k < 8; k++) data.push_back(0);
        soundHdrRVA = dataRVA + (uint32_t)data.size();
        for (int k = 0; k < 56; k++) data.push_back(0);
        soundSeedRVA = dataRVA + (uint32_t)data.size();
        for (int k = 0; k < 8; k++) data.push_back(0);
        soundLutRVA = dataRVA + (uint32_t)data.size();
        for (int i = 0; i < 512; i++) {
            double v = std::sin(2.0 * 3.14159265358979323846 * (double)i / 512.0);
            int16_t s = (int16_t)std::lround(v * 32767.0);
            data.push_back((uint8_t)(s & 0xFF));
            data.push_back((uint8_t)((s >> 8) & 0xFF));
        }
    }
    if (tlsUsed) {
        tlsIoDoneRVA = dataRVA + (uint32_t)data.size();
        for (int k = 0; k < 8; k++) data.push_back(0);
    }
    if (jsUsed) {
        jsResultRVA = dataRVA + (uint32_t)data.size();
        for (int k = 0; k < 512; k++) data.push_back(0);
        jsErrorRVA = dataRVA + (uint32_t)data.size();
        for (int k = 0; k < 512; k++) data.push_back(0);
    }

    // Linux Vulkan: .rdata strings (app/engine name + proc-addr lookup names)
    // and .data struct slots for instance state, the resolved fn table, the
    // physical-device handle array and VkPhysicalDeviceProperties scratch.
    // Allocated here (before buildELF) because buildELF patches RIP-relative
    // slot references against these final RVAs.
    if (vkUsed) {
        auto addRdataStr = [&](const char* s) {
            uint32_t rva = rdataRVA + (uint32_t)rdata.size();
            for (const char* p = s; *p; p++) rdata.push_back((uint8_t)*p);
            rdata.push_back(0);
            return rva;
        };
        vkZenithStrRVA   = addRdataStr("Zenith");
        vkDestroyStrRVA  = addRdataStr("vkDestroyInstance");
        vkEnumPhyStrRVA  = addRdataStr("vkEnumeratePhysicalDevices");
        vkPhyPropsStrRVA = addRdataStr("vkGetPhysicalDeviceProperties");
        vkDevProcStrRVA  = addRdataStr("vkGetDeviceProcAddr");
        while (rdata.size() % 16 != 0) rdata.push_back(0);

        vkInstRVA    = dataRVA + (uint32_t)data.size();   // VkInstance
        for (int k = 0; k < 8; k++)  data.push_back(0);
        vkAppInfoRVA = dataRVA + (uint32_t)data.size();   // VkApplicationInfo (48B)
        for (int k = 0; k < 48; k++) data.push_back(0);
        vkInstInfoRVA= dataRVA + (uint32_t)data.size();   // VkInstanceCreateInfo (64B)
        for (int k = 0; k < 64; k++) data.push_back(0);
        vkFnTableRVA = dataRVA + (uint32_t)data.size();   // fn ptrs (6 * 8B)
        for (int k = 0; k < 48; k++) data.push_back(0);
        vkCountRVA   = dataRVA + (uint32_t)data.size();   // enumerate count
        for (int k = 0; k < 8; k++)  data.push_back(0);
        vkPhyBufRVA  = dataRVA + (uint32_t)data.size();   // device handles (64 * 8B)
        for (int k = 0; k < 512; k++) data.push_back(0);
        vkPropsRVA   = dataRVA + (uint32_t)data.size();   // VkPhysicalDeviceProperties
        for (int k = 0; k < 2048; k++) data.push_back(0);
    }

    // Linux Wayland: .rdata constants (env prefix, socket suffix, request blob)
    // and .data slots for the connected fd/event buffer/etc. Raw syscalls only
    // (codegen_wl_linux.cpp) — the display socket path comes from envp, which
    // emitLinuxEntryPoint stashes into wlEnvRVA as soon as _start runs.
    if (wlUsed) {
        auto addRdataStr = [&](const char* s) {
            uint32_t rva = rdataRVA + (uint32_t)rdata.size();
            for (const char* p = s; *p; p++) rdata.push_back((uint8_t)*p);
            rdata.push_back(0);
            return rva;
        };
        wlXdgRVA   = addRdataStr("XDG_RUNTIME_DIR=");
        wlSfxRVA   = addRdataStr("/wayland-0");
        wlColonRVA = addRdataStr(":");
        wlNlRVA    = addRdataStr("\n");
        // Window builtins (codegen_wl_window.cpp): interface strings are matched
        // against registry.global announcements and sent verbatim in bind and
        // app_id requests.
        wlCompositorStrRVA = addRdataStr("wl_compositor");
        wlXdgWmBaseStrRVA  = addRdataStr("xdg_wm_base");
        wlShmStrRVA        = addRdataStr("wl_shm");
        wlMemfdNameRVA     = addRdataStr("z-wl-fb");
        wlAppIdRVA         = addRdataStr("zenith-app");

        // Two-way init handshake as a static 24-byte blob. Wire header is
        // 8 bytes: u32 object id | u16 opcode | u16 size (incl header); the
        // size of a request taking one new_id arg is therefore 12.
        //   wl_display.get_registry(new_id=2): id=1 opcode=1 size=12 + uint(2)
        //   wl_display.sync(new_id=3):         id=1 opcode=0 size=12 + uint(3)
        static const uint8_t initReq[24] = {
            0x01,0x00,0x00,0x00, 0x01,0x00, 0x0c,0x00, 0x02,0x00,0x00,0x00,
            0x01,0x00,0x00,0x00, 0x00,0x00, 0x0c,0x00, 0x03,0x00,0x00,0x00,
        };
        wlInitReqRVA = rdataRVA + (uint32_t)rdata.size();
        for (size_t k = 0; k < sizeof(initReq); k++) rdata.push_back(initReq[k]);

        wlEnvRVA  = dataRVA + (uint32_t)data.size();   // envp pointer
        for (int k = 0; k < 8; k++) data.push_back(0);
        wlFdRVA   = dataRVA + (uint32_t)data.size();   // wayland socket fd
        for (int k = 0; k < 8; k++) data.push_back(0);
        wlPathRVA = dataRVA + (uint32_t)data.size();   // sockaddr_un (family + path)
        for (int k = 0; k < 128; k++) data.push_back(0);
        wlInRVA   = dataRVA + (uint32_t)data.size();   // event buffer
        for (int k = 0; k < 4096; k++) data.push_back(0);
        wlTmpRVA  = dataRVA + (uint32_t)data.size();   // decimal scratch
        for (int k = 0; k < 32; k++) data.push_back(0);

        // Window / shm-framebuffer state (codegen_wl_window.cpp).
        wlWNameRVA = dataRVA + (uint32_t)data.size();
        for (int k = 0; k < 4; k++) data.push_back(0);
        wlXdgNameRVA = dataRVA + (uint32_t)data.size();
        for (int k = 0; k < 4; k++) data.push_back(0);
        wlShmNameRVA = dataRVA + (uint32_t)data.size();
        for (int k = 0; k < 4; k++) data.push_back(0);
        wlSurfIdRVA = dataRVA + (uint32_t)data.size();
        for (int k = 0; k < 4; k++) data.push_back(0);
        wlXdgIdRVA = dataRVA + (uint32_t)data.size();
        for (int k = 0; k < 4; k++) data.push_back(0);
        wlTopIdRVA = dataRVA + (uint32_t)data.size();
        for (int k = 0; k < 4; k++) data.push_back(0);
        wlShmIdRVA = dataRVA + (uint32_t)data.size();
        for (int k = 0; k < 4; k++) data.push_back(0);
        wlPoolIdRVA = dataRVA + (uint32_t)data.size();
        for (int k = 0; k < 4; k++) data.push_back(0);
        wlBufIdRVA = dataRVA + (uint32_t)data.size();
        for (int k = 0; k < 4; k++) data.push_back(0);
        wlFbPtrRVA = dataRVA + (uint32_t)data.size();
        for (int k = 0; k < 8; k++) data.push_back(0);
        wlBufFdRVA = dataRVA + (uint32_t)data.size();
        for (int k = 0; k < 8; k++) data.push_back(0);
        wlWinWRVA = dataRVA + (uint32_t)data.size();
        for (int k = 0; k < 4; k++) data.push_back(0);
        wlWinHRVA = dataRVA + (uint32_t)data.size();
        for (int k = 0; k < 4; k++) data.push_back(0);
        wlConfiguredRVA = dataRVA + (uint32_t)data.size();
        for (int k = 0; k < 4; k++) data.push_back(0);
        wlClosedRVA = dataRVA + (uint32_t)data.size();
        for (int k = 0; k < 4; k++) data.push_back(0);
        wlOutRVA = dataRVA + (uint32_t)data.size();    // request-build scratch
        for (int k = 0; k < 256; k++) data.push_back(0);
    }

    // Linux Vulkan WSI surface: Wayland client + surface/swapchain state.
    // Built on libwayland-client.so.0 (imports) + libvulkan (vk_* base slots).
    if (vkSurfaceUsed) {
        auto addRdataStr = [&](const char* s) {
            uint32_t rva = rdataRVA + (uint32_t)rdata.size();
            for (const char* p = s; *p; p++) rdata.push_back((uint8_t)*p);
            rdata.push_back(0);
            return rva;
        };
        // .rdata strings used by the WSI layer (wayland interface names + the
        // vulkan extension names that vk_instance_create must enable).
        vkSurfaceKHRStrRVA     = addRdataStr("VK_KHR_surface");
        vkWaylandSurfaceStrRVA = addRdataStr("VK_KHR_wayland_surface");
        vkSwapchainStrRVA      = addRdataStr("VK_KHR_swapchain");
        vkCreateSurfaceStrRVA  = addRdataStr("vkCreateWaylandSurfaceKHR");
        vkDestroySurfStrRVA    = addRdataStr("vkDestroySurfaceKHR");
        vkDestroyDeviceStrRVA  = addRdataStr("vkDestroyDevice");
        static const char* kSfcProcs[] = {
            "vkGetPhysicalDeviceSurfaceCapabilitiesKHR",
            "vkGetPhysicalDeviceSurfaceFormatsKHR",
            "vkGetPhysicalDeviceSurfacePresentModesKHR",
            "vkGetPhysicalDeviceSurfaceSupportKHR",
            "vkCreateSwapchainKHR",
            "vkGetSwapchainImagesKHR",
            "vkDestroySwapchainKHR",
            "vkCreateImageView",
            "vkCreateFramebuffer",
            "vkCreateRenderPass",
            "vkCreateGraphicsPipelines",
            "vkCreatePipelineLayout",
            "vkCreateCommandPool",
            "vkAllocateCommandBuffers",
            "vkBeginCommandBuffer",
            "vkCmdBeginRenderPass",
            "vkCmdBindPipeline",
            "vkCmdDraw",
            "vkCmdEndRenderPass",
            "vkEndCommandBuffer",
            "vkAcquireNextImageKHR",
            "vkWaitForFences",
            "vkResetFences",
            "vkQueueSubmit",
            "vkQueuePresentKHR",
            "vkQueueWaitIdle",
            "vkDeviceWaitIdle",
            "vkCreateSemaphore",
            "vkGetDeviceQueue",
            "vkCreateBuffer",
            "vkGetBufferMemoryRequirements",
            "vkAllocateMemory",
            "vkBindBufferMemory",
            "vkMapMemory",
            "vkUnmapMemory",
            "vkGetPhysicalDeviceMemoryProperties",
            "vkCmdSetViewport",
            "vkCmdSetScissor",
            "vkCmdBindVertexBuffers",
            "vkCreateShaderModule",
        };
        for (int i = 0; i < 40; i++)
            vkSurfaceProcsStrRVA[i] = addRdataStr(kSfcProcs[i]);
        while (rdata.size() % 16 != 0) rdata.push_back(0);

        // Instance extension array: two absolute pointers into the .rdata strings
        // above, so vk_instance_create can enable surface + wayland surface
        // with ppEnabledExtensionNames pointing at this 2*8B cell.
        uint32_t vkSfcExtArrayPos = (uint32_t)data.size();
        for (int k = 0; k < 16; k++) data.push_back(0);
        vkExtArrayRVA = dataRVA + vkSfcExtArrayPos;
        // Bake the absolute pointers (ET_EXEC loads at LOAD_BASE; string RVAs
        // are final at buildLinuxImportData time).
        auto putAbsPtr = [&](size_t pos, uint32_t strRVA) {
            uint64_t va = (uint64_t)LOAD_BASE + strRVA;
            data[vkSfcExtArrayPos + pos + 0] = (uint8_t)(va & 0xFF);
            data[vkSfcExtArrayPos + pos + 1] = (uint8_t)((va >> 8) & 0xFF);
            data[vkSfcExtArrayPos + pos + 2] = (uint8_t)((va >> 16) & 0xFF);
            data[vkSfcExtArrayPos + pos + 3] = (uint8_t)((va >> 24) & 0xFF);
            data[vkSfcExtArrayPos + pos + 4] = (uint8_t)((va >> 32) & 0xFF);
            data[vkSfcExtArrayPos + pos + 5] = (uint8_t)((va >> 40) & 0xFF);
            data[vkSfcExtArrayPos + pos + 6] = (uint8_t)((va >> 48) & 0xFF);
            data[vkSfcExtArrayPos + pos + 7] = (uint8_t)((va >> 56) & 0xFF);
        };
        putAbsPtr(0, vkSurfaceKHRStrRVA);
        putAbsPtr(8, vkWaylandSurfaceStrRVA);

        // Wayland client state.
        wlSfcDisplayRVA    = dataRVA + (uint32_t)data.size();
        for (int k = 0; k < 8; k++) data.push_back(0);
        wlSfcRegistryRVA   = dataRVA + (uint32_t)data.size();
        for (int k = 0; k < 8; k++) data.push_back(0);
        wlSfcCompositorRVA = dataRVA + (uint32_t)data.size();
        for (int k = 0; k < 8; k++) data.push_back(0);
        wlSfcSurfaceRVA    = dataRVA + (uint32_t)data.size();
        for (int k = 0; k < 8; k++) data.push_back(0);
        wlSfcNameRVA       = dataRVA + (uint32_t)data.size();
        for (int k = 0; k < 4; k++) data.push_back(0);
        // Vulkan surface/device state.
        vkSfcSurfaceRVA    = dataRVA + (uint32_t)data.size();
        for (int k = 0; k < 8; k++) data.push_back(0);
        vkSfcGpuRVA        = dataRVA + (uint32_t)data.size();
        for (int k = 0; k < 8; k++) data.push_back(0);
        vkSfcQueueFamilyRVA= dataRVA + (uint32_t)data.size();
        for (int k = 0; k < 4; k++) data.push_back(0);
        vkSfcDeviceRVA     = dataRVA + (uint32_t)data.size();
        for (int k = 0; k < 8; k++) data.push_back(0);
        vkSfcQueueRVA      = dataRVA + (uint32_t)data.size();
        for (int k = 0; k < 8; k++) data.push_back(0);
        vkSfcSwapchainRVA  = dataRVA + (uint32_t)data.size();
        for (int k = 0; k < 8; k++) data.push_back(0);
        vkSfcFormatRVA     = dataRVA + (uint32_t)data.size();
        for (int k = 0; k < 4; k++) data.push_back(0);
        vkSfcExtentRVA     = dataRVA + (uint32_t)data.size();
        for (int k = 0; k < 8; k++) data.push_back(0);
        vkSfcImageCountRVA = dataRVA + (uint32_t)data.size();
        for (int k = 0; k < 4; k++) data.push_back(0);
        vkSfcRenderPassRVA = dataRVA + (uint32_t)data.size();
        for (int k = 0; k < 8; k++) data.push_back(0);
        vkSfcPipeRVA       = dataRVA + (uint32_t)data.size();
        for (int k = 0; k < 8; k++) data.push_back(0);
        vkSfcFrameImageRVA = dataRVA + (uint32_t)data.size();
        for (int k = 0; k < 4; k++) data.push_back(0);
        vkSfcFrameCBRVA    = dataRVA + (uint32_t)data.size();
        for (int k = 0; k < 8; k++) data.push_back(0);
        // Device-level fn table (16 slots), plus image view / framebuffer
        // handles and the scratch arena.
        vkSfcDevTableRVA   = dataRVA + (uint32_t)data.size();
        for (int k = 0; k < 16*8; k++) data.push_back(0);
        vkSfcScratchRVA    = dataRVA + (uint32_t)data.size();
        for (int k = 0; k < 4096; k++) data.push_back(0);
    }

    // Heap area -> .bss (zero-init; buildELF extends the RW segment).
    heapAreaRVA = dataRVA + (uint32_t)data.size();

    // User global variables (same layout as PE path).
    if (!prog.globals.empty()) {
        globalOffsets.clear();
        int totalSize = 0;
        for (auto& g : prog.globals) {
            int fieldSize = 8;
            if (g->arraySize > 0) {
                int elem = arrayElemStride(g->type);
                fieldSize = elem * g->arraySize;
            } else if (g->type.kind == TypeKind::Struct) {
                auto it = structLayouts.find(g->type.structName);
                if (it != structLayouts.end()) fieldSize = it->second.totalSize;
            } else if (g->type.kind == TypeKind::Bool || g->type.kind == TypeKind::Float) {
                fieldSize = 4;
            } else if (g->type.kind == TypeKind::Vec2) {
                fieldSize = 8;
            } else if (g->type.kind == TypeKind::Vec3) {
                fieldSize = 12;
            } else if (g->type.kind == TypeKind::Color) {
                fieldSize = 16;
            }
            if (fieldSize % 8 != 0) fieldSize += 8 - (fieldSize % 8);
            globalOffsets[g->name] = totalSize;
            totalSize += fieldSize;
        }
        globalsSize = totalSize;
        globalsRVA = dataRVA + (uint32_t)data.size();
        for (int k = 0; k < globalsSize; k++) data.push_back(0);
    }

    // Resolve heap-slot fixups (same as PE).
    for (auto& hf : heapFixups) {
        if (hf.targetRVA == 0xFFFFFF00) hf.targetRVA = heapAreaRVA;
        else if (hf.targetRVA == 0xFFFFFE00) hf.targetRVA = heapFreeHeadRVA;
        else if (hf.targetRVA == 0xFFFFFD00) hf.targetRVA = heapOffsetRVA;
    }

    // SPIR-V shader records -> .rdata (assembled binaries, see codegen_shader.cpp).
    emitShaderModules();
}

// ============================================================================
// emitLinuxEntryPoint: the ELF entry (_start). Sets up a frame, runs the
// startup relocator (inline), calls the user entry function (main, else the
// first non-extern function) with a zero exit status fallback, then _exit(0)
// via syscall. Emitted at the end of .text (after all functions), so it only
// ever forward-calls into already-emitted code.
// ============================================================================
void Codegen::emitLinuxEntryPoint() {
    entryPointCodeOffset = code.size();

    // _start prologue: rsp is 16-aligned at process entry. The SysV ABI wants
    // rsp ≡ 0 (mod 16) immediately before `call`, so the callee sees rsp ≡ 8
    // (mod 16) at entry (after the return address is pushed). Nothing to pad:
    // the kernel already hands us a 16-aligned rsp.
    // ---- stash envp (envp = rsp + 8*(argc+2); argc at [rsp]) ----
    // The Wayland backend needs $XDG_RUNTIME_DIR to build the display socket
    // path, and it resolves environment variables raw (no libc getenv). Save
    // the envp pointer here so wl_open() can scan it. rsp is still pristine.
    if (wlUsed) {
        emit8(0x48); emit8(0x8B); emit8(0x04); emit8(0x24);          // mov rax, [rsp]  (argc)
        emit8(0x48); emit8(0x8D); emit8(0x8C); emit8(0xC4); emit8(0x10);
        emit8(0x00); emit8(0x00); emit8(0x00);                       // lea rcx, [rsp+rax*8+16] (envp)
        emit8(0x48); emit8(0x8D); emit8(0x15);                       // lea rdx, [rip+wlEnvRVA]
        globalFixups.push_back({code.size(), wlEnvRVA});
        emit32(0);
        emit8(0x48); emit8(0x89); emit8(0x0A);                       // mov [rdx], rcx
    }
    // ---- startup relocator: resolve elfImportFixups via dlopen/dlsym ----
    // Runs a tight loop over a relocation table in .rdata: each entry is
    // { const char* soname; const char* sym; void** got }. A terminator of
    // {0,0,0} ends the table. dlopen/dlsym are themselves resolved through
    // the same mechanism (recursive), seeded by the primary import below.
    // For the common console case (no OS imports) the table is empty and we
    // fall straight through to main.
    emitStartupRelocator();

    // Determine the user entry function: prefer 'main', else first non-extern.
    std::string entry;
    if (funcOffsets.count("main")) entry = "main";
    else for (auto& f : prog.functions) if (!f->isExtern) { entry = f->name; break; }

    // Global initializers. This was missing on the Linux path: emitEntryPoint()
    // (Windows PE) calls emitGlobalInit(), but this entry point did not, so
    // every `var g: int = 5` stayed zero and global strings were blank. The
    // routine is a no-op when nothing needs initializing and is stack-neutral
    // (push rbp / sub rsp,0x20 ... add rsp,0x20 / pop rbp).
    emitGlobalInit();

    if (!entry.empty()) {
        emitMixCrt0Call();
        emit8(0xE8);
        size_t fp = code.size();
        emit32(0);
        callFixups.push_back({fp, entry});
    }

    // exit status is always 0 here (as before); set rdi before either path,
    // since emitLinuxExitViaLibc() reads it.
    emit8(0x31); emit8(0xFF);                 // xor edi, edi
    if (!emitLinuxExitViaLibc()) {
        emit8(0xB8); emit32(231);
        emit8(0x0F); emit8(0x05);                 // syscall
    }
    emit8(0xF4); emit8(0xEB); emit8(0xFE);    // hlt ; jmp $  (unreachable guard)
}

void Codegen::emitLinuxExitSyscall() {
    emit8(0xB8); emit32(231);                 // mov eax, SYS_exit_group
    emit8(0x31); emit8(0xFF);                 // xor edi, edi
    emit8(0x0F); emit8(0x05);                 // syscall
}

// The raw exit_group syscall above terminates immediately, so anything libc
// has buffered is discarded: a program calling puts()/printf() lost that output
// entirely and still exited 0. When the image is already dynamically linked,
// route the exit through libc instead so atexit/stdio flushing runs.
//
// Deliberately does nothing for a statically linked image: pulling libc in only
// to exit would add a DT_NEEDED to every console program, so those keep the raw
// syscall (and have no libc buffers to lose in the first place). rdi must
// already hold the exit code.
bool Codegen::emitLinuxExitViaLibc() {
    if (elfImportFixups.empty() && mixDynCells.empty()) return false;
    emit8(0xFF); emit8(0x15);                 // call [rip+disp32]  (GOT slot)
    elfImportFixups.push_back({code.size(), "exit", mix::linuxSonameFor("exit")});
    emit32(0);
    // exit() does not return; keep a trap so a broken image stops here instead
    // of running into whatever follows.
    emit8(0xEB); emit8(0xFE);                 // jmp $
    return true;
}

// ============================================================================
// emitLinuxLibInit: DT_INIT target for ET_DYN shared libraries. The dynamic
// linker calls it (with no arguments) once before the exporting host resolves
// any symbol, so running the global initializers + $mixcrt0 here is exactly
// equivalent to the executable's _start glue — minus _exit. Returns to the
// caller (dlopen's internal init loop -> back to dlopen).
// ============================================================================
void Codegen::emitLinuxLibInit() {
    entryPointCodeOffset = code.size();
    emitGlobalInit();
    emitMixCrt0Call();
    emit8(0xC3);                               // ret
}

// ============================================================================
// emitStartupRelocator (virtual-hook, shared with the PE backend): on Linux the
// GOT slots for OS imports are resolved eagerly by the dynamic linker before
// _start runs (see buildELF's PT_INTERP/PT_DYNAMIC/.rela emission), so there is
// nothing to do here. Kept as a hook for uniformity across targets.
// ============================================================================
void Codegen::emitStartupRelocator() {
    // Nothing to relocate -> return immediately (fall through to main).
    if (elfImportFixups.empty()) return;
}

// ============================================================================
// buildELF: assemble the final ELF64 executable.
// ============================================================================
void Codegen::buildELF(const std::string& path) {
    (void)0;

    checkFixupOverlaps("ELF");

    // ---- Layout: .text | .rdata | .data | .bss(heap) ----
    // Initialize .rdata/.data (string pool, globals, slots) if buildImportData
    // was bypassed. Callers normally route through buildImportData -> isLinux
    // branch, but guard defensively.
    if (rdata.empty() && data.empty() && !stringPool.empty()) {
        buildLinuxImportData();
    }

    // GOT: allocate one 8-byte slot per OS import, patched by ld.so at load
    // through the .rela.dyn relocation table emitted below (no dlopen/dlsym
    // needed — the kernel hands the binary to the dynamic linker via PT_INTERP).
    struct GotReloc { std::string symbol; std::string soname; uint32_t slotRVA; };
    std::vector<GotReloc> gotRelocs;
    std::vector<uint8_t> got;
    for (auto& fi : elfImportFixups) {
        uint32_t slotRVA = dataRVA + (uint32_t)data.size() + (uint32_t)got.size();
        gotRelocs.push_back({fi.symbol, fi.soname, slotRVA});
        for (int k = 0; k < 8; k++) got.push_back(0);
        // Patch the call site: targetRVA = slotRVA, instruction at textRVA+pos.
        int dispPos = (int)fi.codePos;
        int32_t disp = (int32_t)(slotRVA - (textRVA + (uint32_t)fi.codePos + 4));
        uint32_t raw = (uint32_t)disp;
        code[dispPos] = raw & 0xFF;
        code[dispPos + 1] = (raw >> 8) & 0xFF;
        code[dispPos + 2] = (raw >> 16) & 0xFF;
        code[dispPos + 3] = (raw >> 24) & 0xFF;
    }
    // C/C++ mix: 8-byte absolute pointer cells already placed in .data by
    // resolve() — same dynamic-symbol/rela treatment, no new bytes here. The
    // soname was recorded by the resolver (probed from the host system).
    for (auto& md : mixDynCells) {
        gotRelocs.push_back({md.symbol, md.soname, md.cellRVA});
    }
    if (!got.empty()) {
        while (got.size() % 8 != 0) got.push_back(0);
        data.insert(data.end(), got.begin(), got.end());
    }

    // ---- Dynamic segment for ld.so-resolved OS imports (libvulkan, libX11,
    // libasound, libc imports). Emitted only when elfImportFixups is non-empty;
    // console/cpu-only programs keep the fully static layout. The blob is
    // appended to the RW LOAD in file order:
    //     interp path | .dynamic | .dynstr | .dynsym | .rela
    // All VAs are absolute (ET_EXEC at LOAD_BASE). ld.so applies the
    // R_X86_64_64 relocations into the GOT slots before jumping to e_entry.
    uint32_t dynBlobSize = 0;
    uint32_t interpOff = 0, dynTabOff = 0, dynstrOff = 0, dynsymOff = 0, relaOff = 0, hashOff = 0;
    uint32_t dynArraySize = 0;
    uint32_t dynTabVA = 0, dynstrVA = 0, dynsymVA = 0, relaVA = 0, hashVA = 0;
    uint32_t interpLen = 0;
    std::vector<uint8_t> dynBlob;
    std::vector<uint8_t> dynHash;
    if (!gotRelocs.empty()) {
        // --- .dynstr: '\0' + sonames + symbols, with exact offsets tracked as
        // each string is appended (sonames can interleave with the first
        // symbol of a library, so NEEDED/Sym st_name offsets must reflect the
        // real positions - not a precomputed "sonames first" layout).
        std::string dynstr;
        dynstr.push_back('\0');
        std::vector<std::string> sonames;
        std::vector<std::string> symbols;
        std::map<std::string,int> symIdx;
        std::unordered_map<std::string,uint32_t> strOff;
        for (auto& gr : gotRelocs) {
            if (std::find(sonames.begin(), sonames.end(), gr.soname) == sonames.end()) {
                strOff[gr.soname] = (uint32_t)dynstr.size();
                sonames.push_back(gr.soname);
                dynstr += gr.soname; dynstr.push_back('\0');
            }
            if (!symIdx.count(gr.symbol)) {
                symIdx[gr.symbol] = (int)symbols.size();
                symbols.push_back(gr.symbol);
                strOff[gr.symbol] = (uint32_t)dynstr.size();
                dynstr += gr.symbol; dynstr.push_back('\0');
            }
        }
        // copy-relocation symbols (libc data loaded via `mov sym(%rip)`): they
        // need .dynsym/.dynstr entries but no GOT slot of their own.
        std::unordered_set<std::string> copySyms;
        std::unordered_map<std::string, uint32_t> copyCellRVA;
        for (auto& cr : copyRelocs) {
            copySyms.insert(cr.symbol);
            copyCellRVA[cr.symbol] = cr.cellRVA;
            if (!symIdx.count(cr.symbol)) {
                symIdx[cr.symbol] = (int)symbols.size();
                symbols.push_back(cr.symbol);
                strOff[cr.symbol] = (uint32_t)dynstr.size();
                dynstr += cr.symbol; dynstr.push_back('\0');
            }
        }
        uint32_t dynstrSize = (uint32_t)dynstr.size();

        // --- .dynsym: null entry + undefined (GOT-import) entries + defined
        // copy-symbol entries. A -no-pie link declares each R_X86_64_COPY
        // target in the executable's own .dynsym as an OBJECT whose st_value
        // is the load-time address of its copy cell and whose st_shndx is the
        // data section, so ld.so resolves every reference to that cell (and
        // the R_X86_64_COPY fills it) before the program starts.
        std::vector<uint8_t> dynsym;
        for (int k = 0; k < 24; k++) dynsym.push_back(0);  // index 0 = null (Elf64_Sym is 24B)
        for (auto& s : symbols) {
            put32(dynsym, strOff[s]);                    // st_name
            bool isCopy = copySyms.count(s) != 0;
            if (isCopy)
                dynsym.push_back((STB_GLOBAL << 4) | STT_OBJECT); // defined copy object
            else
                dynsym.push_back((STB_GLOBAL << 4) | STT_FUNC);   // undefined import
            dynsym.push_back(0);                         // st_other
            put16(dynsym, isCopy ? 2 : 0);               // st_shndx: data section for copies, SHN_UNDEF for imports
            if (isCopy)
                put64(dynsym, (uint64_t)LOAD_BASE + copyCellRVA[s]); // st_value (copy cell address)
            else
                put64(dynsym, 0);                        // st_value (filled by ld.so)
            size_t sz = 0;
            if (isCopy) {
                sz = mix::linuxDynSymSize(s);
                if (getenv("ZT_MIX_DEBUG"))
                    fprintf(stderr, "copy size %s = %zu\n", s.c_str(), sz);
            }
            put64(dynsym, sz ? sz : 8);                  // st_size (copy size)
        }

        // --- .rela: one R_X86_64_64 per GOT slot, then R_X86_64_COPY entries
        // (library data copied into our cells at load, as a -no-pie link) ---
        std::vector<uint8_t> rela;
        for (auto& gr : gotRelocs) {
            put64(rela, (uint64_t)LOAD_BASE + gr.slotRVA);           // r_offset
            put64(rela, ((uint64_t)(symIdx[gr.symbol] + 1) << 32) | R_X86_64_64);
            put64(rela, 0);                                          // r_addend
        }
        for (auto& cr : copyRelocs) {
            put64(rela, (uint64_t)LOAD_BASE + cr.cellRVA);           // r_offset
            put64(rela, ((uint64_t)(symIdx[cr.symbol] + 1) << 32) | R_X86_64_COPY);
            put64(rela, 0);                                          // r_addend
        }

        // --- SysV .hash: nbucket, nchain, buckets[], chains[] ---
        // Canonical structure glibc's do_lookup_x expects (DT_HASH).
        {
            uint32_t nsym = (uint32_t)dynsym.size() / 24;
            uint32_t nbucket = 4;
            std::vector<uint32_t> bucket(nbucket, 0);
            std::vector<uint32_t> chain(nsym, 0);
            auto elfHash = [](const std::string& s) {
                uint32_t h = 0;
                for (unsigned char c : s) {
                    h = (h << 4) + c;
                    uint32_t g = h & 0xF0000000u;
                    if (g) h ^= g >> 24;
                    h &= ~g;
                }
                return h;
            };
            for (uint32_t i = 1; i < nsym; i++) {
                const std::string& name = symbols[i - 1];
                uint32_t b = elfHash(name) % nbucket;
                chain[i] = bucket[b];          // head-insert into the bucket list
                bucket[b] = i;
            }
            dynHash.clear();
            put32(dynHash, nbucket);
            put32(dynHash, nsym);
            for (auto b : bucket) put32(dynHash, b);
            for (auto ch : chain) put32(dynHash, ch);
        }

        // --- Dynamic array (count = DT_NEEDED* + 1 SYMTAB + 1 SYMENT + 1 STRTAB
        //      + 1 STRSZ + 1 RELA + 1 RELASZ + 1 RELAENT + 1 NULL) ---
        int maybeCount = (int)sonames.size() + 9;
        uint32_t dynArraySizeLocal = (uint32_t)maybeCount * 16;
        dynArraySize = dynArraySizeLocal;
        auto align8 = [](uint32_t v) { return (v + 7) & ~7u; };

        // Blob layout offsets (relative to blob start).
        static const char interpPath[] = "/lib64/ld-linux-x86-64.so.2";
        interpLen = (uint32_t)(sizeof(interpPath));   // incl. trailing NUL
        interpOff  = 0;
        dynTabOff  = align8(interpOff + (uint32_t)interpLen);
        dynstrOff  = align8(dynTabOff + dynArraySize);
        dynsymOff  = align8(dynstrOff + dynstrSize);
        relaOff    = align8(dynsymOff + (uint32_t)dynsym.size());
        hashOff    = align8(relaOff + (uint32_t)rela.size());

        // VAs: blob maps contiguously at (LOAD_BASE + dataRVA + data.size()).
        uint32_t baseVA = LOAD_BASE + dataRVA + (uint32_t)data.size();
        dynTabVA = baseVA + dynTabOff;
        dynstrVA = baseVA + dynstrOff;
        dynsymVA = baseVA + dynsymOff;
        relaVA   = baseVA + relaOff;
        hashVA   = baseVA + hashOff;

        // Interp path bytes.
        for (const char* p = interpPath; *p; p++) dynBlob.push_back((uint8_t)*p);
        dynBlob.push_back(0);

        // .dynamic entries.
        while (dynBlob.size() < dynTabOff) dynBlob.push_back(0);
        for (size_t i = 0; i < sonames.size(); i++) {
            put64(dynBlob, DT_NEEDED);
            put64(dynBlob, strOff[sonames[i]]);
        }
        put64(dynBlob, DT_SYMTAB); put64(dynBlob, dynsymVA);
        put64(dynBlob, DT_SYMENT); put64(dynBlob, 24);
        put64(dynBlob, DT_STRTAB); put64(dynBlob, dynstrVA);
        put64(dynBlob, DT_STRSZ);  put64(dynBlob, dynstrSize);
        put64(dynBlob, DT_RELA);   put64(dynBlob, relaVA);
        put64(dynBlob, DT_RELASZ); put64(dynBlob, (uint64_t)rela.size());
        put64(dynBlob, DT_RELAENT);put64(dynBlob, 24);
        put64(dynBlob, DT_HASH);   put64(dynBlob, hashVA);
        put64(dynBlob, DT_NULL);   put64(dynBlob, 0);

        while (dynBlob.size() < dynstrOff) dynBlob.push_back(0);
        dynBlob.insert(dynBlob.end(), dynstr.begin(), dynstr.end());
        while (dynBlob.size() < dynsymOff) dynBlob.push_back(0);
        dynBlob.insert(dynBlob.end(), dynsym.begin(), dynsym.end());
        while (dynBlob.size() < relaOff) dynBlob.push_back(0);
        dynBlob.insert(dynBlob.end(), rela.begin(), rela.end());
        while (dynBlob.size() < hashOff) dynBlob.push_back(0);
        dynBlob.insert(dynBlob.end(), dynHash.begin(), dynHash.end());
    }
    dynBlobSize = (uint32_t)dynBlob.size();

    // --- Snap heapAreaRVA to the .bss start (after .data + dynamic blob,
    // page-aligned) and shift the heap-area fixups to match, mirroring buildPE.
    // The heap lives in NOBITS .bss; computing it early (before globals/GOT
    // were appended) left it overlapping user data.
    {
        uint32_t rawDataEnd = dataRVA + (uint32_t)data.size() + dynBlobSize;
        uint32_t bssRVA     = (rawDataEnd + 0xFFF) & ~0xFFFu;
        if (heapAreaRVA != bssRVA) {
            int32_t bssDelta = (int32_t)(bssRVA - heapAreaRVA);
            for (auto& hf : heapFixups)
                if (hf.targetRVA == heapAreaRVA) hf.targetRVA += bssDelta;
            heapAreaRVA = bssRVA;
        }
    }

    // Patch RIP-relative disp32 fixups. All refs are base-independent (LOAD_BASE
    // cancels), so disp = targetRVA - (textRVA + codePos + 4).
    auto patchDisp = [&](size_t codePos, uint32_t targetRVA) {
        int64_t disp = (int64_t)targetRVA - (int64_t)(textRVA + codePos + 4);
        code[codePos]     = (uint8_t)(disp & 0xFF);
        code[codePos + 1] = (uint8_t)((disp >> 8) & 0xFF);
        code[codePos + 2] = (uint8_t)((disp >> 16) & 0xFF);
        code[codePos + 3] = (uint8_t)((disp >> 24) & 0xFF);
    };

    // String pool fixups (lea rip-relative into .rdata).
    for (auto& sf : strFixups) {
        if (sf.stringIndex < 0 || sf.stringIndex >= (int)stringOffsets.size()) continue;
        patchDisp(sf.codePos, stringRVA + stringOffsets[sf.stringIndex]);
    }

    // Heap fixups: targets already resolved to heapArea/heapOffset/heapFreeHead/
    // randSeed RVAs by buildLinuxImportData.
    for (auto& hf : heapFixups)
        patchDisp(hf.codePos, hf.targetRVA);

    // User global fixups (globals live at globalsRVA; targetRVA already includes
    // the globalsRVA base).
    for (auto& gf : globalFixups)
        patchDisp(gf.codePos, gf.targetRVA);

    // js_result()/js_error() buffers live in .data (jsResultRVA/jsErrorRVA from
    // buildLinuxImportData); tryJsCall reaches them with RIP-relative leas. Only
    // the PE path patched these before, so on ELF disp32 stayed 0: js_error()
    // handed the engine a pointer at the byte after the lea and the engine
    // strcpy'ed the error message over the instructions that followed it.
    if (jsUsed) {
        for (auto& jf : jsFixups)
            patchDisp(jf.codePos, jf.slot == JsFixup::JS_SLOT_ERROR ? jsErrorRVA
                                                                    : jsResultRVA);
    }

    // Align sections to 0x1000 for clean PT_LOAD mapping.
    auto alignUp = [](uint32_t v, uint32_t a) { return (v + a - 1) & ~(a - 1); };
    uint32_t textSize  = (uint32_t)code.size();
    uint32_t rdataSize = (uint32_t)rdata.size();
    uint32_t dataSize  = (uint32_t)data.size();
    uint32_t bssSize   = 64u * 1024 * 1024;   // 64 MiB heap, zero-init (NOBITS)
    uint32_t phnum     = gotRelocs.empty() ? 2 : 4;

    // Compute file offsets (phdr in header; sections padded).
    uint32_t headerSize = 64 + 56 * phnum;    // ehdr(64) + phnum phdr(56)
    uint32_t textOff  = alignUp(headerSize, 0x1000);
    uint32_t rdataOff = alignUp(textOff + textSize, 0x1000);
    uint32_t dataOff  = alignUp(rdataOff + rdataSize, 0x1000);
    if (getenv("ZT_MIX_DEBUG"))
        fprintf(stderr, "DBG buildELF textRVA=%x rdataRVA=%x dataRVA=%x | text=%u rdata=%u data=%u | textOff=%x rdataOff=%x dataOff=%x | stub=%zu cells=%zu copies=%zu\n",
                textRVA, rdataRVA, dataRVA, textSize, rdataSize, dataSize,
                textOff, rdataOff, dataOff, elfImportFixups.size(), mixDynCells.size(), copyRelocs.size());
    uint32_t dynOff   = dataOff + dataSize;   // dyn blob follows .data in-file
    uint32_t bssVA    = alignUp(dataRVA + dataSize + dynBlobSize, 0x1000);
    uint32_t codeEndVA = alignUp(rdataRVA + rdataSize, 0x1000);

    // Build the header.
    std::vector<uint8_t> hdr;
    // e_ident
    hdr.push_back(0x7F); hdr.push_back('E'); hdr.push_back('L'); hdr.push_back('F');
    hdr.push_back(ELFCLASS64); hdr.push_back(ELFDATA2LSB); hdr.push_back(EV_CURRENT);
    hdr.push_back(ELFOSABI_SYSV);
    for (int i = 8; i < EI_NIDENT; i++) hdr.push_back(0);
    put16(hdr, ET_EXEC);
    put16(hdr, EM_X86_64);
    put32(hdr, 1);                            // e_version
    put64(hdr, (LOAD_BASE + textRVA) + (uint32_t)entryPointCodeOffset); // e_entry
    put64(hdr, 64);                           // e_phoff (phdrs follow the 64-byte ehdr)
    put64(hdr, 0);                            // e_shoff (no section table)
    put32(hdr, 0);                            // e_flags
    put16(hdr, 64);                           // e_ehsize
    put16(hdr, 56);                           // e_phentsize
    put16(hdr, phnum);                        // e_phnum
    put16(hdr, 0); put16(hdr, 0); put16(hdr, 0);

    // Program header 1: RX, file offset 0 (ELF header + phdrs + .text + .rdata).
    // The header/phdr bytes must fall inside a PT_LOAD so the kernel sets
    // AT_PHDR (and ld.so derives l_phdr/l_phnum for the main program).
    put32(hdr, PT_LOAD);
    // JS engine / TLS blobs carry their writable arena+BSS inside .text and
    // modify it at runtime -> that segment must be writable too (same rule as
    // the PE build, which sets text Characteristics 0xE0000020 when jsUsed).
    put32(hdr, (jsUsed || tlsUsed || disasmUsed || httpDlUsed) ? (PF_R | PF_W | PF_X) : (PF_R | PF_X)); // p_flags
    put64(hdr, 0);                            // p_offset (from ELF header)
    put64(hdr, LOAD_BASE);                    // p_vaddr
    put64(hdr, LOAD_BASE);                    // p_paddr
    put64(hdr, rdataOff + rdataSize);         // p_filesz (header+text+rdata span)
    put64(hdr, codeEndVA);                    // p_memsz
    put64(hdr, 0x1000);                       // p_align
    // Program header 2: RW, .data .. .bss(heap).
    put32(hdr, PT_LOAD);
    put32(hdr, PF_R | PF_W);
    put64(hdr, dataOff);
    put64(hdr, LOAD_BASE + dataRVA);
    put64(hdr, LOAD_BASE + dataRVA);
    put64(hdr, dataSize + dynBlobSize);       // p_filesz (.data + dynamic blob)
    put64(hdr, (bssVA + bssSize) - dataRVA);  // p_memsz
    put64(hdr, 0x1000);

    if (!elfImportFixups.empty()) {
        // Path to the dynamic linker (load_elf_binary reads it from the file).
        put32(hdr, PT_INTERP);
        put32(hdr, PF_R);
        put64(hdr, dynOff + interpOff);
        put64(hdr, LOAD_BASE + dataRVA + dataSize + interpOff);
        put64(hdr, LOAD_BASE + dataRVA + dataSize + interpOff);
        put64(hdr, interpLen);                // p_filesz
        put64(hdr, interpLen);                // p_memsz
        put64(hdr, 1);                        // p_align
        // .dynamic array (tags/symbols relocations for ld.so).
        put32(hdr, PT_DYNAMIC);
        put32(hdr, PF_R | PF_W);
        put64(hdr, dynOff + dynTabOff);
        put64(hdr, dynTabVA);
        put64(hdr, dynTabVA);
        put64(hdr, dynArraySize);             // p_filesz
        put64(hdr, dynArraySize);             // p_memsz
        put64(hdr, 8);                        // p_align
    }

    // Assemble the file.
    std::vector<uint8_t> out(hdr.begin(), hdr.end());
    out.resize(textOff, 0);
    out.insert(out.end(), code.begin(), code.end());
    out.resize(rdataOff, 0);
    out.insert(out.end(), rdata.begin(), rdata.end());
    out.resize(dataOff, 0);
    out.insert(out.end(), data.begin(), data.end());
    out.insert(out.end(), dynBlob.begin(), dynBlob.end());

    std::ofstream f(path, std::ios::binary);
    if (!f) {
        std::cerr << "Error: cannot write ELF '" << path << "'" << std::endl;
        exit(1);
    }
    f.write((const char*)out.data(), (std::streamsize)out.size());
    f.write((const char*)kZenithMagic, sizeof(kZenithMagic));
    f.close();
    if (!f) {
        std::cerr << "Error: cannot write ELF '" << path << "'" << std::endl;
        exit(1);
    }
}

// ============================================================================
// buildELFLib: assemble a Linux ET_DYN shared library (.so) for 'app linux'
// shared-library mode (--lib / --libs / output dll in workspace.zen).
//
// Layout mirrors buildELF (file offset == RVA, so patchDisp output and all
// internally baked RIP-relative displacements are reused verbatim), with the
// load-base-independent changes ET_DYN requires:
//   - e_type = ET_DYN, e_entry = 0 (no _start; dlopen runs DT_INIT).
//   - Program-header VAs are base-relative (p_vaddr = RVA, no LOAD_BASE).
//   - No PT_INTERP.
//   - Every user function is exported as a defined GLOBAL STT_FUNC in .dynsym
//     (+ .hash), so a host `dlsym(handle, name)` finds it. Exported st_value
//     = textRVA + funcOffsets[name] (0-based image offset — ld.so adds l_addr).
//   - DT_INIT = $so_init initializer (global inits + $mixcrt0), called by the
//     dynamic linker once before the host resolves any symbol.
//   - DT_NEEDED / DT_STRTAB / DT_SYMTAB / DT_HASH / DT_RELA for ld.so.
//   - R_X86_64_COPY relocations are ELF-executable-only and skipped: a shared
//     library references libc data through GOT slots (R_X86_64_64), never a
//     copy relocation. (The PE/mix path only produces copy relocs for the
//     no-pie executable output, so this is a no-op for pure-zenith .so.)
// ============================================================================
void Codegen::buildELFLib(const std::string& path) {
    if (rdata.empty() && data.empty() && !stringPool.empty()) {
        buildLinuxImportData();
    }

    // ---- GOT slots for OS imports (same as buildELF) ----
    struct GotReloc { std::string symbol; std::string soname; uint32_t slotRVA; };
    std::vector<GotReloc> gotRelocs;
    std::vector<uint8_t> got;
    for (auto& fi : elfImportFixups) {
        uint32_t slotRVA = dataRVA + (uint32_t)data.size() + (uint32_t)got.size();
        gotRelocs.push_back({fi.symbol, fi.soname, slotRVA});
        for (int k = 0; k < 8; k++) got.push_back(0);
        int dispPos = (int)fi.codePos;
        int32_t disp = (int32_t)(slotRVA - (textRVA + (uint32_t)fi.codePos + 4));
        uint32_t raw = (uint32_t)disp;
        code[dispPos]     = raw & 0xFF;
        code[dispPos + 1] = (raw >> 8) & 0xFF;
        code[dispPos + 2] = (raw >> 16) & 0xFF;
        code[dispPos + 3] = (raw >> 24) & 0xFF;
    }
    for (auto& md : mixDynCells) {
        gotRelocs.push_back({md.symbol, md.soname, md.cellRVA});
    }
    if (!got.empty()) {
        while (got.size() % 8 != 0) got.push_back(0);
        data.insert(data.end(), got.begin(), got.end());
    }

    // ---- Dynamic segment ----
    uint32_t interpOff = 0, dynTabOff = 0, dynstrOff = 0, dynsymOff = 0, relaOff = 0, hashOff = 0;
    uint32_t dynTabVA = 0, dynstrVA = 0, dynsymVA = 0, relaVA = 0, hashVA = 0;
    uint32_t dynArraySize = 0;
    std::vector<uint8_t> dynBlob;
    std::vector<uint8_t> dynHash;

    // .dynstr: '\0' + sonames + undefined-import symbols + exported names.
    std::string dynstr;
    dynstr.push_back('\0');
    std::vector<std::string> sonames;
    std::vector<std::string> symbols;               // undefined imports
    std::map<std::string,int> symIdx;
    std::unordered_map<std::string,uint32_t> strOff;
    auto addStr = [&](const std::string& s) -> uint32_t {
        auto it = strOff.find(s);
        if (it != strOff.end()) return it->second;
        uint32_t off = (uint32_t)dynstr.size();
        strOff[s] = off;
        dynstr += s; dynstr.push_back('\0');
        return off;
    };
    for (auto& gr : gotRelocs) {
        addStr(gr.soname);
        if (std::find(sonames.begin(), sonames.end(), gr.soname) == sonames.end())
            sonames.push_back(gr.soname);
        addStr(gr.symbol);
        if (!symIdx.count(gr.symbol)) {
            symIdx[gr.symbol] = (int)symbols.size();
            symbols.push_back(gr.symbol);
        }
    }
    // Exports (defined symbols): user functions collected by generate().
    for (auto& e : exportEntries) addStr(e.name);
    uint32_t dynstrSize = (uint32_t)dynstr.size();

    // .dynsym: index 0 = null; then undefined imports; then defined exports.
    // Defined-function addresses are base-relative (st_value = image offset),
    // which is exactly what ELF demands for ET_DYN and what dlsym returns
    // (dlopen adds the load base).
    std::vector<uint8_t> dynsym;
    for (int k = 0; k < 24; k++) dynsym.push_back(0);   // null entry
    for (auto& s : symbols) {
        put32(dynsym, strOff[s]);
        dynsym.push_back((STB_GLOBAL << 4) | STT_FUNC); // undefined import
        dynsym.push_back(0);
        put16(dynsym, 0);                               // SHN_UNDEF
        put64(dynsym, 0);                               // st_value (ld.so fills)
        put64(dynsym, 8);                               // st_size
    }
    for (auto& e : exportEntries) {
        put32(dynsym, strOff[e.name]);
        dynsym.push_back((STB_GLOBAL << 4) | STT_FUNC); // defined export
        dynsym.push_back(0);
        put16(dynsym, 1);                               // st_shndx = .text (defined)
        put64(dynsym, (uint64_t)e.funcRVA);             // base-relative address
        put64(dynsym, 0);                               // st_size (unknown; 0 = ok)
    }

    // .rela: R_X86_64_64 for each GOT slot / mix dyn cell.
    std::vector<uint8_t> rela;
    for (auto& gr : gotRelocs) {
        put64(rela, (uint64_t)gr.slotRVA);                      // r_offset (base-relative)
        put64(rela, ((uint64_t)(symIdx[gr.symbol] + 1) << 32) | R_X86_64_64);
        put64(rela, 0);                                         // r_addend
    }
    // NOTE: copyRelocs intentionally skipped — R_X86_64_COPY is exec-only.

    // SysV .hash (same as buildELF).
    {
        uint32_t nsym = (uint32_t)dynsym.size() / 24;
        uint32_t nbucket = 4;
        std::vector<uint32_t> bucket(nbucket, 0);
        std::vector<uint32_t> chain(nsym, 0);
        auto elfHash = [](const std::string& s) {
            uint32_t h = 0;
            for (unsigned char c : s) {
                h = (h << 4) + c;
                uint32_t g = h & 0xF0000000u;
                if (g) h ^= g >> 24;
                h &= ~g;
            }
            return h;
        };
        // symbols[] fill dynsym indices 1..symbols.size(); exports follow.
        for (uint32_t i = 1; i < nsym; i++) {
            std::string name;
            if (i <= symbols.size()) name = symbols[i - 1];
            else {
                size_t x = i - 1 - symbols.size();
                if (x < exportEntries.size()) name = exportEntries[x].name;
            }
            uint32_t b = elfHash(name) % nbucket;
            chain[i] = bucket[b];
            bucket[b] = i;
        }
        dynHash.clear();
        put32(dynHash, nbucket);
        put32(dynHash, nsym);
        for (auto b : bucket) put32(dynHash, b);
        for (auto ch : chain) put32(dynHash, ch);
    }

    // Dynamic entries: NEEDED* + STRTAB + STRSZ + SYMTAB + SYMENT + HASH
    // + INIT + [RELA + RELASZ + RELAENT when imports exist] + NULL.
    int entryCount = (int)sonames.size() + 7 + (rela.empty() ? 0 : 3);
    uint32_t dynArraySizeLocal = (uint32_t)entryCount * 16;
    dynArraySize = dynArraySizeLocal;
    auto align8 = [](uint32_t v) { return (v + 7) & ~7u; };

    // Blob layout offsets (relative to blob start); no interp for a .so.
    dynTabOff = 0;
    dynstrOff = align8(dynTabOff + dynArraySize);
    dynsymOff = align8(dynstrOff + dynstrSize);
    relaOff   = align8(dynsymOff + (uint32_t)dynsym.size());
    hashOff   = align8(relaOff + (uint32_t)rela.size());

    // VAs (base-relative): blob maps contiguously at (dataRVA + data.size()).
    uint32_t baseVA = dataRVA + (uint32_t)data.size();
    dynTabVA = baseVA + dynTabOff;
    dynstrVA = baseVA + dynstrOff;
    dynsymVA = baseVA + dynsymOff;
    relaVA   = baseVA + relaOff;
    hashVA   = baseVA + hashOff;

    while (dynBlob.size() < dynTabOff) dynBlob.push_back(0);
    for (size_t i = 0; i < sonames.size(); i++) {
        put64(dynBlob, DT_NEEDED);
        put64(dynBlob, strOff[sonames[i]]);
    }
    put64(dynBlob, DT_SYMTAB); put64(dynBlob, dynsymVA);
    put64(dynBlob, DT_SYMENT); put64(dynBlob, 24);
    put64(dynBlob, DT_STRTAB); put64(dynBlob, dynstrVA);
    put64(dynBlob, DT_STRSZ);  put64(dynBlob, dynstrSize);
    put64(dynBlob, DT_HASH);   put64(dynBlob, hashVA);
    // DT_INIT: $so_init base-relative address (dlopen adds l_addr).
    put64(dynBlob, DT_INIT);   put64(dynBlob, textRVA + (uint32_t)entryPointCodeOffset);
    if (!rela.empty()) {
        put64(dynBlob, DT_RELA);    put64(dynBlob, relaVA);
        put64(dynBlob, DT_RELASZ);  put64(dynBlob, (uint64_t)rela.size());
        put64(dynBlob, DT_RELAENT); put64(dynBlob, 24);
    }
    put64(dynBlob, DT_NULL);   put64(dynBlob, 0);

    while (dynBlob.size() < dynstrOff) dynBlob.push_back(0);
    dynBlob.insert(dynBlob.end(), dynstr.begin(), dynstr.end());
    while (dynBlob.size() < dynsymOff) dynBlob.push_back(0);
    dynBlob.insert(dynBlob.end(), dynsym.begin(), dynsym.end());
    while (dynBlob.size() < relaOff) dynBlob.push_back(0);
    dynBlob.insert(dynBlob.end(), rela.begin(), rela.end());
    while (dynBlob.size() < hashOff) dynBlob.push_back(0);
    dynBlob.insert(dynBlob.end(), dynHash.begin(), dynHash.end());
    uint32_t dynBlobSize = (uint32_t)dynBlob.size();

    // ---- Snap heapAreaRVA to the .bss start (mirrors buildELF) ----
    {
        uint32_t rawDataEnd = dataRVA + (uint32_t)data.size() + dynBlobSize;
        uint32_t bssRVA     = (rawDataEnd + 0xFFF) & ~0xFFFu;
        if (heapAreaRVA != bssRVA) {
            int32_t bssDelta = (int32_t)(bssRVA - heapAreaRVA);
            for (auto& hf : heapFixups)
                if (hf.targetRVA == heapAreaRVA) hf.targetRVA += bssDelta;
            heapAreaRVA = bssRVA;
        }
    }

    // Patch RIP-relative disp32 fixups (identical to buildELF — all refs are
    // base-independent because file offset == RVA in this layout).
    auto patchDisp = [&](size_t codePos, uint32_t targetRVA) {
        int64_t disp = (int64_t)targetRVA - (int64_t)(textRVA + codePos + 4);
        code[codePos]     = (uint8_t)(disp & 0xFF);
        code[codePos + 1] = (uint8_t)((disp >> 8) & 0xFF);
        code[codePos + 2] = (uint8_t)((disp >> 16) & 0xFF);
        code[codePos + 3] = (uint8_t)((disp >> 24) & 0xFF);
    };
    for (auto& sf : strFixups) {
        if (sf.stringIndex < 0 || sf.stringIndex >= (int)stringOffsets.size()) continue;
        patchDisp(sf.codePos, stringRVA + stringOffsets[sf.stringIndex]);
    }
    for (auto& hf : heapFixups)
        patchDisp(hf.codePos, hf.targetRVA);
    for (auto& gf : globalFixups)
        patchDisp(gf.codePos, gf.targetRVA);
    // js_result()/js_error() .data buffers — see buildELF.
    if (jsUsed) {
        for (auto& jf : jsFixups)
            patchDisp(jf.codePos, jf.slot == JsFixup::JS_SLOT_ERROR ? jsErrorRVA
                                                                    : jsResultRVA);
    }

    // ---- Layout (file offset == RVA, so p_vaddr = RVA for ET_DYN) ----
    auto alignUp = [](uint32_t v, uint32_t a) { return (v + a - 1) & ~(a - 1); };
    uint32_t textSize  = (uint32_t)code.size();
    uint32_t rdataSize = (uint32_t)rdata.size();
    uint32_t dataSize  = (uint32_t)data.size();
    uint32_t bssSize   = 64u * 1024 * 1024;   // 64 MiB heap, zero-init (NOBITS)
    uint32_t phnum     = 3;                   // LOAD + LOAD + PT_DYNAMIC

    uint32_t headerSize = 64 + 56 * phnum;
    uint32_t textOff  = alignUp(headerSize, 0x1000);
    uint32_t rdataOff = alignUp(textOff + textSize, 0x1000);
    uint32_t dataOff  = alignUp(rdataOff + rdataSize, 0x1000);
    uint32_t dynOff  = dataOff + dataSize;
    uint32_t bssVA   = alignUp(dataRVA + dataSize + dynBlobSize, 0x1000);
    uint32_t codeEndVA = alignUp(rdataRVA + rdataSize, 0x1000);

    // ---- Header (ET_DYN) ----
    std::vector<uint8_t> hdr;
    hdr.push_back(0x7F); hdr.push_back('E'); hdr.push_back('L'); hdr.push_back('F');
    hdr.push_back(ELFCLASS64); hdr.push_back(ELFDATA2LSB); hdr.push_back(EV_CURRENT);
    hdr.push_back(ELFOSABI_SYSV);
    for (int i = 8; i < EI_NIDENT; i++) hdr.push_back(0);
    put16(hdr, ET_DYN);
    put16(hdr, EM_X86_64);
    put32(hdr, 1);
    put64(hdr, 0);                            // e_entry = 0 (dlopen uses DT_INIT)
    put64(hdr, 64);                           // e_phoff
    put64(hdr, 0);                            // e_shoff
    put32(hdr, 0);                            // e_flags
    put16(hdr, 64);                           // e_ehsize
    put16(hdr, 56);                           // e_phentsize
    put16(hdr, phnum);                        // e_phnum
    put16(hdr, 0); put16(hdr, 0); put16(hdr, 0);

    // PT_LOAD 1: RX, file offset 0, base-relative VA starting at 0.
    put32(hdr, PT_LOAD);
    put32(hdr, (jsUsed || tlsUsed || disasmUsed || httpDlUsed) ? (PF_R | PF_W | PF_X) : (PF_R | PF_X));
    put64(hdr, 0);                            // p_offset (from ELF header)
    put64(hdr, 0);                            // p_vaddr (base-relative)
    put64(hdr, 0);                            // p_paddr
    put64(hdr, rdataOff + rdataSize);         // p_filesz (header+text+rdata span)
    put64(hdr, codeEndVA);                    // p_memsz
    put64(hdr, 0x1000);                       // p_align

    // PT_LOAD 2: RW, .data .. .bss(heap).
    put32(hdr, PT_LOAD);
    put32(hdr, PF_R | PF_W);
    put64(hdr, dataOff);
    put64(hdr, dataRVA);                      // base-relative
    put64(hdr, dataRVA);
    put64(hdr, dataSize + dynBlobSize);       // p_filesz (.data + dynamic blob)
    put64(hdr, (bssVA + bssSize) - dataRVA);  // p_memsz
    put64(hdr, 0x1000);

    // PT_DYNAMIC (always present for a .so).
    put32(hdr, PT_DYNAMIC);
    put32(hdr, PF_R | PF_W);
    put64(hdr, dynOff + dynTabOff);
    put64(hdr, dynTabVA);
    put64(hdr, dynTabVA);
    put64(hdr, dynArraySize);
    put64(hdr, dynArraySize);
    put64(hdr, 8);

    // ---- Assemble the file ----
    std::vector<uint8_t> out(hdr.begin(), hdr.end());
    out.resize(textOff, 0);
    out.insert(out.end(), code.begin(), code.end());
    out.resize(rdataOff, 0);
    out.insert(out.end(), rdata.begin(), rdata.end());
    out.resize(dataOff, 0);
    out.insert(out.end(), data.begin(), data.end());
    out.insert(out.end(), dynBlob.begin(), dynBlob.end());

    std::ofstream f(path, std::ios::binary);
    if (!f) {
        std::cerr << "Error: cannot write ELF shared library '" << path << "'" << std::endl;
        exit(1);
    }
    f.write((const char*)out.data(), (std::streamsize)out.size());
    f.write((const char*)kZenithMagic, sizeof(kZenithMagic));
    f.close();
    if (!f) {
        std::cerr << "Error: cannot write ELF shared library '" << path << "'" << std::endl;
        exit(1);
    }
}
