#include "codegen.h"
#include <cstdint>
#include <vector>
#include <string>

// ============================================================================
// Linux Vulkan 1.3 builtins (app linux). Headless, X11-free core: instance
// version / create / destroy, physical-device enumeration and properties.
// Device + queue + compute + swapchain (needs X11 surface) are later layers.
//
// libvulkan.so.1 is reached through the ELF .rela/.dynamic mechanism emitted
// by buildELF (PT_INTERP + DT_NEEDED): the loader resolves vkEnumerate-
// InstanceVersion, vkCreateInstance and vkGetInstanceProcAddr into GOT slots,
// and every instance-level function is fetched with vkGetInstanceProcAddr at
// vk_instance_create() time and cached in a .data fn table (Vulkan's own
// recommended pattern, so we only import 3 symbols statically).
//
// Language surface (VK constants / vulkan.h layout mirrored by hand):
//   vk_api_version()        -> 0x403000  (VK_API_VERSION_1_3)
//   vk_instance_version()   -> loader/device max supported apiVersion or -1
//   vk_instance_create()    -> VkInstance handle or -1
//   vk_destroy_instance(h)  -> 0 or -1
//   vk_gpu_count(h)         -> number of physical devices or -1
//   vk_gpu_name(h,i,&buf)   -> copies deviceName into buf (>=256 bytes), 0/-1
//   vk_gpu_api(h,i)         -> physical device apiVersion (e.g. 4206592 = 1.3)
//   vk_gpu_vendor(h,i)      -> vendorID        vk_gpu_device(h,i) -> deviceID
// ============================================================================

// VK_API_VERSION_1_3 = (1 << 22) | (3 << 12) | 0
static constexpr uint32_t VK_API_VERSION_1_3 = 4206592u; // 0x00403000

// ============================================================================
// Usage pre-scan: mirrors detectNetSockUsage so buildLinuxImportData allocates
// the instance/app-info/fn-table slots before buildELF patches slot refs.
// ============================================================================
void detectVkExpr(Codegen* self, Expr* e, bool& used);
void detectVkStmt(Codegen* self, Stmt* s, bool& used);

void Codegen::detectVkUsage() {
    if (vkUsed) return;
    for (auto& func : prog.functions) {
        if (func->isExtern) continue;
        for (auto& stmt : func->body.stmts) detectVkStmt(this, stmt.get(), vkUsed);
        if (vkUsed) break;
    }
    for (auto& g : prog.globals) {
        if (g->init) detectVkExpr(this, g->init.get(), vkUsed);
        if (vkUsed) break;
    }
}

void detectVkExpr(Codegen* self, Expr* e, bool& used) {
    (void)self;
    if (!e) return;
    if (auto call = dynamic_cast<CallExpr*>(e)) {
        if (call->name.rfind("vk_", 0) == 0) used = true;
        for (auto& arg : call->args) detectVkExpr(self, arg.get(), used);
        return;
    }
    if (auto bin = dynamic_cast<BinaryExpr*>(e)) {
        detectVkExpr(self, bin->left.get(), used);
        detectVkExpr(self, bin->right.get(), used);
    } else if (auto memb = dynamic_cast<MemberExpr*>(e)) {
        detectVkExpr(self, memb->object.get(), used);
    } else if (auto arr = dynamic_cast<ArrayAccessExpr*>(e)) {
        detectVkExpr(self, arr->array.get(), used);
        detectVkExpr(self, arr->index.get(), used);
    } else if (auto un = dynamic_cast<UnaryExpr*>(e)) {
        detectVkExpr(self, un->operand.get(), used);
    }
}

void detectVkStmt(Codegen* self, Stmt* s, bool& used) {
    (void)self;
    if (!s) return;
    if (auto ret = dynamic_cast<ReturnStmt*>(s)) {
        detectVkExpr(self, ret->value.get(), used);
    } else if (auto exprStmt = dynamic_cast<ExprStmt*>(s)) {
        detectVkExpr(self, exprStmt->expr.get(), used);
    } else if (auto varDecl = dynamic_cast<VarDecl*>(s)) {
        detectVkExpr(self, varDecl->init.get(), used);
    } else if (auto ifs = dynamic_cast<IfStmt*>(s)) {
        detectVkExpr(self, ifs->condition.get(), used);
        for (auto& st : ifs->thenBlock.stmts) detectVkStmt(self, st.get(), used);
        for (auto& st : ifs->elseBlock.stmts) detectVkStmt(self, st.get(), used);
    } else if (auto wh = dynamic_cast<WhileStmt*>(s)) {
        detectVkExpr(self, wh->condition.get(), used);
        for (auto& st : wh->body.stmts) detectVkStmt(self, st.get(), used);
    } else if (auto loop = dynamic_cast<LoopStmt*>(s)) {
        for (auto& st : loop->body.stmts) detectVkStmt(self, st.get(), used);
    } else if (auto fs = dynamic_cast<ForStmt*>(s)) {
        detectVkExpr(self, fs->start.get(), used);
        detectVkExpr(self, fs->end.get(), used);
        detectVkExpr(self, fs->step.get(), used);
        for (auto& st : fs->body.stmts) detectVkStmt(self, st.get(), used);
    }
}

// ============================================================================
// tryLinuxVulkanCall: emits the machine code, returns true when `call` is one
// of the vk_* builtins (resultReg set), false otherwise.
// ============================================================================
bool Codegen::tryLinuxVulkanCall(CallExpr* call, int& resultReg) {
    const std::string& name = call->name;
    const bool isVkBuiltin = (name == "vk_api_version" || name == "vk_instance_create" ||
                              name == "vk_instance_version" || name == "vk_destroy_instance" ||
                              name == "vk_gpu_count" || name == "vk_gpu_name" ||
                              name == "vk_gpu_api" || name == "vk_gpu_vendor" ||
                              name == "vk_gpu_device");
    if (!isVkBuiltin) return false;
    if (name == "vk_api_version" && !call->args.empty()) return false;
    if (name == "vk_instance_create" && !call->args.empty()) return false;
    if (name == "vk_instance_version" && !call->args.empty()) return false;
    if (name == "vk_destroy_instance" && call->args.size() != 1) return false;
    if (name == "vk_gpu_count" && call->args.size() != 1) return false;
    if ((name == "vk_gpu_api" || name == "vk_gpu_vendor" || name == "vk_gpu_device") && call->args.size() != 2) return false;
    if (name == "vk_gpu_name" && call->args.size() != 3) return false;

    vkUsed = true;

    // Staging mirrors the net backend: spill, pause allocation, push the
    // callee-saved rdi/rsi (pool regs 7/6) and r12 (outside the pool).
    int saved = regsUsed;
    spillRegs();
    regsUsed = 0;

    auto guard = [&](int wantReg) {
        if (wantReg == 6 || wantReg == 7) regsUsed = (uint8_t)(regsUsed | (1 << wantReg));
    };
    // mov r12/r13/r14, regX (49 89 0xC4/0xC5/0xC6 | X<<3) — outside the pool.
    auto movToR12 = [&](int src) { emit8(0x49); emit8(0x89); emit8((uint8_t)(0xC4 | (src << 3))); };
    auto movToR13 = [&](int src) { emit8(0x49); emit8(0x89); emit8((uint8_t)(0xC5 | (src << 3))); };
    auto movToR14 = [&](int src) { emit8(0x49); emit8(0x89); emit8((uint8_t)(0xC6 | (src << 3))); };

    emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x08);  // sub rsp, 8 (alignment pad)

    emit8(0x57);              // push rdi
    emit8(0x56);              // push rsi
    emit8(0x41); emit8(0x54); // push r12

    int vkExit = newLabel();

    // lea reg, [rip + slotRVA].
    auto leaRip = [&](int r, uint32_t rva) {
        if (r >= 8) emit8(0x4C); else emit8(0x48);
        emit8(0x8D);
        emit8((uint8_t)(0x05 | ((r & 7) << 3)));
        globalFixups.push_back({code.size(), rva});
        emit32(0);
    };

    // One dynamic-import call site (resolved into a GOT slot by ld.so).
    auto callRipImport = [&](const char* sym) {
        emit8(0xFF); emit8(0x15);
        elfImportFixups.push_back({code.size(), sym, "libvulkan.so.1"});
        emit32(0);
    };

    // Direct call through a slot whose RVA is already final (.data fn table).
    auto callRipSlot = [&](uint32_t slotRVA) {
        emit8(0xFF); emit8(0x15);
        size_t pos = code.size();
        int64_t disp = (int64_t)slotRVA - (int64_t)(textRVA + pos + 4);
        uint32_t raw = (uint32_t)disp;
        emit8(raw & 0xFF); emit8((raw >> 8) & 0xFF);
        emit8((raw >> 16) & 0xFF); emit8((raw >> 24) & 0xFF);
    };

    // End of a handler: pop the staged regs and join the common exit that
    // restores the allocator view and lifts rax into the result register.
    auto finish = [&]() {
        emit8(0x41); emit8(0x5C);   // pop r12
        emit8(0x5E);                // pop rsi
        emit8(0x5F);                // pop rdi
        emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x08);  // add rsp, 8 (undo pad)
        emitJmp(vkExit);
    };

    // rax = -1 (error return for the builtin).
    auto setNeg1 = [&]() {
        emit8(0x48); emit8(0xC7); emit8(0xC0); emit32((uint32_t)-1);
    };

    // ---- vk_api_version() -> 4206592 (VK_API_VERSION_1_3) ----
    if (name == "vk_api_version") {
        int done = newLabel();
        emit8(0x48); emit8(0xC7); emit8(0xC0); emit32(VK_API_VERSION_1_3);
        emitJmp(done);
        emitLabel(done);
        finish();
        goto emitRestore;
    }

    // ---- vk_instance_version() -> max supported apiVersion (or -1) ----
    if (name == "vk_instance_version") {
        int ok = newLabel(), done = newLabel();
        leaRip(7, vkCountRVA);                    // rdi = &version
        callRipImport("vkEnumerateInstanceVersion");
        emit8(0x48); emit8(0x85); emit8(0xC0);    // test rax, rax
        emitJcc("==", ok);                        // je ok
        setNeg1();
        emitJmp(done);
        emitLabel(ok);
        leaRip(0, vkCountRVA);
        emit8(0x8B); emit8(0x00);                 // mov eax, [version]
        emitLabel(done);
        finish();
        goto emitRestore;
    }

    // ---- vk_instance_create() -> VkInstance handle (or -1) ----
    if (name == "vk_instance_create") {
        int fail = newLabel(), done = newLabel();

        // VkApplicationInfo in the .data slot:
        //  [0] sType=0 + pad, [8] pNext=0, [16] pApplicationName="Zenith",
        //  [24] applicationVersion=1 (+pad), [32] pEngineName="Zenith",
        //  [40] engineVersion=1, [44] apiVersion=VK_API_VERSION_1_3.
        leaRip(0, vkAppInfoRVA);
        emit8(0x48); emit8(0xC7); emit8(0x00); emit32(0);          // [rax+0] = 0
        emit8(0x48); emit8(0xC7); emit8(0x40); emit8(0x08); emit32(0); // [rax+8] = 0 (pNext)
        leaRip(1, vkZenithStrRVA);
        emit8(0x48); emit8(0x89); emit8(0x48); emit8(0x10);        // [rax+0x10] = "Zenith"
        emit8(0x48); emit8(0xC7); emit8(0x40); emit8(0x18); emit32(1); // appVersion=1 (+pad)
        emit8(0x48); emit8(0x89); emit8(0x48); emit8(0x20);        // [rax+0x20] = "Zenith"
        emit8(0xC7); emit8(0x40); emit8(0x28); emit32(1);          // engineVersion=1
        emit8(0xC7); emit8(0x40); emit8(0x2C); emit32(VK_API_VERSION_1_3); // apiVersion

        // VkInstanceCreateInfo in the .data slot:
        //  [0] sType=1 + pad, [8] pNext=0, [0x10] flags=0(+pad),
        //  [0x18] pApplicationInfo=&ai, [0x20] layerCount=0(+pad),
        //  [0x28] ppLayers=0, [0x30] extCount=0(+pad), [0x38] ppExt=0.
        leaRip(1, vkInstInfoRVA);
        emit8(0x48); emit8(0xC7); emit8(0x01); emit32(1);          // sType=1
        emit8(0x48); emit8(0xC7); emit8(0x41); emit8(0x08); emit32(0);
        emit8(0x48); emit8(0xC7); emit8(0x41); emit8(0x10); emit32(0);
        leaRip(2, vkAppInfoRVA);
        emit8(0x48); emit8(0x89); emit8(0x51); emit8(0x18);        // pApplicationInfo
        emit8(0x48); emit8(0xC7); emit8(0x41); emit8(0x20); emit32(0);
        emit8(0x48); emit8(0xC7); emit8(0x41); emit8(0x28); emit32(0);
        emit8(0x48); emit8(0xC7); emit8(0x41); emit8(0x30); emit32(0);
        emit8(0x48); emit8(0xC7); emit8(0x41); emit8(0x38); emit32(0);
        // When the WSI layer is in use, enable VK_KHR_surface +
        // VK_KHR_wayland_surface so vkCreateWaylandSurfaceKHR works.
        if (vkSurfaceUsed) {
            leaRip(1, vkInstInfoRVA);
            emit8(0xC7); emit8(0x41); emit8(0x30); emit32(2);      // extCount = 2
            leaRip(2, vkExtArrayRVA);
            emit8(0x48); emit8(0x89); emit8(0x51); emit8(0x38);    // ppEnabledExtensionNames
        }

        leaRip(7, vkInstInfoRVA);                 // rdi = &createInfo
        emit8(0x31); emit8(0xF6);                 // rsi = NULL (pAllocator)
        leaRip(2, vkInstRVA);                     // rdx = &instance
        callRipImport("vkCreateInstance");
        emit8(0x48); emit8(0x85); emit8(0xC0);    // test rax, rax
        emitJcc("!=", fail);

        // Resolve the instance-level fn table via vkGetInstanceProcAddr.
        auto resolveTableFn = [&](int idx, uint32_t strRVA) {
            leaRip(1, vkInstRVA);
            emit8(0x48); emit8(0x8B); emit8(0x39);            // mov rdi, [vkInstRVA]
            leaRip(6, strRVA);
            callRipImport("vkGetInstanceProcAddr");
            leaRip(1, vkFnTableRVA + (uint32_t)idx * 8);
            emit8(0x48); emit8(0x89); emit8(0x01);            // mov [slot], rax
        };
        resolveTableFn(0, vkDestroyStrRVA);       // vkDestroyInstance
        resolveTableFn(1, vkEnumPhyStrRVA);       // vkEnumeratePhysicalDevices
        resolveTableFn(2, vkPhyPropsStrRVA);      // vkGetPhysicalDeviceProperties
        resolveTableFn(3, vkDevProcStrRVA);       // vkGetDeviceProcAddr

        leaRip(1, vkInstRVA);
        emit8(0x48); emit8(0x8B); emit8(0x01);    // mov rax, [vkInstRVA]
        emitJmp(done);
        emitLabel(fail);
        setNeg1();
        emitLabel(done);
        finish();
        goto emitRestore;
    }

    // ---- vk_destroy_instance(h) -> 0 or -1 ----
    if (name == "vk_destroy_instance") {
        int fail = newLabel(), done = newLabel();
        int a0 = emitExpr(call->args[0].get());
        if (a0 != 7) emitMovReg(7, a0);            // h -> rdi
        freeReg(a0);
        guard(7);
        emit8(0x31); emit8(0xF6);                  // rsi = NULL
        callRipSlot(vkFnTableRVA + 0);             // vkDestroyInstance
        emit8(0x48); emit8(0x85); emit8(0xC0);
        emitJcc("!=", fail);
        emit8(0x31); emit8(0xC0);                  // rax = 0
        emitJmp(done);
        emitLabel(fail);
        setNeg1();
        emitLabel(done);
        finish();
        goto emitRestore;
    }

    // ---- vk_gpu_count(h) -> device count or -1 ----
    if (name == "vk_gpu_count") {
        int fail = newLabel(), done = newLabel();
        int a0 = emitExpr(call->args[0].get());
        if (a0 != 7) emitMovReg(7, a0);
        freeReg(a0);
        guard(7);
        leaRip(6, vkCountRVA);                     // rsi = &count
        emit8(0x31); emit8(0xD2);                  // rdx = NULL
        callRipSlot(vkFnTableRVA + 8);             // vkEnumeratePhysicalDevices
        emit8(0x48); emit8(0x85); emit8(0xC0);
        emitJcc("!=", fail);
        leaRip(0, vkCountRVA);
        emit8(0x8B); emit8(0x00);                  // mov eax, [count]
        emitJmp(done);
        emitLabel(fail);
        setNeg1();
        emitLabel(done);
        finish();
        goto emitRestore;
    }

    // ---- GPU-family: (h, idx[, &buf]) -> read a physical device property ----
    if (name == "vk_gpu_name" || name == "vk_gpu_api" ||
        name == "vk_gpu_vendor" || name == "vk_gpu_device") {
        int fail = newLabel(), ok = newLabel(), done = newLabel();
        int a0 = emitExpr(call->args[0].get());
        movToR12(a0); freeReg(a0);                 // h -> r12
        int a1 = emitExpr(call->args[1].get());
        movToR13(a1); freeReg(a1);                 // idx -> r13
        if (name == "vk_gpu_name") {
            int a2 = emitExpr(call->args[2].get());
            movToR14(a2); freeReg(a2);             // &buf -> r14
        }

        emit8(0x4C); emit8(0x89); emit8(0xE7);     // mov rdi, r12 (instance)
        leaRip(6, vkCountRVA);
        leaRip(2, vkPhyBufRVA);                    // rdx = &devices[]
        callRipSlot(vkFnTableRVA + 8);             // vkEnumeratePhysicalDevices
        emit8(0x48); emit8(0x85); emit8(0xC0);
        emitJcc("!=", fail);

        leaRip(1, vkCountRVA);
        emit8(0x4C); emit8(0x39); emit8(0x29);     // cmp [count], r13
        emit8(0x0F); emit8(0x87);                  // unsigned ja ok (count > idx)
        jmpFixups.push_back({code.size(), ok});
        emit32(0);
        emitJmp(fail);
        emitLabel(ok);

        // dev = vkPhyBufRVA[idx * 8]
        leaRip(1, vkPhyBufRVA);
        emit8(0x4C); emit8(0x89); emit8(0xE8);     // mov rax, r13
        emit8(0x48); emit8(0xC1); emit8(0xE0); emit8(0x03); // shl rax, 3
        emit8(0x48); emit8(0x01); emit8(0xC8);     // add rax, rcx
        emit8(0x48); emit8(0x8B); emit8(0x38);     // mov rdi, [rax]
        leaRip(6, vkPropsRVA);                     // rsi = &properties
        callRipSlot(vkFnTableRVA + 16);            // vkGetPhysicalDeviceProperties (void)

        if (name == "vk_gpu_name") {
            // memcpy proto: copy deviceName (props+20, 256 bytes) -> buf.
            leaRip(6, vkPropsRVA);
            emit8(0x48); emit8(0x83); emit8(0xC6); emit8(0x14); // rsi = props+20
            emit8(0x4C); emit8(0x89); emit8(0xF7);             // rdi = buf
            emit8(0xB9); emit32(256);                          // ecx = 256
            emit8(0xF3); emit8(0xA4);                          // rep movsb
            emit8(0x31); emit8(0xC0);                          // rax = 0
            emitJmp(done);
        } else {
            leaRip(0, vkPropsRVA);
            if (name == "vk_gpu_api")    { emit8(0x8B); emit8(0x00); }        // [0] apiVersion
            if (name == "vk_gpu_vendor") { emit8(0x8B); emit8(0x40); emit8(0x08); } // [8] vendorID
            if (name == "vk_gpu_device") { emit8(0x8B); emit8(0x40); emit8(0x0C); } // [12] deviceID
            emitJmp(done);
        }
        emitLabel(fail);
        setNeg1();
        emitLabel(done);
        finish();
        goto emitRestore;
    }

emitRestore:
    // =============== Common exit: restore the allocator view ================
    emitLabel(vkExit);
    regsUsed = 0;
    freeReg(1);
    freeReg(2);
    freeReg(3);
    int r = allocReg();
    if (r != 0) { emitMovReg(r, 0); freeReg(0); }
    regsUsed = (uint8_t)(saved & ~(1 << r));
    reloadRegs();
    regsUsed = (uint8_t)(saved | (1 << r));
    resultReg = r >= 0 ? r : 0;
    return true;
}