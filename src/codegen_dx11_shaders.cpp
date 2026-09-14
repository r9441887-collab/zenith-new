#include "codegen.h"
#include "ast.h"
#include "parser.h"
#include <iostream>
#include <cstring>
#include <algorithm>

using namespace std;

int Codegen::ensureString(const std::string& s) {
    for (size_t i = 0; i < stringPool.size(); i++) {
        if (stringPool[i] == s) return (int)i;
    }
    int idx = (int)stringPool.size();
    stringPool.push_back(s);
    return idx;
}

bool Codegen::tryDX11Call(CallExpr* call, int& resultReg) {
    // === dxCreateVertexShader(hlsl) ===
    if (call->name == "dxCreateVertexShader" && call->args.size() == 1) {
        if (dynamic_cast<StringExpr*>(call->args[0].get()) == nullptr) return false;
        string hlsl = ((StringExpr*)call->args[0].get())->value;
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;

        int hlslIdx = -1;
        for (size_t i = 0; i < stringPool.size(); i++) {
            if (stringPool[i] == hlsl) { hlslIdx = (int)i; break; }
        }
        if (hlslIdx < 0) {
            hlslIdx = (int)stringPool.size();
            stringPool.push_back(hlsl);
        }
        int mainIdx = ensureString("main");
        int vsTargetIdx = ensureString("vs_5_0");

        emit8(0x48); emit8(0x81); emit8(0xEC); emit32(0x80);

        emit8(0x48); emit8(0x8D); emit8(0x1D);
        heapFixups.push_back({code.size(), win32GlobalsRVA});
        emit32(0);

        // Setup D3DCompile(hlsl,len,NULL,NULL,NULL,"main","vs_5_0",0,0,&blob,NULL)
        emit8(0x48); emit8(0x8D); emit8(0x05);
        heapFixups.push_back({code.size(), stringRVA + stringOffsets[hlslIdx]});
        emit32(0);
        emit8(0x48); emit8(0x89); emit8(0xC1);  // rcx = hlsl
        emit8(0xBA); emit32((uint32_t)hlsl.size());  // rdx = len
        emit8(0x45); emit8(0x33); emit8(0xC0);  // r8 = NULL
        emit8(0x45); emit8(0x33); emit8(0xC9);  // r9 = NULL
        emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x20); emit32(0); // pInclude = NULL
        emit8(0x48); emit8(0x8D); emit8(0x05);
        heapFixups.push_back({code.size(), stringRVA + stringOffsets[mainIdx]});
        emit32(0);
        emit8(0x48); emit8(0x89); emit8(0x44); emit8(0x24); emit8(0x28); // pEntrypoint
        emit8(0x48); emit8(0x8D); emit8(0x05);
        heapFixups.push_back({code.size(), stringRVA + stringOffsets[vsTargetIdx]});
        emit32(0);
        emit8(0x48); emit8(0x89); emit8(0x44); emit8(0x24); emit8(0x30); // pTarget
        emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x38); emit32(0); // Flags1
        emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x40); emit32(0); // Flags2
        emit8(0x48); emit8(0x8D); emit8(0x44); emit8(0x24); emit8(0x60);
        emit8(0x48); emit8(0x89); emit8(0x44); emit8(0x24); emit8(0x48); // &blob
        emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x50); emit32(0); // ppErrorMsgs = NULL

        emit8(0xFF); emit8(0x15);
        importCallFixups.push_back({code.size(), "D3DCompile", "d3dcompiler_47.dll"});
        emit32(0);

        int compileFailed = newLabel();
        int compileDone = newLabel();
        emit8(0x85); emit8(0xC0);
        emitJcc("<", compileFailed);

        // blob->GetBufferPointer() -> pBuffer
        emit8(0x48); emit8(0x8B); emit8(0x44); emit8(0x24); emit8(0x60); // rax = blob
        emit8(0x48); emit8(0x8B); emit8(0x00);
        emit8(0x48); emit8(0x8B); emit8(0x40); emit8(0x18); // GetBufferPointer
        emit8(0x48); emit8(0x8B); emit8(0x4C); emit8(0x24); emit8(0x60);
        emit8(0xFF); emit8(0xD0);
        emit8(0x49); emit8(0x89); emit8(0xC1);  // r9 = pBuffer (save in r9)

        // blob->GetBufferSize() -> size
        emit8(0x48); emit8(0x8B); emit8(0x44); emit8(0x24); emit8(0x60);
        emit8(0x48); emit8(0x8B); emit8(0x00);
        emit8(0x48); emit8(0x8B); emit8(0x40); emit8(0x20); // GetBufferSize
        emit8(0x48); emit8(0x8B); emit8(0x4C); emit8(0x24); emit8(0x60);
        emit8(0xFF); emit8(0xD0);
        emit8(0x49); emit8(0x89); emit8(0xC0);  // r8 = size

        // device->CreateVertexShader(device, pBuffer, size, NULL, &vs)
        // [rsp+0x68] = vs output
        emit8(0x4C); emit8(0x8B); emit8(0x53); emit8(0x38); // r10 = device
        emit8(0x4D); emit8(0x8B); emit8(0x12);              // r10 = [r10] = vtable
        emit8(0x4D); emit8(0x8B); emit8(0x52); emit8(0x60); // r10 = [r10+96] = CreateVertexShader (12*8)
        emit8(0x4C); emit8(0x8B); emit8(0x5B); emit8(0x38); // r11 = device (save this before fn call)
        emit8(0x4C); emit8(0x89); emit8(0xD9);              // rcx = r11 = device
        emit8(0x4C); emit8(0x89); emit8(0xCA);              // rdx = r9 = pBuffer
        // r8 already = size
        emit8(0x45); emit8(0x33); emit8(0xC9);              // r9d = 0 (pClassLinkage)
        emit8(0x48); emit8(0x8D); emit8(0x44); emit8(0x24); emit8(0x68);
        emit8(0x48); emit8(0x89); emit8(0x44); emit8(0x24); emit8(0x20); // [rsp+0x20] = &vs
        emit8(0x41); emit8(0xFF); emit8(0xD2);              // call r10

        // Release blob
        emit8(0x48); emit8(0x8B); emit8(0x44); emit8(0x24); emit8(0x60);
        emit8(0x48); emit8(0x85); emit8(0xC0);
        int skipRelease = newLabel();
        emit8(0x74); emit8(0x0E);
        emit8(0x48); emit8(0x8B); emit8(0x00);
        emit8(0x48); emit8(0x8B); emit8(0x40); emit8(0x10);
        emit8(0x48); emit8(0x8B); emit8(0x4C); emit8(0x24); emit8(0x60);
        emit8(0xFF); emit8(0xD0);
        emitLabel(skipRelease);

        emit8(0x48); emit8(0x8B); emit8(0x44); emit8(0x24); emit8(0x68);
        emitJmp(compileDone);
        emitLabel(compileFailed);
        emit8(0x33); emit8(0xC0);
        emitLabel(compileDone);

        emit8(0x48); emit8(0x81); emit8(0xC4); emit32(0x80);
        regsUsed = 1;
        resultReg = 0;
        return true;
    }

    // === dxCreatePixelShader(hlsl) ===
    if (call->name == "dxCreatePixelShader" && call->args.size() == 1) {
        if (dynamic_cast<StringExpr*>(call->args[0].get()) == nullptr) return false;
        string hlsl = ((StringExpr*)call->args[0].get())->value;
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;

        int hlslIdx = -1;
        for (size_t i = 0; i < stringPool.size(); i++) {
            if (stringPool[i] == hlsl) { hlslIdx = (int)i; break; }
        }
        if (hlslIdx < 0) {
            hlslIdx = (int)stringPool.size();
            stringPool.push_back(hlsl);
        }
        int mainIdx = ensureString("main");
        int psTargetIdx = ensureString("ps_5_0");

        emit8(0x48); emit8(0x81); emit8(0xEC); emit32(0x80);

        emit8(0x48); emit8(0x8D); emit8(0x1D);
        heapFixups.push_back({code.size(), win32GlobalsRVA});
        emit32(0);

        emit8(0x48); emit8(0x8D); emit8(0x05);
        heapFixups.push_back({code.size(), stringRVA + stringOffsets[hlslIdx]});
        emit32(0);
        emit8(0x48); emit8(0x89); emit8(0xC1);
        emit8(0xBA); emit32((uint32_t)hlsl.size());
        emit8(0x45); emit8(0x33); emit8(0xC0);
        emit8(0x45); emit8(0x33); emit8(0xC9);
        emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x20); emit32(0);
        emit8(0x48); emit8(0x8D); emit8(0x05);
        heapFixups.push_back({code.size(), stringRVA + stringOffsets[mainIdx]});
        emit32(0);
        emit8(0x48); emit8(0x89); emit8(0x44); emit8(0x24); emit8(0x28);
        emit8(0x48); emit8(0x8D); emit8(0x05);
        heapFixups.push_back({code.size(), stringRVA + stringOffsets[psTargetIdx]});
        emit32(0);
        emit8(0x48); emit8(0x89); emit8(0x44); emit8(0x24); emit8(0x30);
        emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x38); emit32(0);
        emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x40); emit32(0);
        emit8(0x48); emit8(0x8D); emit8(0x44); emit8(0x24); emit8(0x60);
        emit8(0x48); emit8(0x89); emit8(0x44); emit8(0x24); emit8(0x48);
        emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x50); emit32(0);

        emit8(0xFF); emit8(0x15);
        importCallFixups.push_back({code.size(), "D3DCompile", "d3dcompiler_47.dll"});
        emit32(0);

        int compileFailed = newLabel();
        int compileDone = newLabel();
        emit8(0x85); emit8(0xC0);
        emitJcc("<", compileFailed);

        emit8(0x48); emit8(0x8B); emit8(0x44); emit8(0x24); emit8(0x60);
        emit8(0x48); emit8(0x8B); emit8(0x00);
        emit8(0x48); emit8(0x8B); emit8(0x40); emit8(0x18);
        emit8(0x48); emit8(0x8B); emit8(0x4C); emit8(0x24); emit8(0x60);
        emit8(0xFF); emit8(0xD0);
        emit8(0x49); emit8(0x89); emit8(0xC1);  // r9 = pBuffer

        emit8(0x48); emit8(0x8B); emit8(0x44); emit8(0x24); emit8(0x60);
        emit8(0x48); emit8(0x8B); emit8(0x00);
        emit8(0x48); emit8(0x8B); emit8(0x40); emit8(0x20);
        emit8(0x48); emit8(0x8B); emit8(0x4C); emit8(0x24); emit8(0x60);
        emit8(0xFF); emit8(0xD0);
        emit8(0x49); emit8(0x89); emit8(0xC0);  // r8 = size

        // CreatePixelShader(device, pBuffer, size, NULL, &ps) - vtable index 15
        emit8(0x4C); emit8(0x8B); emit8(0x53); emit8(0x38);
        emit8(0x4D); emit8(0x8B); emit8(0x12);
        emit8(0x4D); emit8(0x8B); emit8(0x52); emit8(0x78); // [r10+120] = CreatePixelShader (15*8)
        emit8(0x4C); emit8(0x8B); emit8(0x5B); emit8(0x38); // r11 = device
        emit8(0x4C); emit8(0x89); emit8(0xD9);  // rcx = device
        emit8(0x4C); emit8(0x89); emit8(0xCA);  // rdx = pBuffer
        emit8(0x45); emit8(0x33); emit8(0xC9);  // r9d = 0
        emit8(0x48); emit8(0x8D); emit8(0x44); emit8(0x24); emit8(0x68);
        emit8(0x48); emit8(0x89); emit8(0x44); emit8(0x24); emit8(0x20);
        emit8(0x41); emit8(0xFF); emit8(0xD2);

        emit8(0x48); emit8(0x8B); emit8(0x44); emit8(0x24); emit8(0x60);
        emit8(0x48); emit8(0x85); emit8(0xC0);
        int skipRelease = newLabel();
        emit8(0x74); emit8(0x0E);
        emit8(0x48); emit8(0x8B); emit8(0x00);
        emit8(0x48); emit8(0x8B); emit8(0x40); emit8(0x10);
        emit8(0x48); emit8(0x8B); emit8(0x4C); emit8(0x24); emit8(0x60);
        emit8(0xFF); emit8(0xD0);
        emitLabel(skipRelease);

        emit8(0x48); emit8(0x8B); emit8(0x44); emit8(0x24); emit8(0x68);
        emitJmp(compileDone);
        emitLabel(compileFailed);
        emit8(0x33); emit8(0xC0);
        emitLabel(compileDone);

        emit8(0x48); emit8(0x81); emit8(0xC4); emit32(0x80);
        regsUsed = 1;
        resultReg = 0;
        return true;
    }

    // === dxCreateInputLayout(vs_hlsl) ===
    if (call->name == "dxCreateInputLayout" && call->args.size() == 1) {
        if (dynamic_cast<StringExpr*>(call->args[0].get()) == nullptr) return false;
        string hlsl = ((StringExpr*)call->args[0].get())->value;
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;

        int hlslIdx = -1;
        for (size_t i = 0; i < stringPool.size(); i++) {
            if (stringPool[i] == hlsl) { hlslIdx = (int)i; break; }
        }
        if (hlslIdx < 0) {
            hlslIdx = (int)stringPool.size();
            stringPool.push_back(hlsl);
        }
        int mainIdx = ensureString("main");
        int vsTargetIdx = ensureString("vs_5_0");
        int posIdx = ensureString("POSITION");

        emit8(0x48); emit8(0x81); emit8(0xEC); emit32(0xA0);

        emit8(0x48); emit8(0x8D); emit8(0x1D);
        heapFixups.push_back({code.size(), win32GlobalsRVA});
        emit32(0);

        // D3DCompile to get vertex shader blob for reflection
        emit8(0x48); emit8(0x8D); emit8(0x05);
        heapFixups.push_back({code.size(), stringRVA + stringOffsets[hlslIdx]});
        emit32(0);
        emit8(0x48); emit8(0x89); emit8(0xC1);
        emit8(0xBA); emit32((uint32_t)hlsl.size());
        emit8(0x45); emit8(0x33); emit8(0xC0);
        emit8(0x45); emit8(0x33); emit8(0xC9);
        emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x20); emit32(0);
        emit8(0x48); emit8(0x8D); emit8(0x05);
        heapFixups.push_back({code.size(), stringRVA + stringOffsets[mainIdx]});
        emit32(0);
        emit8(0x48); emit8(0x89); emit8(0x44); emit8(0x24); emit8(0x28);
        emit8(0x48); emit8(0x8D); emit8(0x05);
        heapFixups.push_back({code.size(), stringRVA + stringOffsets[vsTargetIdx]});
        emit32(0);
        emit8(0x48); emit8(0x89); emit8(0x44); emit8(0x24); emit8(0x30);
        emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x38); emit32(0);
        emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x40); emit32(0);
        emit8(0x48); emit8(0x8D); emit8(0x44); emit8(0x24); emit8(0x78);
        emit8(0x48); emit8(0x89); emit8(0x44); emit8(0x24); emit8(0x48);
        emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x50); emit32(0);

        emit8(0xFF); emit8(0x15);
        importCallFixups.push_back({code.size(), "D3DCompile", "d3dcompiler_47.dll"});
        emit32(0);

        int compileFailed = newLabel();
        int compileDone = newLabel();
        emit8(0x85); emit8(0xC0);
        emitJcc("<", compileFailed);

        // Build D3D11_INPUT_ELEMENT_DESC at [rsp+0x80] (32 bytes)
        emit8(0x48); emit8(0x8D); emit8(0x05);
        heapFixups.push_back({code.size(), stringRVA + stringOffsets[posIdx]});
        emit32(0);
        emit8(0x48); emit8(0x89); emit8(0x84); emit8(0x24); emit32(0x80); // SemanticName
        emit8(0x48); emit8(0xC7); emit8(0x84); emit8(0x24); emit32(0x88); emit32(0); // SemanticIndex
        emit8(0x48); emit8(0xC7); emit8(0x84); emit8(0x24); emit32(0x8C); emit32(16); // Format=R32G32_FLOAT
        emit8(0x48); emit8(0xC7); emit8(0x84); emit8(0x24); emit32(0x90); emit32(0); // InputSlot
        emit8(0x48); emit8(0xC7); emit8(0x84); emit8(0x24); emit32(0x94); emit32(0); // AlignedByteOffset=0 (APPEND)
        emit8(0x48); emit8(0xC7); emit8(0x84); emit8(0x24); emit32(0x98); emit32(0); // InputSlotClass=PER_VERTEX_DATA
        emit8(0x48); emit8(0xC7); emit8(0x84); emit8(0x24); emit32(0x9C); emit32(0); // InstanceDataStepRate

        // Get pBuffer from blob
        emit8(0x48); emit8(0x8B); emit8(0x44); emit8(0x24); emit8(0x78);
        emit8(0x48); emit8(0x8B); emit8(0x00);
        emit8(0x48); emit8(0x8B); emit8(0x40); emit8(0x18);
        emit8(0x48); emit8(0x8B); emit8(0x4C); emit8(0x24); emit8(0x78);
        emit8(0xFF); emit8(0xD0);
        emit8(0x49); emit8(0x89); emit8(0xC1);  // r9 = pBuffer
        emit8(0x4C); emit8(0x89); emit8(0x4C); emit8(0x24); emit8(0x60); // [rsp+0x60] = pBuffer

        emit8(0x48); emit8(0x8B); emit8(0x44); emit8(0x24); emit8(0x78);
        emit8(0x48); emit8(0x8B); emit8(0x00);
        emit8(0x48); emit8(0x8B); emit8(0x40); emit8(0x20);
        emit8(0x48); emit8(0x8B); emit8(0x4C); emit8(0x24); emit8(0x78);
        emit8(0xFF); emit8(0xD0);
        emit8(0x49); emit8(0x89); emit8(0xC0);  // r8 = size
        emit8(0x4C); emit8(0x89); emit8(0x44); emit8(0x24); emit8(0x68); // [rsp+0x68] = size

        // CreateInputLayout(device, &desc, 1, pBuffer, size, &layout)
        // vtable index 11: [rax+88]
        emit8(0x4C); emit8(0x8B); emit8(0x53); emit8(0x38);
        emit8(0x4D); emit8(0x8B); emit8(0x12);
        emit8(0x4D); emit8(0x8B); emit8(0x52); emit8(0x58); // [r10+88] = CreateInputLayout (11*8)
        emit8(0x4C); emit8(0x8B); emit8(0x5B); emit8(0x38); // r11 = device
        emit8(0x4C); emit8(0x89); emit8(0xD9);  // rcx = device
        emit8(0x48); emit8(0x8D); emit8(0x94); emit8(0x24); emit32(0x80); // rdx = &desc
        emit8(0x4C); emit8(0x8B); emit8(0x4C); emit8(0x24); emit8(0x60); // r9 = pBuffer
        emit8(0x48); emit8(0x8B); emit8(0x44); emit8(0x24); emit8(0x68); // rax = size
        emit8(0x48); emit8(0x89); emit8(0x44); emit8(0x24); emit8(0x20); // [rsp+0x20] = BytecodeLength
        emit8(0x48); emit8(0x8D); emit8(0x44); emit8(0x24); emit8(0x70);
        emit8(0x48); emit8(0x89); emit8(0x44); emit8(0x24); emit8(0x28); // [rsp+0x28] = &layout
        emit8(0x41); emit8(0xB8); emit32(1);    // r8d = NumElements = 1
        emit8(0x41); emit8(0xFF); emit8(0xD2);

        // Release blob
        emit8(0x48); emit8(0x8B); emit8(0x44); emit8(0x24); emit8(0x78);
        emit8(0x48); emit8(0x85); emit8(0xC0);
        int skipRelease = newLabel();
        emit8(0x74); emit8(0x0E);
        emit8(0x48); emit8(0x8B); emit8(0x00);
        emit8(0x48); emit8(0x8B); emit8(0x40); emit8(0x10);
        emit8(0x48); emit8(0x8B); emit8(0x4C); emit8(0x24); emit8(0x78);
        emit8(0xFF); emit8(0xD0);
        emitLabel(skipRelease);

        emit8(0x48); emit8(0x8B); emit8(0x44); emit8(0x24); emit8(0x70);
        emitJmp(compileDone);
        emitLabel(compileFailed);
        emit8(0x33); emit8(0xC0);
        emitLabel(compileDone);

        emit8(0x48); emit8(0x81); emit8(0xC4); emit32(0xA0);
        regsUsed = 1;
        resultReg = 0;
        return true;
    }

    // === dxSetShaders(vs, ps) ===
    if (call->name == "dxSetShaders" && call->args.size() == 2) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;

        int vsReg = emitExpr(call->args[0].get());
        int psReg = emitExpr(call->args[1].get());
        if (vsReg != 0) { emitMovReg(0, vsReg); freeReg(vsReg); }
        else freeReg(0);
        if (psReg != 0) { emitMovReg(1, psReg); freeReg(psReg); }
        else freeReg(1);

        emit8(0x51);  // push rcx (save ps across VSSetShader call)

        emit8(0x48); emit8(0x8D); emit8(0x1D);
        heapFixups.push_back({code.size(), win32GlobalsRVA});
        emit32(0);

        // VSSetShader(context, vs, NULL, 0) - vtable[11]
        emit8(0x4C); emit8(0x8B); emit8(0x53); emit8(0x40); // r10 = context
        emit8(0x4D); emit8(0x8B); emit8(0x12);              // r10 = vtable
        emit8(0x4D); emit8(0x8B); emit8(0x52); emit8(0x58); // r10 = [r10+88] = VSSetShader (11*8)
        emit8(0x4C); emit8(0x8B); emit8(0x5B); emit8(0x40); // r11 = context (for this)
        emit8(0x4C); emit8(0x89); emit8(0xD9);  // rcx = context
        emit8(0x48); emit8(0x89); emit8(0xC2);  // rdx = rax = vs (r0)
        emit8(0x45); emit8(0x33); emit8(0xC0);  // r8d = 0
        emit8(0x45); emit8(0x33); emit8(0xC9);  // r9d = 0
        emit8(0x41); emit8(0xFF); emit8(0xD2);  // call r10

        // VSSetShader is a COM call that may clobber callee-saved rbx on real
        // Windows hardware. Reload the globals base before reading context
        // for the PSSetShader call below.
        emit8(0x48); emit8(0x8D); emit8(0x1D);
        heapFixups.push_back({code.size(), win32GlobalsRVA});
        emit32(0);

        // PSSetShader(context, ps, NULL, 0) - vtable[9]
        emit8(0x4C); emit8(0x8B); emit8(0x53); emit8(0x40); // r10 = context
        emit8(0x4D); emit8(0x8B); emit8(0x12);              // r10 = vtable
        emit8(0x4D); emit8(0x8B); emit8(0x52); emit8(0x48); // r10 = [r10+72] = PSSetShader (9*8)
        emit8(0x4C); emit8(0x8B); emit8(0x5B); emit8(0x40); // r11 = context
        emit8(0x4C); emit8(0x89); emit8(0xD9);  // rcx = context
        emit8(0x5A);  // pop rdx (ps)
        emit8(0x45); emit8(0x33); emit8(0xC0);  // r8d = 0
        emit8(0x45); emit8(0x33); emit8(0xC9);  // r9d = 0
        emit8(0x41); emit8(0xFF); emit8(0xD2);  // call r10

        regsUsed = 1;
        emitMovRegImm(0, 0);
        resultReg = 0;
        return true;
    }

    // === dxSetInputLayout(layout) ===
    if (call->name == "dxSetInputLayout" && call->args.size() == 1) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;

        int layoutReg = emitExpr(call->args[0].get());
        if (layoutReg != 0) { emitMovReg(0, layoutReg); freeReg(layoutReg); }
        else freeReg(0);

        emit8(0x48); emit8(0x8D); emit8(0x1D);
        heapFixups.push_back({code.size(), win32GlobalsRVA});
        emit32(0);

        // IASetInputLayout(context, layout) - vtable[17]
        emit8(0x4C); emit8(0x8B); emit8(0x53); emit8(0x40); // r10 = context
        emit8(0x4D); emit8(0x8B); emit8(0x12);
        emit8(0x4D); emit8(0x8B); emit8(0x92); emit32(136); // [r10+136] = IASetInputLayout (17*8)
        emit8(0x4C); emit8(0x8B); emit8(0x5B); emit8(0x40); // r11 = context
        emit8(0x4C); emit8(0x89); emit8(0xD9);  // rcx = context
        emit8(0x48); emit8(0x89); emit8(0xC2);  // rdx = layout
        emit8(0x41); emit8(0xFF); emit8(0xD2);  // call r10

        regsUsed = 1;
        emitMovRegImm(0, 0);
        resultReg = 0;
        return true;
    }

    // === dxCreateBuffer(size, data) ===
    if (call->name == "dxCreateBuffer" && call->args.size() == 2) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;

        int sizeReg = emitExpr(call->args[0].get());
        int dataReg = emitExpr(call->args[1].get());
        if (sizeReg != 0) { emitMovReg(0, sizeReg); freeReg(sizeReg); }
        else freeReg(0);
        if (dataReg != 0) { emitMovReg(1, dataReg); freeReg(dataReg); }
        else freeReg(1);

        emit8(0x48); emit8(0x8D); emit8(0x1D);
        heapFixups.push_back({code.size(), win32GlobalsRVA});
        emit32(0);

        // Allocate stack: desc + subres + output
        emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x50); // sub rsp, 0x50

        // [rsp+0x20]: D3D11_BUFFER_DESC start
        // ByteWidth = r0 (size)
        emit8(0x48); emit8(0x89); emit8(0x44); emit8(0x24); emit8(0x20);
        // Usage = D3D11_USAGE_DEFAULT = 0
        emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x24); emit32(0);
        // BindFlags = D3D11_BIND_VERTEX_BUFFER | D3D11_BIND_INDEX_BUFFER = 3
        emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x28); emit32(3);
        // CPUAccessFlags = 0
        emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x2C); emit32(0);
        // MiscFlags = 0
        emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x30); emit32(0);
        // StructureByteStride = 0
        emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x34); emit32(0);

        // [rsp+0x38]: D3D11_SUBRESOURCE_DATA start
        // pSysMem = r1 (data)
        emit8(0x48); emit8(0x89); emit8(0x4C); emit8(0x24); emit8(0x38);
        // SysMemPitch = 0
        emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x40); emit32(0);
        // SysMemSlicePitch = 0
        emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x44); emit32(0);

        // [rsp+0x48]: output buffer ptr
        // device->CreateBuffer(device, &desc, &subres, &buffer)
        emit8(0x4C); emit8(0x8B); emit8(0x53); emit8(0x38); // r10 = device
        emit8(0x4D); emit8(0x8B); emit8(0x12);              // r10 = vtable
        emit8(0x4D); emit8(0x8B); emit8(0x52); emit8(0x18); // r10 = [r10+24] = CreateBuffer (3*8)
        emit8(0x4C); emit8(0x8B); emit8(0x5B); emit8(0x38); // r11 = device
        emit8(0x4C); emit8(0x89); emit8(0xD9);  // rcx = device
        emit8(0x48); emit8(0x8D); emit8(0x54); emit8(0x24); emit8(0x20); // rdx = &desc
        emit8(0x48); emit8(0x8D); emit8(0x44); emit8(0x24); emit8(0x38); // rax = &subres
        emit8(0x49); emit8(0x89); emit8(0xC0);  // r8 = &subres
        emit8(0x48); emit8(0x8D); emit8(0x44); emit8(0x24); emit8(0x48); // rax = &buffer
        emit8(0x49); emit8(0x89); emit8(0xC1);  // r9 = &buffer
        emit8(0x41); emit8(0xFF); emit8(0xD2);  // call r10

        // Result = buffer ptr
        emit8(0x48); emit8(0x8B); emit8(0x44); emit8(0x24); emit8(0x48);

        emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x50);
        regsUsed = 1;
        resultReg = 0;
        return true;
    }

    // === dxSetVertexBuffer(buffer, stride) ===
    if (call->name == "dxSetVertexBuffer" && call->args.size() == 2) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;

        int bufReg = emitExpr(call->args[0].get());
        int strideReg = emitExpr(call->args[1].get());
        if (bufReg != 0) { emitMovReg(0, bufReg); freeReg(bufReg); }
        else freeReg(0);
        if (strideReg != 0) { emitMovReg(1, strideReg); freeReg(strideReg); }
        else freeReg(1);

        emit8(0x48); emit8(0x8D); emit8(0x1D);
        heapFixups.push_back({code.size(), win32GlobalsRVA});
        emit32(0);

        // Allocate stack: &buffer, &stride, &offset
        emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x40);

        // [rsp+0x30] = buffer ptr (ppVertexBuffers[0], kept in its own slot)
        emit8(0x48); emit8(0x89); emit8(0x44); emit8(0x24); emit8(0x30);
        // [rsp+0x38] = stride value
        emit8(0x48); emit8(0x89); emit8(0x4C); emit8(0x24); emit8(0x38);
        // [rsp+0x3C] = offset = 0
        emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x3C); emit32(0);

        // IASetVertexBuffers(context, 0, 1, &buffer, &stride, &offset) - vtable[18]
        emit8(0x4C); emit8(0x8B); emit8(0x53); emit8(0x40); // r10 = context
        emit8(0x4D); emit8(0x8B); emit8(0x12);
        emit8(0x4D); emit8(0x8B); emit8(0x92); emit32(144); // [r10+144] = IASetVertexBuffers (18*8)
        emit8(0x4C); emit8(0x8B); emit8(0x5B); emit8(0x40); // r11 = context
        emit8(0x4C); emit8(0x89); emit8(0xD9);  // rcx = context
        emit8(0x33); emit8(0xD2);                             // rdx = 0 (StartSlot)
        emit8(0x41); emit8(0xB8); emit32(1);                  // r8d = 1 (NumBuffers)
        emit8(0x4C); emit8(0x8D); emit8(0x4C); emit8(0x24); emit8(0x30); // r9 = &buffer
        // 5th param: &strides (shadow slot)
        emit8(0x48); emit8(0x8D); emit8(0x44); emit8(0x24); emit8(0x38);
        emit8(0x48); emit8(0x89); emit8(0x44); emit8(0x24); emit8(0x20); // [rsp+0x20] = &strides
        // 6th param: &offsets (shadow slot)
        emit8(0x48); emit8(0x8D); emit8(0x44); emit8(0x24); emit8(0x3C);
        emit8(0x48); emit8(0x89); emit8(0x44); emit8(0x24); emit8(0x28); // [rsp+0x28] = &offsets
        emit8(0x41); emit8(0xFF); emit8(0xD2);  // call r10

        emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x40);
        regsUsed = 1;
        emitMovRegImm(0, 0);
        resultReg = 0;
        return true;
    }

    // === dxSetIndexBuffer(buffer) ===
    if (call->name == "dxSetIndexBuffer" && call->args.size() == 1) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;

        int bufReg = emitExpr(call->args[0].get());
        if (bufReg != 0) { emitMovReg(0, bufReg); freeReg(bufReg); }
        else freeReg(0);

        emit8(0x48); emit8(0x8D); emit8(0x1D);
        heapFixups.push_back({code.size(), win32GlobalsRVA});
        emit32(0);

        // IASetIndexBuffer(context, buffer, DXGI_FORMAT_R16_UINT=57, Offset=0) - vtable[19]
        emit8(0x4C); emit8(0x8B); emit8(0x53); emit8(0x40); // r10 = context
        emit8(0x4D); emit8(0x8B); emit8(0x12);
        emit8(0x4D); emit8(0x8B); emit8(0x92); emit32(152); // [r10+152] = IASetIndexBuffer (19*8)
        emit8(0x4C); emit8(0x8B); emit8(0x5B); emit8(0x40); // r11 = context
        emit8(0x4C); emit8(0x89); emit8(0xD9);  // rcx = context
        emit8(0x48); emit8(0x89); emit8(0xC2);  // rdx = buffer
        emit8(0x41); emit8(0xB8); emit32(57);   // r8d = DXGI_FORMAT_R16_UINT
        emit8(0x45); emit8(0x33); emit8(0xC9);  // r9d = 0
        emit8(0x41); emit8(0xFF); emit8(0xD2);  // call r10

        regsUsed = 1;
        emitMovRegImm(0, 0);
        resultReg = 0;
        return true;
    }

    // === dxDrawIndexed(indexCount) ===
    if (call->name == "dxDrawIndexed" && call->args.size() == 1) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;

        int countReg = emitExpr(call->args[0].get());
        if (countReg != 0) { emitMovReg(0, countReg); freeReg(countReg); }
        else freeReg(0);

        emit8(0x48); emit8(0x8D); emit8(0x1D);
        heapFixups.push_back({code.size(), win32GlobalsRVA});
        emit32(0);

        // DrawIndexed(context, IndexCount, 0, 0) - vtable[12]
        emit8(0x4C); emit8(0x8B); emit8(0x53); emit8(0x40);
        emit8(0x4D); emit8(0x8B); emit8(0x12);
        emit8(0x4D); emit8(0x8B); emit8(0x52); emit8(0x60); // [r10+96] = DrawIndexed (12*8)
        emit8(0x4C); emit8(0x8B); emit8(0x5B); emit8(0x40);
        emit8(0x4C); emit8(0x89); emit8(0xD9);  // rcx = context
        emit8(0x48); emit8(0x89); emit8(0xC2);  // rdx = IndexCount
        emit8(0x45); emit8(0x33); emit8(0xC0);  // r8d = 0
        emit8(0x45); emit8(0x33); emit8(0xC9);  // r9d = 0
        emit8(0x41); emit8(0xFF); emit8(0xD2);  // call r10

        // COM calls may clobber callee-saved rbx (events/geometry on real
        // Windows hardware). Reload the globals base before touching [rbx+96].
        emit8(0x48); emit8(0x8D); emit8(0x1D);
        heapFixups.push_back({code.size(), win32GlobalsRVA});
        emit32(0);

        // Mark that a GPU frame was drawn so present() won't overwrite it
        emit8(0xC7); emit8(0x43); emit8(0x60); emit32(1);  // [rbx+96] = gpuFrame = 1

        regsUsed = 1;
        emitMovRegImm(0, 0);
        resultReg = 0;
        return true;
    }

    // === dxDraw(vertexCount) ===
    if (call->name == "dxDraw" && call->args.size() == 1) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;

        int countReg = emitExpr(call->args[0].get());
        if (countReg != 0) { emitMovReg(0, countReg); freeReg(countReg); }
        else freeReg(0);

        emit8(0x48); emit8(0x8D); emit8(0x1D);
        heapFixups.push_back({code.size(), win32GlobalsRVA});
        emit32(0);

        // Draw(context, VertexCount, 0) - vtable[13]
        emit8(0x4C); emit8(0x8B); emit8(0x53); emit8(0x40);
        emit8(0x4D); emit8(0x8B); emit8(0x12);
        emit8(0x4D); emit8(0x8B); emit8(0x52); emit8(0x68); // [r10+104] = Draw (13*8)
        emit8(0x4C); emit8(0x8B); emit8(0x5B); emit8(0x40);
        emit8(0x4C); emit8(0x89); emit8(0xD9);  // rcx = context
        emit8(0x48); emit8(0x89); emit8(0xC2);  // rdx = VertexCount
        emit8(0x45); emit8(0x33); emit8(0xC0);  // r8d = 0
        emit8(0x41); emit8(0xFF); emit8(0xD2);  // call r10

        // COM calls may clobber callee-saved rbx on real Windows hardware.
        // Reload the globals base before touching [rbx+96].
        emit8(0x48); emit8(0x8D); emit8(0x1D);
        heapFixups.push_back({code.size(), win32GlobalsRVA});
        emit32(0);

        // Mark that a GPU frame was drawn so present() won't overwrite it
        emit8(0xC7); emit8(0x43); emit8(0x60); emit32(1);  // [rbx+96] = gpuFrame = 1

        regsUsed = 1;
        emitMovRegImm(0, 0);
        resultReg = 0;
        return true;
    }

    // === dxCreateConstantBuffer(size, data) ===
    if (call->name == "dxCreateConstantBuffer" && call->args.size() == 2) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;

        int sizeReg = emitExpr(call->args[0].get());
        int dataReg = emitExpr(call->args[1].get());
        if (sizeReg != 0) { emitMovReg(0, sizeReg); freeReg(sizeReg); }
        else freeReg(0);
        if (dataReg != 0) { emitMovReg(1, dataReg); freeReg(dataReg); }
        else freeReg(1);

        emit8(0x48); emit8(0x8D); emit8(0x1D);
        heapFixups.push_back({code.size(), win32GlobalsRVA});
        emit32(0);

        // Allocate stack: desc + subres + output
        emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x50);

        // [rsp+0x20]: D3D11_BUFFER_DESC
        emit8(0x48); emit8(0x89); emit8(0x44); emit8(0x24); emit8(0x20); // ByteWidth = size
        emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x24); emit32(0); // Usage = D3D11_USAGE_DEFAULT
        emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x28); emit32(4); // BindFlags = D3D11_BIND_CONSTANT_BUFFER
        emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x2C); emit32(0); // CPUAccessFlags
        emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x30); emit32(0); // MiscFlags
        emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x34); emit32(0); // StructureByteStride

        // [rsp+0x38]: D3D11_SUBRESOURCE_DATA
        emit8(0x48); emit8(0x89); emit8(0x4C); emit8(0x24); emit8(0x38); // pSysMem = data
        emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x40); emit32(0); // SysMemPitch
        emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x44); emit32(0); // SysMemSlicePitch

        // device->CreateBuffer(device, &desc, &subres, &buffer) - vtable[3]
        emit8(0x4C); emit8(0x8B); emit8(0x53); emit8(0x38); // r10 = device
        emit8(0x4D); emit8(0x8B); emit8(0x12);              // r10 = vtable
        emit8(0x4D); emit8(0x8B); emit8(0x52); emit8(0x18); // r10 = CreateBuffer
        emit8(0x4C); emit8(0x8B); emit8(0x5B); emit8(0x38); // r11 = device
        emit8(0x4C); emit8(0x89); emit8(0xD9);  // rcx = device
        emit8(0x48); emit8(0x8D); emit8(0x54); emit8(0x24); emit8(0x20); // rdx = &desc
        emit8(0x48); emit8(0x8D); emit8(0x44); emit8(0x24); emit8(0x38); // rax = &subres
        emit8(0x49); emit8(0x89); emit8(0xC0);  // r8 = &subres
        emit8(0x48); emit8(0x8D); emit8(0x44); emit8(0x24); emit8(0x48); // rax = &buffer
        emit8(0x49); emit8(0x89); emit8(0xC1);  // r9 = &buffer
        emit8(0x41); emit8(0xFF); emit8(0xD2);  // call r10

        // Result = buffer ptr
        emit8(0x48); emit8(0x8B); emit8(0x44); emit8(0x24); emit8(0x48);

        emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x50);
        regsUsed = 1;
        resultReg = 0;
        return true;
    }

    // === dxUpdateBuffer(buffer, data) ===
    if (call->name == "dxUpdateBuffer" && call->args.size() == 2) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;

        int bufReg = emitExpr(call->args[0].get());
        int dataReg = emitExpr(call->args[1].get());

        emit8(0x48); emit8(0x8D); emit8(0x1D);
        heapFixups.push_back({code.size(), win32GlobalsRVA});
        emit32(0);

        emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x40);

        // Spill buffer to [rsp+0x38] (all GPR regs that allocReg can return)
        auto storeToRsp38 = [&](int r) {
            emit8(0x48);
            if (r == 0) { emit8(0x89); emit8(0x44); }
            else if (r == 1) { emit8(0x89); emit8(0x4C); }
            else if (r == 2) { emit8(0x89); emit8(0x54); }
            else if (r == 3) { emit8(0x89); emit8(0x5C); }
            else if (r == 6) { emit8(0x89); emit8(0x74); }
            else if (r == 7) { emit8(0x89); emit8(0x7C); }
            else throw std::runtime_error("dxUpdateBuffer: unexpected reg");
            emit8(0x24); emit8(0x38);
        };
        if (bufReg >= 0) { storeToRsp38(bufReg); freeReg(bufReg); }
        else freeReg(0);

        // rcx = data
        if (dataReg >= 0) { emitMovReg(1, dataReg); freeReg(dataReg); }

        // [rsp+0x20] = pSrcData (rcx)
        emit8(0x48); emit8(0x89); emit8(0x4C); emit8(0x24); emit8(0x20);

        // rdx = buffer  ->  [rsp+0x38]
        emit8(0x48); emit8(0x8B); emit8(0x54); emit8(0x24); emit8(0x38);

        emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x28); emit32(0); // SrcRowPitch
        emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x30); emit32(0); // SrcDepthPitch

        emit8(0x4C); emit8(0x8B); emit8(0x53); emit8(0x40); // r10 = context
        emit8(0x4D); emit8(0x8B); emit8(0x12);
        emit8(0x4D); emit8(0x8B); emit8(0x92); emit32(384); // [r10+384] = UpdateSubresource (48*8)
        emit8(0x4C); emit8(0x8B); emit8(0x5B); emit8(0x40); // r11 = context
        emit8(0x4C); emit8(0x89); emit8(0xD9);  // rcx = context
        emit8(0x45); emit8(0x33); emit8(0xC0);  // r8d = 0 (DstSubresource)
        emit8(0x45); emit8(0x33); emit8(0xC9);  // r9d = 0 (pDstBox = NULL)
        emit8(0x41); emit8(0xFF); emit8(0xD2);  // call r10

        emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x40);
        regsUsed = 1;
        emitMovRegImm(0, 0);
        resultReg = 0;
        return true;
    }

    // === dxSetVertexConstants(buffer) ===
    if (call->name == "dxSetVertexConstants" && call->args.size() == 1) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;

        int bufReg = emitExpr(call->args[0].get());
        if (bufReg != 0) { emitMovReg(0, bufReg); freeReg(bufReg); }
        else freeReg(0);

        emit8(0x48); emit8(0x8D); emit8(0x1D);
        heapFixups.push_back({code.size(), win32GlobalsRVA});
        emit32(0);

        emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x30);
        emit8(0x48); emit8(0x89); emit8(0x44); emit8(0x24); emit8(0x20); // [rsp+0x20] = &buffers[0]

        // VSSetConstantBuffers(context, 0, 1, &buffers) - vtable[7]
        emit8(0x4C); emit8(0x8B); emit8(0x53); emit8(0x40);
        emit8(0x4D); emit8(0x8B); emit8(0x12);
        emit8(0x4D); emit8(0x8B); emit8(0x52); emit8(0x38); // [r10+56] = VSSetConstantBuffers (7*8)
        emit8(0x4C); emit8(0x8B); emit8(0x5B); emit8(0x40); // r11 = context
        emit8(0x4C); emit8(0x89); emit8(0xD9);  // rcx = context
        emit8(0x33); emit8(0xD2);               // rdx = 0 (StartSlot)
        emit8(0x41); emit8(0xB8); emit32(1);    // r8d = 1 (NumBuffers)
        emit8(0x4C); emit8(0x8D); emit8(0x4C); emit8(0x24); emit8(0x20); // r9 = &buffers
        emit8(0x41); emit8(0xFF); emit8(0xD2);  // call r10

        emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x30);
        regsUsed = 1;
        emitMovRegImm(0, 0);
        resultReg = 0;
        return true;
    }

    // === dxSetPixelConstants(buffer) ===
    if (call->name == "dxSetPixelConstants" && call->args.size() == 1) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;

        int bufReg = emitExpr(call->args[0].get());
        if (bufReg != 0) { emitMovReg(0, bufReg); freeReg(bufReg); }
        else freeReg(0);

        emit8(0x48); emit8(0x8D); emit8(0x1D);
        heapFixups.push_back({code.size(), win32GlobalsRVA});
        emit32(0);

        emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x30);
        emit8(0x48); emit8(0x89); emit8(0x44); emit8(0x24); emit8(0x20); // [rsp+0x20] = &buffers[0]

        // PSSetConstantBuffers(context, 0, 1, &buffers) - vtable[16]
        emit8(0x4C); emit8(0x8B); emit8(0x53); emit8(0x40);
        emit8(0x4D); emit8(0x8B); emit8(0x12);
        emit8(0x4D); emit8(0x8B); emit8(0x92); emit32(128); // [r10+128] = PSSetConstantBuffers (16*8)
        emit8(0x4C); emit8(0x8B); emit8(0x5B); emit8(0x40); // r11 = context
        emit8(0x4C); emit8(0x89); emit8(0xD9);  // rcx = context
        emit8(0x33); emit8(0xD2);               // rdx = 0 (StartSlot)
        emit8(0x41); emit8(0xB8); emit32(1);    // r8d = 1 (NumBuffers)
        emit8(0x4C); emit8(0x8D); emit8(0x4C); emit8(0x24); emit8(0x20); // r9 = &buffers
        emit8(0x41); emit8(0xFF); emit8(0xD2);  // call r10

        emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x30);
        regsUsed = 1;
        emitMovRegImm(0, 0);
        resultReg = 0;
        return true;
    }

    // === dxSetTopology(topology) ===
    if (call->name == "dxSetTopology" && call->args.size() == 1) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;

        int topReg = emitExpr(call->args[0].get());
        if (topReg != 0) { emitMovReg(0, topReg); freeReg(topReg); }
        else freeReg(0);

        emit8(0x48); emit8(0x8D); emit8(0x1D);
        heapFixups.push_back({code.size(), win32GlobalsRVA});
        emit32(0);

        emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x30);

        // IASetPrimitiveTopology(context, topology) - vtable[24]
        emit8(0x4C); emit8(0x8B); emit8(0x53); emit8(0x40);
        emit8(0x4D); emit8(0x8B); emit8(0x12);
        emit8(0x4D); emit8(0x8B); emit8(0x92); emit32(192); // [r10+192] = IASetPrimitiveTopology (24*8)
        emit8(0x4C); emit8(0x8B); emit8(0x5B); emit8(0x40); // r11 = context
        emit8(0x4C); emit8(0x89); emit8(0xD9);  // rcx = context
        emit8(0x89); emit8(0xC2);               // edx = eax (topology)
        emit8(0x41); emit8(0xFF); emit8(0xD2);  // call r10

        emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x30);
        regsUsed = 1;
        emitMovRegImm(0, 0);
        resultReg = 0;
        return true;
    }

    // === dxCreateTexture2D(width, height, data) ===
    if (call->name == "dxCreateTexture2D" && call->args.size() == 3) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;

        int widthReg = emitExpr(call->args[0].get());
        int heightReg = emitExpr(call->args[1].get());
        int dataReg = emitExpr(call->args[2].get());
        if (widthReg != 0) { emitMovReg(0, widthReg); freeReg(widthReg); }
        else freeReg(0);
        if (heightReg != 0) { emitMovReg(1, heightReg); freeReg(heightReg); }
        else freeReg(1);
        if (dataReg != 0) { emitMovReg(2, dataReg); freeReg(dataReg); }
        else freeReg(2);

        emit8(0x48); emit8(0x8D); emit8(0x1D);
        heapFixups.push_back({code.size(), win32GlobalsRVA});
        emit32(0);

        emit8(0x48); emit8(0x81); emit8(0xEC); emit32(0x70);

        // D3D11_TEXTURE2D_DESC at [rsp+0x20] (44 bytes)
        emit8(0x89); emit8(0x44); emit8(0x24); emit8(0x20); // Width
        emit8(0x89); emit8(0x4C); emit8(0x24); emit8(0x24); // Height
        emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x28); emit32(1); // MipLevels = 1
        emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x2C); emit32(1); // ArraySize = 1
        emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x30); emit32(28); // Format = R8G8B8A8_UNORM
        emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x34); emit32(1);  // SampleDesc.Count = 1
        emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x38); emit32(0); // SampleDesc.Quality, Usage = DEFAULT
        emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x40); emit32(8);  // BindFlags = D3D11_BIND_SHADER_RESOURCE
        emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x44); emit32(0); // CPUAccessFlags, MiscFlags

        // D3D11_SUBRESOURCE_DATA at [rsp+0x50]
        emit8(0x48); emit8(0x89); emit8(0x54); emit8(0x24); emit8(0x50); // pSysMem = data
        emit8(0x8B); emit8(0x44); emit8(0x24); emit8(0x20);  // eax = Width
        emit8(0xC1); emit8(0xE0); emit8(0x02);               // shl eax, 2
        emit8(0x89); emit8(0x44); emit8(0x24); emit8(0x58);  // SysMemPitch = width * 4
        emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x5C); emit32(0); // SysMemSlicePitch

        // device->CreateTexture2D(device, &desc, &subres, &texture) - vtable[5]
        emit8(0x4C); emit8(0x8B); emit8(0x53); emit8(0x38); // r10 = device
        emit8(0x4D); emit8(0x8B); emit8(0x12);
        emit8(0x4D); emit8(0x8B); emit8(0x52); emit8(0x28); // [r10+40] = CreateTexture2D (5*8)
        emit8(0x4C); emit8(0x8B); emit8(0x5B); emit8(0x38); // r11 = device
        emit8(0x4C); emit8(0x89); emit8(0xD9);  // rcx = device
        emit8(0x48); emit8(0x8D); emit8(0x54); emit8(0x24); emit8(0x20); // rdx = &desc
        emit8(0x4C); emit8(0x8D); emit8(0x44); emit8(0x24); emit8(0x50); // r8 = &subres
        emit8(0x4C); emit8(0x8D); emit8(0x4C); emit8(0x24); emit8(0x60); // r9 = &texture
        emit8(0x41); emit8(0xFF); emit8(0xD2);  // call r10

        emit8(0x48); emit8(0x8B); emit8(0x44); emit8(0x24); emit8(0x60); // rax = texture
        emit8(0x48); emit8(0x81); emit8(0xC4); emit32(0x70);
        regsUsed = 1;
        resultReg = 0;
        return true;
    }

    // === dxCreateShaderResourceView(texture) ===
    if (call->name == "dxCreateShaderResourceView" && call->args.size() == 1) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;

        int texReg = emitExpr(call->args[0].get());
        if (texReg != 0) { emitMovReg(0, texReg); freeReg(texReg); }
        else freeReg(0);

        emit8(0x48); emit8(0x8D); emit8(0x1D);
        heapFixups.push_back({code.size(), win32GlobalsRVA});
        emit32(0);

        emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x30);

        // device->CreateShaderResourceView(device, texture, NULL, &srv) - vtable[7]
        emit8(0x4C); emit8(0x8B); emit8(0x53); emit8(0x38); // r10 = device
        emit8(0x4D); emit8(0x8B); emit8(0x12);
        emit8(0x4D); emit8(0x8B); emit8(0x52); emit8(0x38); // [r10+56] = CreateShaderResourceView (7*8)
        emit8(0x4C); emit8(0x8B); emit8(0x5B); emit8(0x38); // r11 = device
        emit8(0x4C); emit8(0x89); emit8(0xD9);  // rcx = device
        emit8(0x48); emit8(0x89); emit8(0xC2);  // rdx = texture
        emit8(0x45); emit8(0x33); emit8(0xC0);  // r8d = 0 (pDesc = NULL)
        emit8(0x4C); emit8(0x8D); emit8(0x4C); emit8(0x24); emit8(0x20); // r9 = &srv
        emit8(0x41); emit8(0xFF); emit8(0xD2);  // call r10

        emit8(0x48); emit8(0x8B); emit8(0x44); emit8(0x24); emit8(0x20); // rax = srv
        emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x30);
        regsUsed = 1;
        resultReg = 0;
        return true;
    }

    // === dxSetTexture(srv) ===
    if (call->name == "dxSetTexture" && call->args.size() == 1) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;

        int srvReg = emitExpr(call->args[0].get());
        if (srvReg != 0) { emitMovReg(0, srvReg); freeReg(srvReg); }
        else freeReg(0);

        emit8(0x48); emit8(0x8D); emit8(0x1D);
        heapFixups.push_back({code.size(), win32GlobalsRVA});
        emit32(0);

        emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x30);
        emit8(0x48); emit8(0x89); emit8(0x44); emit8(0x24); emit8(0x20); // [rsp+0x20] = &views[0]

        // PSSetShaderResources(context, 0, 1, &views) - vtable[8]
        emit8(0x4C); emit8(0x8B); emit8(0x53); emit8(0x40);
        emit8(0x4D); emit8(0x8B); emit8(0x12);
        emit8(0x4D); emit8(0x8B); emit8(0x52); emit8(0x40); // [r10+64] = PSSetShaderResources (8*8)
        emit8(0x4C); emit8(0x8B); emit8(0x5B); emit8(0x40); // r11 = context
        emit8(0x4C); emit8(0x89); emit8(0xD9);  // rcx = context
        emit8(0x33); emit8(0xD2);               // rdx = 0 (StartSlot)
        emit8(0x41); emit8(0xB8); emit32(1);    // r8d = 1 (NumViews)
        emit8(0x4C); emit8(0x8D); emit8(0x4C); emit8(0x24); emit8(0x20); // r9 = &views
        emit8(0x41); emit8(0xFF); emit8(0xD2);  // call r10

        emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x30);
        regsUsed = 1;
        emitMovRegImm(0, 0);
        resultReg = 0;
        return true;
    }

    // === dxCreateSamplerState() ===
    if (call->name == "dxCreateSamplerState" && call->args.empty()) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;

        emit8(0x48); emit8(0x8D); emit8(0x1D);
        heapFixups.push_back({code.size(), win32GlobalsRVA});
        emit32(0);

        emit8(0x48); emit8(0x81); emit8(0xEC); emit32(0x60);

        // D3D11_SAMPLER_DESC at [rsp+0x20] (52 bytes)
        emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x20); emit32(21);       // Filter = MIN_MAG_MIP_LINEAR
        emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x24); emit32(1);       // AddressU = WRAP
        emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x28); emit32(1);       // AddressV = WRAP
        emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x2C); emit32(1);       // AddressW = WRAP
        emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x30); emit32(0);       // MipLODBias = 0
        emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x34); emit32(1);       // MaxAnisotropy = 1
        emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x38); emit32(8);       // ComparisonFunc = ALWAYS
        emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x3C); emit32(0); // BorderColor[0..1]
        emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x44); emit32(0); // BorderColor[2..3]
        emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x4C); emit32(0);       // MinLOD = 0.0f
        emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x50); emit32(0x7F7FFFFF); // MaxLOD = FLT_MAX

        // device->CreateSamplerState(device, &desc, &sampler) - vtable[23]
        emit8(0x4C); emit8(0x8B); emit8(0x53); emit8(0x38); // r10 = device
        emit8(0x4D); emit8(0x8B); emit8(0x12);
        emit8(0x4D); emit8(0x8B); emit8(0x92); emit32(184); // [r10+184] = CreateSamplerState (23*8)
        emit8(0x4C); emit8(0x8B); emit8(0x5B); emit8(0x38); // r11 = device
        emit8(0x4C); emit8(0x89); emit8(0xD9);  // rcx = device
        emit8(0x48); emit8(0x8D); emit8(0x54); emit8(0x24); emit8(0x20); // rdx = &desc
        emit8(0x4C); emit8(0x8D); emit8(0x44); emit8(0x24); emit8(0x58); // r8 = &sampler
        emit8(0x41); emit8(0xFF); emit8(0xD2);  // call r10

        emit8(0x48); emit8(0x8B); emit8(0x44); emit8(0x24); emit8(0x58); // rax = sampler
        emit8(0x48); emit8(0x81); emit8(0xC4); emit32(0x60);
        regsUsed = 1;
        resultReg = 0;
        return true;
    }

    // === dxSetSampler(sampler) ===
    if (call->name == "dxSetSampler" && call->args.size() == 1) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;

        int sampReg = emitExpr(call->args[0].get());
        if (sampReg != 0) { emitMovReg(0, sampReg); freeReg(sampReg); }
        else freeReg(0);

        emit8(0x48); emit8(0x8D); emit8(0x1D);
        heapFixups.push_back({code.size(), win32GlobalsRVA});
        emit32(0);

        emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x30);
        emit8(0x48); emit8(0x89); emit8(0x44); emit8(0x24); emit8(0x20); // [rsp+0x20] = &samplers[0]

        // PSSetSamplers(context, 0, 1, &samplers) - vtable[10]
        emit8(0x4C); emit8(0x8B); emit8(0x53); emit8(0x40);
        emit8(0x4D); emit8(0x8B); emit8(0x12);
        emit8(0x4D); emit8(0x8B); emit8(0x52); emit8(0x50); // [r10+80] = PSSetSamplers (10*8)
        emit8(0x4C); emit8(0x8B); emit8(0x5B); emit8(0x40); // r11 = context
        emit8(0x4C); emit8(0x89); emit8(0xD9);  // rcx = context
        emit8(0x33); emit8(0xD2);               // rdx = 0 (StartSlot)
        emit8(0x41); emit8(0xB8); emit32(1);    // r8d = 1 (NumSamplers)
        emit8(0x4C); emit8(0x8D); emit8(0x4C); emit8(0x24); emit8(0x20); // r9 = &samplers
        emit8(0x41); emit8(0xFF); emit8(0xD2);  // call r10

        emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x30);
        regsUsed = 1;
        emitMovRegImm(0, 0);
        resultReg = 0;
        return true;
    }

    // === dxCreateInputLayout(hlsl, sem, fmt, off, ...) - extended version ===
    if (call->name == "dxCreateInputLayout" && call->args.size() >= 4) {
        int count = ((int)call->args.size() - 1) / 3;
        if ((int)call->args.size() != 1 + count * 3) return false;
        if (dynamic_cast<StringExpr*>(call->args[0].get()) == nullptr) return false;
        for (int i = 0; i < count; i++) {
            if (dynamic_cast<StringExpr*>(call->args[1 + i * 3].get()) == nullptr) return false;
        }
        string hlsl = ((StringExpr*)call->args[0].get())->value;
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;

        int hlslIdx = -1;
        for (size_t i = 0; i < stringPool.size(); i++) {
            if (stringPool[i] == hlsl) { hlslIdx = (int)i; break; }
        }
        if (hlslIdx < 0) {
            hlslIdx = (int)stringPool.size();
            stringPool.push_back(hlsl);
        }
        int mainIdx = ensureString("main");
        int vsTargetIdx = ensureString("vs_5_0");
        std::vector<int> semIdx(count);
        for (int i = 0; i < count; i++) {
            string sem = ((StringExpr*)call->args[1 + i * 3].get())->value;
            int idx = -1;
            for (size_t j = 0; j < stringPool.size(); j++) {
                if (stringPool[j] == sem) { idx = (int)j; break; }
            }
            if (idx < 0) {
                idx = (int)stringPool.size();
                stringPool.push_back(sem);
            }
            semIdx[i] = idx;
        }

        int totalStack = 0x80 + count * 0x20;
        emit8(0x48); emit8(0x81); emit8(0xEC); emit32((uint32_t)totalStack);

        emit8(0x48); emit8(0x8D); emit8(0x1D);
        heapFixups.push_back({code.size(), win32GlobalsRVA});
        emit32(0);

        // D3DCompile to get the vertex shader blob for reflection
        emit8(0x48); emit8(0x8D); emit8(0x05);
        heapFixups.push_back({code.size(), stringRVA + stringOffsets[hlslIdx]});
        emit32(0);
        emit8(0x48); emit8(0x89); emit8(0xC1);
        emit8(0xBA); emit32((uint32_t)hlsl.size());
        emit8(0x45); emit8(0x33); emit8(0xC0);
        emit8(0x45); emit8(0x33); emit8(0xC9);
        emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x20); emit32(0);
        emit8(0x48); emit8(0x8D); emit8(0x05);
        heapFixups.push_back({code.size(), stringRVA + stringOffsets[mainIdx]});
        emit32(0);
        emit8(0x48); emit8(0x89); emit8(0x44); emit8(0x24); emit8(0x28);
        emit8(0x48); emit8(0x8D); emit8(0x05);
        heapFixups.push_back({code.size(), stringRVA + stringOffsets[vsTargetIdx]});
        emit32(0);
        emit8(0x48); emit8(0x89); emit8(0x44); emit8(0x24); emit8(0x30);
        emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x38); emit32(0);
        emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x40); emit32(0);
        emit8(0x48); emit8(0x8D); emit8(0x44); emit8(0x24); emit8(0x78);
        emit8(0x48); emit8(0x89); emit8(0x44); emit8(0x24); emit8(0x48); // &blob
        emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x50); emit32(0);

        emit8(0xFF); emit8(0x15);
        importCallFixups.push_back({code.size(), "D3DCompile", "d3dcompiler_47.dll"});
        emit32(0);

        int compileFailed = newLabel();
        int compileDone = newLabel();
        emit8(0x85); emit8(0xC0);
        emitJcc("<", compileFailed);

        // blob->GetBufferPointer() -> r9 = pBuffer
        emit8(0x48); emit8(0x8B); emit8(0x44); emit8(0x24); emit8(0x78);
        emit8(0x48); emit8(0x8B); emit8(0x00);
        emit8(0x48); emit8(0x8B); emit8(0x40); emit8(0x18);
        emit8(0x48); emit8(0x8B); emit8(0x4C); emit8(0x24); emit8(0x78);
        emit8(0xFF); emit8(0xD0);
        emit8(0x49); emit8(0x89); emit8(0xC1);  // r9 = pBuffer

        // blob->GetBufferSize() -> r8 = size
        emit8(0x48); emit8(0x8B); emit8(0x44); emit8(0x24); emit8(0x78);
        emit8(0x48); emit8(0x8B); emit8(0x00);
        emit8(0x48); emit8(0x8B); emit8(0x40); emit8(0x20);
        emit8(0x48); emit8(0x8B); emit8(0x4C); emit8(0x24); emit8(0x78);
        emit8(0xFF); emit8(0xD0);
        emit8(0x49); emit8(0x89); emit8(0xC0);  // r8 = size

        // Save pBuffer / size (emitExpr below may clobber r8/r9)
        emit8(0x4C); emit8(0x89); emit8(0x4C); emit8(0x24); emit8(0x60); // [rsp+0x60] = pBuffer
        emit8(0x4C); emit8(0x89); emit8(0x44); emit8(0x24); emit8(0x68); // [rsp+0x68] = size

        // Desc store helpers (disp8 when small, disp32 otherwise)
        auto storeQwordRax = [&](int disp) {
            if (disp <= 127) { emit8(0x48); emit8(0x89); emit8(0x44); emit8(0x24); emit8((uint8_t)disp); }
            else { emit8(0x48); emit8(0x89); emit8(0x84); emit8(0x24); emit32((uint32_t)disp); }
        };
        auto storeQwordZero = [&](int disp) {
            if (disp <= 127) { emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8((uint8_t)disp); emit32(0); }
            else { emit8(0x48); emit8(0xC7); emit8(0x84); emit8(0x24); emit32((uint32_t)disp); emit32(0); }
        };
        auto storeDwordImm = [&](int disp, uint32_t imm) {
            if (disp <= 127) { emit8(0xC7); emit8(0x44); emit8(0x24); emit8((uint8_t)disp); emit32(imm); }
            else { emit8(0xC7); emit8(0x84); emit8(0x24); emit32((uint32_t)disp); emit32(imm); }
        };
        auto storeDwordEax = [&](int disp) {
            if (disp <= 127) { emit8(0x89); emit8(0x44); emit8(0x24); emit8((uint8_t)disp); }
            else { emit8(0x89); emit8(0x84); emit8(0x24); emit32((uint32_t)disp); }
        };

        // Build D3D11_INPUT_ELEMENT_DESC array at [rsp+0x80] (32 bytes each)
        for (int i = 0; i < count; i++) {
            int base = 0x80 + i * 0x20;
            emit8(0x48); emit8(0x8D); emit8(0x05);
            heapFixups.push_back({code.size(), stringRVA + stringOffsets[semIdx[i]]});
            emit32(0);
            storeQwordRax(base);                 // SemanticName
            storeDwordImm(base + 8, 0);          // SemanticIndex
            int fmtReg = emitExpr(call->args[2 + i * 3].get());
            if (fmtReg != 0) { emitMovReg(0, fmtReg); freeReg(fmtReg); }
            else freeReg(0);
            storeDwordEax(base + 12);            // Format
            storeDwordImm(base + 16, 0);         // InputSlot
            int offReg = emitExpr(call->args[3 + i * 3].get());
            if (offReg != 0) { emitMovReg(0, offReg); freeReg(offReg); }
            else freeReg(0);
            storeDwordEax(base + 20);            // AlignedByteOffset
            storeQwordZero(base + 24);           // InputSlotClass=PER_VERTEX_DATA, InstanceDataStepRate=0
        }

        // emitExpr may have clobbered rbx — reload globals base
        emit8(0x48); emit8(0x8D); emit8(0x1D);
        heapFixups.push_back({code.size(), win32GlobalsRVA});
        emit32(0);

        emit8(0x4C); emit8(0x8B); emit8(0x4C); emit8(0x24); emit8(0x60); // r9 = pBuffer
        emit8(0x4C); emit8(0x8B); emit8(0x44); emit8(0x24); emit8(0x68); // r8 = size

        // CreateInputLayout(device, &desc, count, pBuffer, size, &layout) - vtable[11]
        emit8(0x4C); emit8(0x8B); emit8(0x53); emit8(0x38); // r10 = device
        emit8(0x4D); emit8(0x8B); emit8(0x12);
        emit8(0x4D); emit8(0x8B); emit8(0x52); emit8(0x58); // [r10+88] = CreateInputLayout (11*8)
        emit8(0x4C); emit8(0x8B); emit8(0x5B); emit8(0x38); // r11 = device
        emit8(0x4C); emit8(0x89); emit8(0xD9);  // rcx = device
        emit8(0x48); emit8(0x8D); emit8(0x94); emit8(0x24); emit32(0x80); // rdx = &desc
        emit8(0x41); emit8(0xB8); emit32((uint32_t)count); // r8d = NumElements
        emit8(0x48); emit8(0x8B); emit8(0x44); emit8(0x24); emit8(0x68); // rax = size
        emit8(0x48); emit8(0x89); emit8(0x44); emit8(0x24); emit8(0x20); // [rsp+0x20] = BytecodeLength
        emit8(0x48); emit8(0x8D); emit8(0x44); emit8(0x24); emit8(0x70); // rax = &layout
        emit8(0x48); emit8(0x89); emit8(0x44); emit8(0x24); emit8(0x28); // [rsp+0x28] = &layout
        emit8(0x41); emit8(0xFF); emit8(0xD2);  // call r10

        // Release blob
        emit8(0x48); emit8(0x8B); emit8(0x44); emit8(0x24); emit8(0x78);
        emit8(0x48); emit8(0x85); emit8(0xC0);
        int skipRelease = newLabel();
        emit8(0x74); emit8(0x0E);
        emit8(0x48); emit8(0x8B); emit8(0x00);
        emit8(0x48); emit8(0x8B); emit8(0x40); emit8(0x10);
        emit8(0x48); emit8(0x8B); emit8(0x4C); emit8(0x24); emit8(0x78);
        emit8(0xFF); emit8(0xD0);
        emitLabel(skipRelease);

        emit8(0x48); emit8(0x8B); emit8(0x44); emit8(0x24); emit8(0x70);
        emitJmp(compileDone);
        emitLabel(compileFailed);
        emit8(0x33); emit8(0xC0);
        emitLabel(compileDone);

        emit8(0x48); emit8(0x81); emit8(0xC4); emit32((uint32_t)totalStack);
        regsUsed = 1;
        resultReg = 0;
        return true;
    }

    // === dxClearDepthStencil() ===
    if (call->name == "dxClearDepthStencil" && call->args.empty()) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;

        emit8(0x48); emit8(0x8D); emit8(0x1D);
        heapFixups.push_back({code.size(), win32GlobalsRVA});
        emit32(0);

        // dsv = [rbx+108]
        emit8(0x48); emit8(0x8B); emit8(0x43); emit8(0x6C);  // rax = dsv
        emit8(0x48); emit8(0x85); emit8(0xC0);               // test rax, rax
        int skipClear = newLabel();
        emitJcc("==", skipClear);

        emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x20);
        // context->vtable[53](context, dsv, D3D11_CLEAR_DEPTH, 1.0f, 0)
        emit8(0x48); emit8(0x8B); emit8(0x43); emit8(0x40);  // rax = context
        emit8(0x48); emit8(0x8B); emit8(0x00);                // rax = vtable
        emit8(0x48); emit8(0x8B); emit8(0x80); emit32(0x1A8); // rax = ClearDepthStencilView (53*8)
        emit8(0x48); emit8(0x8B); emit8(0x4B); emit8(0x40);  // rcx = context
        emit8(0x48); emit8(0x8B); emit8(0x53); emit8(0x6C);  // rdx = dsv
        emit8(0x41); emit8(0xB8); emit32(1);                  // r8d = D3D11_CLEAR_DEPTH
        // Store 1.0f on stack then load into xmm3.
        // x64 Windows ABI: ClearDepthStencilView(context, dsv, ClearFlags,
        // Depth, Stencil) passes the 4th arg (FLOAT Depth) in xmm3, NOT xmm0.
        // Passing it in xmm0 was the black-screen root cause: D3D11 read a
        // garbage xmm3 (~0) -> depth buffer cleared to ~0 -> default LESS
        // depth test rejected every cube fragment.
        emit8(0xC7); emit8(0x84); emit8(0x24); emit32(0x28); emit32(0x3F800000); // mov dword [rsp+0x28], 1.0f
        emit8(0xF3); emit8(0x0F); emit8(0x10); emit8(0x9C); emit8(0x24); emit32(0x28); // movss xmm3, [rsp+0x28]
        emit8(0x45); emit8(0x33); emit8(0xC9);               // r9d = 0
        emit8(0xFF); emit8(0xD0);                             // call rax
        emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x20);

        emitLabel(skipClear);

        regsUsed = 1;
        emitMovRegImm(0, 0);
        resultReg = 0;
        return true;
    }

    // === dxClear() ===
    // ClearRenderTargetView(context, rtv, {0,0,0,1}) to black at the start of
    // every frame. Without this the swapchain back buffer accumulates the
    // previous frame (the cube leaves ghost trails / duplicates as it moves).
    if (call->name == "dxClear" && call->args.empty()) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;

        emit8(0x48); emit8(0x8D); emit8(0x1D);
        heapFixups.push_back({code.size(), win32GlobalsRVA});
        emit32(0);

        // rtv = [rbx+80]; skip if 0
        emit8(0x48); emit8(0x8B); emit8(0x43); emit8(0x50);  // rax = rtv
        emit8(0x48); emit8(0x85); emit8(0xC0);               // test rax, rax
        int skipClearC = newLabel();
        emitJcc("==", skipClearC);

        emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x40);

        // save rtv on stack (post-sub rsp): [rsp+0x20] = rtv
        emit8(0x48); emit8(0x89); emit8(0x44); emit8(0x24); emit8(0x20);

        // color[4] = {0,0,0,1} at [rsp+0x28]
        emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x28); emit32(0);   // R = 0
        emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x2C); emit32(0);   // G = 0
        emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x30); emit32(0);   // B = 0
        emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x34); emit32(0x3F800000); // A = 1

        // context->vtable[50@0x190](context, rtv, &color)
        emit8(0x4C); emit8(0x8B); emit8(0x53); emit8(0x40);   // r10 = context
        emit8(0x4D); emit8(0x8B); emit8(0x12);                 // r10 = vtable
        emit8(0x4D); emit8(0x8B); emit8(0x92); emit32(0x190); // r10 = ClearRenderTargetView
        emit8(0x4C); emit8(0x8B); emit8(0x5B); emit8(0x40);   // r11 = context
        emit8(0x4C); emit8(0x89); emit8(0xD9);                // rcx = context
        emit8(0x48); emit8(0x8B); emit8(0x54); emit8(0x24); emit8(0x20); // rdx = rtv
        emit8(0x48); emit8(0x8D); emit8(0x44); emit8(0x24); emit8(0x28); // rax = &color
        emit8(0x49); emit8(0x89); emit8(0xC0);                // r8 = &color
        emit8(0x41); emit8(0xFF); emit8(0xD2);                // call r10

        emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x40);
        emitLabel(skipClearC);

        // rbx may be clobbered by the COM call on real Windows; reload.
        emit8(0x48); emit8(0x8D); emit8(0x1D);
        heapFixups.push_back({code.size(), win32GlobalsRVA});
        emit32(0);

        regsUsed = 1;
        emitMovRegImm(0, 0);
        resultReg = 0;
        return true;
    }

    // === dxClearGPU() - TEMPORARY DIAGNOSTIC (kept) ===
    // Re-acquires the swapchain backbuffer each call (like CPU present),
    // creates a fresh RTV, binds it, clears it red, then sets gpuFrame=1.
    // Decisive: if present (GPU-only) then shows red, the bug was the stale
    // init-cached RTV; if black, the GPU render->present chain is broken.
    if (call->name == "dxClearGPU" && call->args.empty()) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;

        // IID_ID3D11Texture2D (same as init)
        std::string iidBytes(16, '\0');
        iidBytes[0] = '\xF2'; iidBytes[1] = '\xAA'; iidBytes[2] = '\x15'; iidBytes[3] = '\x6F';
        iidBytes[4] = '\x08'; iidBytes[5] = '\xD2'; iidBytes[6] = '\x89'; iidBytes[7] = '\x4E';
        iidBytes[8] = '\x9A'; iidBytes[9] = '\xB4'; iidBytes[10] = '\x48'; iidBytes[11] = '\x95';
        iidBytes[12] = '\x35'; iidBytes[13] = '\xD3'; iidBytes[14] = '\x4F'; iidBytes[15] = '\x9C';
        int iidIdx = ensureString(iidBytes);

        emit8(0x48); emit8(0x8D); emit8(0x1D);
        heapFixups.push_back({code.size(), win32GlobalsRVA});
        emit32(0);

        emit8(0x48); emit8(0x81); emit8(0xEC); emit32(0xC0);
        // stack: [rsp+0x20]=color [rsp+0x50]=backBuffer [rsp+0x58]=rtv [rsp+0x60]=&rtvSlot

        // Progress markers m1..m5 (0x01 byte each) to pinpoint the crashing call.
        auto writeMarkerD3 = [&](int pIdx) {
            emit8(0x48); emit8(0x8D); emit8(0x0D);
            heapFixups.push_back({code.size(), stringRVA + stringOffsets[pIdx]});
            emit32(0);
            emit8(0xBA); emit32(0x40000000);
            emit8(0x45); emit8(0x31); emit8(0xC0);
            emit8(0x45); emit8(0x31); emit8(0xC9);
            emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x20); emit32(2);
            emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x28); emit32(0x80);
            emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x30); emit32(0);
            emit8(0xFF); emit8(0x15);
            importCallFixups.push_back({code.size(), "CreateFileA", "kernel32.dll"});
            emit32(0);
            emit8(0x49); emit8(0x89); emit8(0xC4);
            emit8(0x49); emit8(0x83); emit8(0xFC); emit8(0xFF);
            int mFail2 = newLabel();
            emitJcc("==", mFail2);
            emit8(0x4C); emit8(0x89); emit8(0xE1);
            emit8(0x48); emit8(0x8D); emit8(0x94); emit8(0x24); emit32(0xB0);
            emit8(0xC7); emit8(0x84); emit8(0x24); emit32(0xB0); emit32(1);
            emit8(0x41); emit8(0xB8); emit32(1);
            emit8(0x4C); emit8(0x8D); emit8(0x8C); emit8(0x24); emit32(0xB4);
            emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x20); emit32(0);
            emit8(0xFF); emit8(0x15);
            importCallFixups.push_back({code.size(), "WriteFile", "kernel32.dll"});
            emit32(0);
            emit8(0x4C); emit8(0x89); emit8(0xE1);
            emit8(0xFF); emit8(0x15);
            importCallFixups.push_back({code.size(), "CloseHandle", "kernel32.dll"});
            emit32(0);
            emitLabel(mFail2);
        };
        int mM1 = ensureString("C:\\Users\\user\\Desktop\\b\\zenith\\build\\m1.bin");
        int mM2 = ensureString("C:\\Users\\user\\Desktop\\b\\zenith\\build\\m2.bin");
        int mM3 = ensureString("C:\\Users\\user\\Desktop\\b\\zenith\\build\\m3.bin");
        int mM4 = ensureString("C:\\Users\\user\\Desktop\\b\\zenith\\build\\m4.bin");
        int mM5 = ensureString("C:\\Users\\user\\Desktop\\b\\zenith\\build\\m5.bin");

        // color[4] = {1,0,0,1} at [rsp+0x20]
        emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x20); emit32(0x3F800000);
        emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x24); emit32(0);
        emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x28); emit32(0);
        emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x2C); emit32(0x3F800000);

        // --- swapChain->GetBuffer(0, &IID, &backBuffer) vtable[9] ---
        emit8(0x4C); emit8(0x8B); emit8(0x53); emit8(0x48);   // r10 = swapChain
        emit8(0x4D); emit8(0x8B); emit8(0x12);                 // r10 = vtable
        emit8(0x4D); emit8(0x8B); emit8(0x52); emit8(0x48);   // r10 = GetBuffer
        emit8(0x4C); emit8(0x8B); emit8(0x5B); emit8(0x48);   // r11 = swapChain
        emit8(0x4C); emit8(0x89); emit8(0xD9);                // rcx = swapChain
        emit8(0x33); emit8(0xD2);                              // rdx = 0
        emit8(0x4C); emit8(0x8D); emit8(0x05);
        heapFixups.push_back({code.size(), stringRVA + stringOffsets[iidIdx]});
        emit32(0);                                             // r8 = &IID
        emit8(0x4C); emit8(0x8D); emit8(0x4C); emit8(0x24); emit8(0x50); // r9 = &backBuffer
        emit8(0x41); emit8(0xFF); emit8(0xD2);                // call r10
        writeMarkerD3(mM1);

        // --- device->CreateRenderTargetView(device, backBuffer, NULL, &rtv) vtable[9] ---
        emit8(0x4C); emit8(0x8B); emit8(0x53); emit8(0x38);   // r10 = device
        emit8(0x4D); emit8(0x8B); emit8(0x12);                 // r10 = vtable
        emit8(0x4D); emit8(0x8B); emit8(0x52); emit8(0x48);   // r10 = CreateRenderTargetView
        emit8(0x4C); emit8(0x8B); emit8(0x5B); emit8(0x38);   // r11 = device
        emit8(0x4C); emit8(0x89); emit8(0xD9);                // rcx = device
        emit8(0x48); emit8(0x8B); emit8(0x54); emit8(0x24); emit8(0x50); // rdx = backBuffer
        emit8(0x45); emit8(0x33); emit8(0xC0);               // r8d = 0
        emit8(0x4C); emit8(0x8D); emit8(0x4C); emit8(0x24); emit8(0x58); // r9 = &rtv
        emit8(0x41); emit8(0xFF); emit8(0xD2);                // call r10
        writeMarkerD3(mM2);

        // --- OMSetRenderTargets(context, 1, &rtv, NULL) vtable[33] -> off 0x108 ---
        emit8(0x4C); emit8(0x8B); emit8(0x53); emit8(0x40);   // r10 = context
        emit8(0x4D); emit8(0x8B); emit8(0x12);                 // r10 = vtable
        emit8(0x4D); emit8(0x8B); emit8(0x92); emit32(0x108); // r10 = OMSetRenderTargets
        emit8(0x4C); emit8(0x8B); emit8(0x5B); emit8(0x40);   // r11 = context
        emit8(0x4C); emit8(0x89); emit8(0xD9);                // rcx = context
        emit8(0x48); emit8(0xC7); emit8(0xC2); emit32(1);     // rdx = 1
        emit8(0x48); emit8(0x8D); emit8(0x44); emit8(0x24); emit8(0x58); // rax = &rtv
        emit8(0x49); emit8(0x89); emit8(0xC0);                // r8 = &rtv
        emit8(0x45); emit8(0x33); emit8(0xC9);               // r9d = 0
        emit8(0x41); emit8(0xFF); emit8(0xD2);                // call r10
        writeMarkerD3(mM3);

        // --- ClearRenderTargetView(context, rtv, color) vtable[50] -> off 0x190 ---
        emit8(0x4C); emit8(0x8B); emit8(0x53); emit8(0x40);   // r10 = context
        emit8(0x4D); emit8(0x8B); emit8(0x12);                 // r10 = vtable
        emit8(0x4D); emit8(0x8B); emit8(0x92); emit32(0x190); // r10 = ClearRenderTargetView
        emit8(0x4C); emit8(0x8B); emit8(0x5B); emit8(0x40);   // r11 = context
        emit8(0x4C); emit8(0x89); emit8(0xD9);                // rcx = context
        emit8(0x48); emit8(0x8B); emit8(0x54); emit8(0x24); emit8(0x58); // rdx = rtv
        emit8(0x48); emit8(0x8D); emit8(0x44); emit8(0x24); emit8(0x20); // rax = &color
        emit8(0x49); emit8(0x89); emit8(0xC0);                // r8 = &color
        emit8(0x41); emit8(0xFF); emit8(0xD2);                // call r10
        writeMarkerD3(mM4);

        // --- swapChain->Present(1,0) vtable[8] -> off 0x40 ---
        emit8(0x4C); emit8(0x8B); emit8(0x53); emit8(0x48);   // r10 = swapChain
        emit8(0x4D); emit8(0x8B); emit8(0x12);                 // r10 = vtable
        emit8(0x4D); emit8(0x8B); emit8(0x52); emit8(0x40);   // r10 = Present
        emit8(0x4C); emit8(0x8B); emit8(0x5B); emit8(0x48);   // r11 = swapChain
        emit8(0x4C); emit8(0x89); emit8(0xD9);                // rcx = swapChain
        emit8(0xBA); emit32(1);                               // rdx = 1
        emit8(0x45); emit8(0x33); emit8(0xC0);               // r8d = 0
        emit8(0x41); emit8(0xFF); emit8(0xD2);                // call r10
        writeMarkerD3(mM5);

        // rbx may be clobbered; reload + set gpuFrame
        emit8(0x48); emit8(0x8D); emit8(0x1D);
        heapFixups.push_back({code.size(), win32GlobalsRVA});
        emit32(0);
        emit8(0xC7); emit8(0x43); emit8(0x60); emit32(1);     // [rbx+96] = gpuFrame = 1

        emit8(0x48); emit8(0x81); emit8(0xC4); emit32(0xC0);

        regsUsed = 1;
        emitMovRegImm(0, 0);
        resultReg = 0;
        return true;
    }

    // === dxCheckSwapChain() - TEMPORARY DIAGNOSTIC (kept) ===
    // From inside the process: dump hwnd, swapChain, the real DXGI_SWAP_CHAIN_DESC
    // (via swapChain->GetDesc, vtable[12]@0x60) and the Present(0,0) HRESULT to
    // build\vlock.bin. Verifies the swapchain is really attached to the visible
    // window (OutputWindow vs hwnd) and that Present is being called/succeeding.
    if (call->name == "dxCheckSwapChain" && call->args.empty()) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;

        int pathIdx = ensureString("C:\\Users\\user\\Desktop\\b\\zenith\\build\\vlock.bin");
        int mM7 = ensureString("C:\\Users\\user\\Desktop\\b\\zenith\\build\\m7.bin");
        int mM8 = ensureString("C:\\Users\\user\\Desktop\\b\\zenith\\build\\m8.bin");
        int mM9 = ensureString("C:\\Users\\user\\Desktop\\b\\zenith\\build\\m9.bin");
        emit8(0x48); emit8(0x8D); emit8(0x1D);
        heapFixups.push_back({code.size(), win32GlobalsRVA});
        emit32(0);

        emit8(0x48); emit8(0x81); emit8(0xEC); emit32(0x170);
        // stack layout:
        // [rsp+0x20..0x30] shadow
        // [rsp+0x40..0x87]  DXGI_SWAP_CHAIN_DESC local (72)
        // [rsp+0x88]        GetDesc HRESULT
        // [rsp+0x90]        Present HRESULT
        // [rsp+0xE8..]      output buffer (60 bytes)
        //  0xE8 hwnd(8) 0xF0 swapChain(8) 0xF8 w(4) 0xFC h(4) 0x100 fmt(4)
        //  0x104 count(4) 0x108 outputWindow(8) 0x110 windowed(4) 0x114 effect(4)
        //  0x118 flags(4) 0x11C presentHr(4) 0x120 getDescHr(4)

        // marker writer: writes nBytes from [rsp+0xE8] to file (path pIdx)
        auto wm = [&](int pIdx, int nBytes) {
            emit8(0x48); emit8(0x8D); emit8(0x0D);
            heapFixups.push_back({code.size(), stringRVA + stringOffsets[pIdx]});
            emit32(0);
            emit8(0xBA); emit32(0x40000000);
            emit8(0x45); emit8(0x31); emit8(0xC0);
            emit8(0x45); emit8(0x31); emit8(0xC9);
            emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x20); emit32(2);
            emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x28); emit32(0x80);
            emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x30); emit32(0);
            emit8(0xFF); emit8(0x15);
            importCallFixups.push_back({code.size(), "CreateFileA", "kernel32.dll"});
            emit32(0);
            emit8(0x49); emit8(0x89); emit8(0xC4);
            emit8(0x49); emit8(0x83); emit8(0xFC); emit8(0xFF);
            int mFail = newLabel();
            emitJcc("==", mFail);
            emit8(0x4C); emit8(0x89); emit8(0xE1);
            emit8(0x48); emit8(0x8D); emit8(0x94); emit8(0x24); emit32(0xE8);
            emit8(0x41); emit8(0xB8); emit32(nBytes);
            emit8(0x4C); emit8(0x8D); emit8(0x8C); emit8(0x24); emit32(0x124);
            emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x20); emit32(0);
            emit8(0xFF); emit8(0x15);
            importCallFixups.push_back({code.size(), "WriteFile", "kernel32.dll"});
            emit32(0);
            emit8(0x4C); emit8(0x89); emit8(0xE1);
            emit8(0xFF); emit8(0x15);
            importCallFixups.push_back({code.size(), "CloseHandle", "kernel32.dll"});
            emit32(0);
            emitLabel(mFail);
        };
        auto addDword = [&](int where, int val) {
            emit8(0xC7); emit8(0x84); emit8(0x24); emit32(where); emit32(val);
        };

        // entry marker m7
        addDword(0xE8, 1);
        wm(mM7, 1);

        // --- swapChain->GetDesc(swapChain, &desc@0x40) ---
        emit8(0x4C); emit8(0x8B); emit8(0x53); emit8(0x48);  // r10 = swapChain
        emit8(0x4D); emit8(0x8B); emit8(0x12);                // r10 = [r10] = vtable
        emit8(0x4D); emit8(0x8B); emit8(0x52); emit8(0x60);  // r10 = [r10+0x60] = GetDesc
        emit8(0x4C); emit8(0x8B); emit8(0x5B); emit8(0x48);  // r11 = swapChain
        emit8(0x4C); emit8(0x89); emit8(0xD9);               // rcx = swapChain
        emit8(0x48); emit8(0x8D); emit8(0x54); emit8(0x24); emit8(0x40); // rdx = &desc
        emit8(0x41); emit8(0xFF); emit8(0xD2);               // call r10
        emit8(0x89); emit8(0x84); emit8(0x24); emit32(0x88);  // [rsp+0x88] = GetDesc HRESULT
        // m8 = GetDesc HRESULT
        emit8(0x8B); emit8(0x84); emit8(0x24); emit32(0x88);
        emit8(0x89); emit8(0x84); emit8(0x24); emit32(0xE8);
        wm(mM8, 4);

        // --- swapChain->Present(0, 0) ---
        emit8(0x4C); emit8(0x8B); emit8(0x53); emit8(0x48);  // r10 = swapChain
        emit8(0x4D); emit8(0x8B); emit8(0x12);                // r10 = vtable
        emit8(0x4D); emit8(0x8B); emit8(0x52); emit8(0x40);  // r10 = [r10+0x40] = Present
        emit8(0x4C); emit8(0x8B); emit8(0x5B); emit8(0x48);  // r11 = swapChain
        emit8(0x4C); emit8(0x89); emit8(0xD9);               // rcx = swapChain
        emit8(0x33); emit8(0xD2);                             // rdx = 0 (SyncInterval)
        emit8(0x45); emit8(0x33); emit8(0xC0);              // r8d = 0 (Flags)
        emit8(0x41); emit8(0xFF); emit8(0xD2);               // call r10
        emit8(0x89); emit8(0x84); emit8(0x24); emit32(0x11C); // [rsp+0x11C] = Present HRESULT
        // m9 = Present HRESULT
        emit8(0x8B); emit8(0x84); emit8(0x24); emit32(0x11C);
        emit8(0x89); emit8(0x84); emit8(0x24); emit32(0xE8);
        wm(mM9, 4);

        // --- populate output buffer ---
        emit8(0x48); emit8(0x8B); emit8(0x43); emit8(0x08);  // rax = [rbx+8] = hwnd
        emit8(0x48); emit8(0x89); emit8(0x84); emit8(0x24); emit32(0xE8);
        emit8(0x4C); emit8(0x8B); emit8(0x53); emit8(0x48);  // r10 = swapChain
        emit8(0x4C); emit8(0x89); emit8(0x94); emit8(0x24); emit32(0xF0);
        // copy desc fields into output buffer
        emit8(0x8B); emit8(0x44); emit8(0x24); emit8(0x40);  // Width
        emit8(0x89); emit8(0x84); emit8(0x24); emit32(0xF8);
        emit8(0x8B); emit8(0x44); emit8(0x24); emit8(0x44);  // Height
        emit8(0x89); emit8(0x84); emit8(0x24); emit32(0xFC);
        emit8(0x8B); emit8(0x44); emit8(0x24); emit8(0x50);  // Format
        emit8(0x89); emit8(0x84); emit8(0x24); emit32(0x100);
        emit8(0x8B); emit8(0x44); emit8(0x24); emit8(0x68);  // BufferCount
        emit8(0x89); emit8(0x84); emit8(0x24); emit32(0x104);
        emit8(0x48); emit8(0x8B); emit8(0x44); emit8(0x24); emit8(0x70);  // OutputWindow
        emit8(0x48); emit8(0x89); emit8(0x84); emit8(0x24); emit32(0x108);
        emit8(0x8B); emit8(0x44); emit8(0x24); emit8(0x78);  // Windowed
        emit8(0x89); emit8(0x84); emit8(0x24); emit32(0x110);
        emit8(0x8B); emit8(0x44); emit8(0x24); emit8(0x7C);  // SwapEffect
        emit8(0x89); emit8(0x84); emit8(0x24); emit32(0x114);
        emit8(0x8B); emit8(0x44); emit8(0x24); emit8(0x80);  // Flags
        emit8(0x89); emit8(0x84); emit8(0x24); emit32(0x118);
        emit8(0x8B); emit8(0x84); emit8(0x24); emit32(0x88); // eax = GetDesc HRESULT
        emit8(0x89); emit8(0x84); emit8(0x24); emit32(0x120);

        // --- write 60 bytes from [rsp+0xE8] to vlock.bin ---
        wm(pathIdx, 60);

        emit8(0x48); emit8(0x81); emit8(0xC4); emit32(0x170);

        regsUsed = 1;
        emitMovRegImm(0, 0);
        resultReg = 0;
        return true;
    }

    // === dxProbeGPU() - TEMPORARY DIAGNOSTIC (kept) ===
    // Raw GPU-pipeline test independent of the swapchain:
    //   1. Create offscreen RT texture + RTV (Usage DEFAULT, Bind RENDER_TARGET)
    //   2. ClearRenderTargetView to red
    //   3. Create readback staging (Usage STAGING, CPU_ACCESS_READ)
    //   4. CopyResource(readback <- offscreen)
    //   5. Map readback, read first pixel, write 4 bytes to build\probe.bin
    // readback first pixel == red (0,0,255,255)  => GPU writes pixels; bug is in swapchain present
    // readback first pixel == black              => GPU pipeline itself broken
    if (call->name == "dxProbeGPU" && call->args.empty()) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;

        int pathIdx = ensureString("C:\\Users\\user\\Desktop\\b\\zenith\\build\\probe.bin");
        std::string iidBytes(16, '\0');
        iidBytes[0] = '\xF2'; iidBytes[1] = '\xAA'; iidBytes[2] = '\x15'; iidBytes[3] = '\x6F';
        iidBytes[4] = '\x08'; iidBytes[5] = '\xD2'; iidBytes[6] = '\x89'; iidBytes[7] = '\x4E';
        iidBytes[8] = '\x9A'; iidBytes[9] = '\xB4'; iidBytes[10] = '\x48'; iidBytes[11] = '\x95';
        iidBytes[12] = '\x35'; iidBytes[13] = '\xD3'; iidBytes[14] = '\x4F'; iidBytes[15] = '\x9C';
        int iidIdx = ensureString(iidBytes);

        emit8(0x48); emit8(0x8D); emit8(0x1D);
        heapFixups.push_back({code.size(), win32GlobalsRVA});
        emit32(0);

        emit8(0x48); emit8(0x81); emit8(0xEC); emit32(0x160);
        // stack layout:
        // [rsp+0x20..0x4F]  D3D11_TEXTURE2D_DESC (offscreen)
        // [rsp+0x50]        offscreen texture
        // [rsp+0x58]        rtv
        // [rsp+0x60..0x8F]  D3D11_TEXTURE2D_DESC (readback)
        // [rsp+0x90]        readback texture
        // [rsp+0x98..0xAF]  D3D11_MAPPED_SUBRESOURCE (pData, RowPitch, DepthPitch)
        // [rsp+0xC0..0xCF]  red color {1,0,0,1}

        int sFailZ = newLabel();

        // ---- MARKER helper: writes nBytes from [rsp+0xE8] to file (path string at pIdx) ----
        auto writeFile = [&](int pIdx, int nBytes) {
            emit8(0x48); emit8(0x8D); emit8(0x0D);
            heapFixups.push_back({code.size(), stringRVA + stringOffsets[pIdx]});
            emit32(0);
            emit8(0xBA); emit32(0x40000000);
            emit8(0x45); emit8(0x31); emit8(0xC0);
            emit8(0x45); emit8(0x31); emit8(0xC9);
            emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x20); emit32(2);
            emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x28); emit32(0x80);
            emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x30); emit32(0);
            emit8(0xFF); emit8(0x15);
            importCallFixups.push_back({code.size(), "CreateFileA", "kernel32.dll"});
            emit32(0);
            emit8(0x49); emit8(0x89); emit8(0xC4);
            emit8(0x49); emit8(0x83); emit8(0xFC); emit8(0xFF);
            int mFail = newLabel();
            emitJcc("==", mFail);
            emit8(0x4C); emit8(0x89); emit8(0xE1);
            emit8(0x48); emit8(0x8D); emit8(0x94); emit8(0x24); emit32(0xE8);
            emit8(0x41); emit8(0xB8); emit32(nBytes);
            emit8(0x4C); emit8(0x8D); emit8(0x8C); emit8(0x24); emit32(0xEC);
            emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x20); emit32(0);
            emit8(0xFF); emit8(0x15);
            importCallFixups.push_back({code.size(), "WriteFile", "kernel32.dll"});
            emit32(0);
            emit8(0x4C); emit8(0x89); emit8(0xE1);
            emit8(0xFF); emit8(0x15);
            importCallFixups.push_back({code.size(), "CloseHandle", "kernel32.dll"});
            emit32(0);
            emitLabel(mFail);
        };
        auto writeMarker = [&](int pIdx) {   // single byte 0x01
            emit8(0xC7); emit8(0x84); emit8(0x24); emit32(0xE8); emit32(0x01);
            writeFile(pIdx, 1);
        };
        auto writeDword = [&](int pIdx) {    // dword already placed at [rsp+0xE8]
            writeFile(pIdx, 4);
        };
        int mM1 = ensureString("C:\\Users\\user\\Desktop\\b\\zenith\\build\\m1.bin");
        int mM2 = ensureString("C:\\Users\\user\\Desktop\\b\\zenith\\build\\m2.bin");
        int mM3 = ensureString("C:\\Users\\user\\Desktop\\b\\zenith\\build\\m3.bin");
        int mM4 = ensureString("C:\\Users\\user\\Desktop\\b\\zenith\\build\\m4.bin");
        int mM5 = ensureString("C:\\Users\\user\\Desktop\\b\\zenith\\build\\m5.bin");
        int mM6 = ensureString("C:\\Users\\user\\Desktop\\b\\zenith\\build\\m6.bin");

        writeMarker(mM1);

        // ==== screen readback: GetBuffer(backbuffer) -> STAGING -> CopyResource -> Map -> dump ====
        // --- swapChain->GetBuffer(0, &IID, &backBuffer) vtable[9] @0x24? -> use offset 0x48 (dxClearGPU pattern) ---
        emit8(0x4C); emit8(0x8B); emit8(0x53); emit8(0x48);   // r10 = swapChain
        emit8(0x4D); emit8(0x8B); emit8(0x12);                 // r10 = vtable
        emit8(0x4D); emit8(0x8B); emit8(0x52); emit8(0x48);   // r10 = GetBuffer
        emit8(0x4C); emit8(0x8B); emit8(0x5B); emit8(0x48);   // r11 = swapChain
        emit8(0x4C); emit8(0x89); emit8(0xD9);                // rcx = swapChain
        emit8(0x33); emit8(0xD2);                              // rdx = 0
        emit8(0x4C); emit8(0x8D); emit8(0x05);
        heapFixups.push_back({code.size(), stringRVA + stringOffsets[iidIdx]});
        emit32(0);                                             // r8 = &IID
        emit8(0x4C); emit8(0x8D); emit8(0x4C); emit8(0x24); emit8(0x50); // r9 = &backBuffer
        emit8(0x41); emit8(0xFF); emit8(0xD2);                // call r10
        writeMarker(mM2);

        // ---- Fill readback desc at [rsp+0x60] ----
        emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x60); emit32(800);
        emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x64); emit32(600);
        emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x68); emit32(1);
        emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x6C); emit32(1);
        emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x70); emit32(28);
        emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x74); emit32(1);
        emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x78); emit32(0);
        emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x7C); emit32(3);     // Usage STAGING
        emit8(0xC7); emit8(0x84); emit8(0x24); emit32(0x80); emit32(0);
        emit8(0xC7); emit8(0x84); emit8(0x24); emit32(0x84); emit32(0x20000);
        emit8(0xC7); emit8(0x84); emit8(0x24); emit32(0x88); emit32(0);

        // ---- device->CreateTexture2D(device, &readbackDesc, NULL, &readback) ----
        emit8(0x4C); emit8(0x8B); emit8(0x53); emit8(0x38);
        emit8(0x4D); emit8(0x8B); emit8(0x12);
        emit8(0x4D); emit8(0x8B); emit8(0x52); emit8(0x28);
        emit8(0x4C); emit8(0x8B); emit8(0x5B); emit8(0x38);
        emit8(0x4C); emit8(0x89); emit8(0xD9);
        emit8(0x48); emit8(0x8D); emit8(0x54); emit8(0x24); emit8(0x60);
        emit8(0x45); emit8(0x33); emit8(0xC0);
        emit8(0x4C); emit8(0x8D); emit8(0x8C); emit8(0x24); emit32(0x90);
        emit8(0x41); emit8(0xFF); emit8(0xD2);
        writeMarker(mM5);   // readback created

        // ---- context->CopyResource(context, readback, backBuffer) vtable[47] -> 0x178 ----
        emit8(0x4C); emit8(0x8B); emit8(0x53); emit8(0x40);
        emit8(0x4D); emit8(0x8B); emit8(0x12);
        emit8(0x4D); emit8(0x8B); emit8(0x92); emit32(0x178);
        emit8(0x4C); emit8(0x8B); emit8(0x5B); emit8(0x40);
        emit8(0x4C); emit8(0x89); emit8(0xD9);                                // rcx = context
        emit8(0x48); emit8(0x8B); emit8(0x94); emit8(0x24); emit32(0x90);     // rdx = readback
        emit8(0x48); emit8(0x8B); emit8(0x44); emit8(0x24); emit8(0x50);      // rax = backBuffer
        emit8(0x49); emit8(0x89); emit8(0xC0);                                // r8 = backBuffer
        emit8(0x41); emit8(0xFF); emit8(0xD2);
        writeMarker(mM4);

        // ---- context->Map(context, readback, 0, D3D11_MAP_READ=1, 0, &mapped) vtable[14] -> 0x70 ----
        emit8(0x48); emit8(0x8D); emit8(0x84); emit8(0x24); emit32(0x98);     // rax = &mapped
        emit8(0x48); emit8(0x89); emit8(0x44); emit8(0x24); emit8(0x28);      // [rsp+0x28] = &mapped  (6th arg)
        emit8(0x4C); emit8(0x8B); emit8(0x53); emit8(0x40);                    // r10 = context
        emit8(0x4D); emit8(0x8B); emit8(0x12);
        emit8(0x4D); emit8(0x8B); emit8(0x52); emit8(0x70);                    // r10 = Map
        emit8(0x4C); emit8(0x8B); emit8(0x5B); emit8(0x40);                    // r11 = context
        emit8(0x4C); emit8(0x89); emit8(0xD9);                                 // rcx = context
        emit8(0x48); emit8(0x8B); emit8(0x94); emit8(0x24); emit32(0x90);      // rdx = readback
        emit8(0x45); emit8(0x33); emit8(0xC0);                                // r8d = 0
        emit8(0x41); emit8(0xB9); emit32(1);                                   // r9d = D3D11_MAP_READ
        emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x20); emit32(0); // MapFlags (5th arg)
        emit8(0x41); emit8(0xFF); emit8(0xD2);
        writeMarker(mM6);

        // ---- read 4 pixels: (0,0) bg, (400,300) center, (650,450), (790,590) ----
        // pData = [rsp+0x98]; RowPitch = [rsp+0xA0] (qword slot)
        emit8(0x48); emit8(0x8B); emit8(0x84); emit8(0x24); emit32(0x98); // rax = pData
        emit8(0x8B); emit8(0x08);                            // ecx = [pData] (0,0)
        emit8(0x89); emit8(0x8C); emit8(0x24); emit32(0xE0);  // [rsp+0xE0] = px0
        emit8(0x8B); emit8(0x8C); emit8(0x24); emit32(0xA0);  // ecx = RowPitch (UINT32, zero-extend)
        emit8(0x48); emit8(0x69); emit8(0xC9); emit32(300);   // rcx = pitch*300
        emit8(0x48); emit8(0x01); emit8(0xC1);                // rcx += pData
        emit8(0x48); emit8(0x8D); emit8(0x89); emit32(1600);  // rcx += 400*4
        emit8(0x8B); emit8(0x11);                             // ecx = [center]
        emit8(0x89); emit8(0x94); emit8(0x24); emit32(0xE4);  // [rsp+0xE4] = px1
        emit8(0x8B); emit8(0x8C); emit8(0x24); emit32(0xA0);
        emit8(0x48); emit8(0x69); emit8(0xC9); emit32(450);
        emit8(0x48); emit8(0x01); emit8(0xC1);
        emit8(0x48); emit8(0x8D); emit8(0x89); emit32(2600);
        emit8(0x8B); emit8(0x11);
        emit8(0x89); emit8(0x94); emit8(0x24); emit32(0xE8);  // [rsp+0xE8] = px2
        emit8(0x8B); emit8(0x8C); emit8(0x24); emit32(0xA0);
        emit8(0x48); emit8(0x69); emit8(0xC9); emit32(590);
        emit8(0x48); emit8(0x01); emit8(0xC1);
        emit8(0x48); emit8(0x8D); emit8(0x89); emit32(3160);
        emit8(0x8B); emit8(0x11);
        emit8(0x89); emit8(0x94); emit8(0x24); emit32(0xEC);  // [rsp+0xEC] = px3

        // ---- Write 16 bytes to probe.bin ----
        emit8(0x48); emit8(0x8D); emit8(0x0D);
        heapFixups.push_back({code.size(), stringRVA + stringOffsets[pathIdx]});
        emit32(0);
        emit8(0xBA); emit32(0x40000000);
        emit8(0x45); emit8(0x31); emit8(0xC0);
        emit8(0x45); emit8(0x31); emit8(0xC9);
        emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x20); emit32(2);
        emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x28); emit32(0x80);
        emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x30); emit32(0);
        emit8(0xFF); emit8(0x15);
        importCallFixups.push_back({code.size(), "CreateFileA", "kernel32.dll"});
        emit32(0);
        emit8(0x49); emit8(0x89); emit8(0xC4);
        emit8(0x49); emit8(0x83); emit8(0xFC); emit8(0xFF);
        int sFailD = newLabel();
        emitJcc("==", sFailD);
        emit8(0x4C); emit8(0x89); emit8(0xE1);              // rcx = hFile
        emit8(0x48); emit8(0x8D); emit8(0x94); emit8(0x24); emit32(0xE0); // rdx = &pixel
        emit8(0x41); emit8(0xB8); emit32(16);              // r8 = 16 bytes
        emit8(0x4C); emit8(0x8D); emit8(0x8C); emit8(0x24); emit32(0xE4); // r9 = &written
        emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x20); emit32(0);
        emit8(0xFF); emit8(0x15);
        importCallFixups.push_back({code.size(), "WriteFile", "kernel32.dll"});
        emit32(0);
        emit8(0x4C); emit8(0x89); emit8(0xE1);              // rcx = hFile
        emit8(0xFF); emit8(0x15);
        importCallFixups.push_back({code.size(), "CloseHandle", "kernel32.dll"});
        emit32(0);
        emitLabel(sFailD);

        emitLabel(sFailZ);

        emit8(0x48); emit8(0x81); emit8(0xC4); emit32(0x160);

        regsUsed = 1;
        emitMovRegImm(0, 0);
        resultReg = 0;
        return true;
    }

    // === dxTrace() - TEMPORARY DIAGNOSTIC ===
    // Replicates the FULL clear->readback->present chain in ONE call with
    // HRESULT capture (markers in dxClearGPU/dxProbeGPU never checked HRs).
    // Order: GetBuffer -> CreateRTV -> OMSetRT -> ClearRT(red) ->
    //        staging CreateTexture2D -> CopyResource -> Map ->
    //        read 4 pixels -> Present(0,0). Readback happens BEFORE present so
    //        a 1-buffer DISCARD swapchain can't discard the content first.
    // Writes trace.bin:
    //   0xA0 hwnd(8) 0xA8 device(8) 0xB0 context(8) 0xB8 swapChain(8)
    //   0xC0 hrGetBuffer(4) 0xC4 backBuffer(8)
    //   0xCC hrCreateRTV(4) 0xD0 rtv(8)
    //   0xD8 hrStaging(4) 0xDC hrMap(4)
    //   0xE0..0xEF px0..px3 (16 bytes)
    //   0xF0 hrPresent(4)  (total 0xF4 bytes)
    if (call->name == "dxTrace" && call->args.empty()) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;

        int pathIdx = ensureString("C:\\Users\\user\\Desktop\\b\\zenith\\build\\trace.bin");
        std::string iidBytes(16, '\0');
        iidBytes[0] = '\xF2'; iidBytes[1] = '\xAA'; iidBytes[2] = '\x15'; iidBytes[3] = '\x6F';
        iidBytes[4] = '\x08'; iidBytes[5] = '\xD2'; iidBytes[6] = '\x89'; iidBytes[7] = '\x4E';
        iidBytes[8] = '\x9A'; iidBytes[9] = '\xB4'; iidBytes[10] = '\x48'; iidBytes[11] = '\x95';
        iidBytes[12] = '\x35'; iidBytes[13] = '\xD3'; iidBytes[14] = '\x4F'; iidBytes[15] = '\x9C';
        int iidIdx = ensureString(iidBytes);

        emit8(0x48); emit8(0x8D); emit8(0x1D);
        heapFixups.push_back({code.size(), win32GlobalsRVA});
        emit32(0);

        emit8(0x48); emit8(0x81); emit8(0xEC); emit32(0x1D0);
        // stack: [rsp+0x20..0x2F]=color(clear after ClearRT) [rsp+0x30]=backBuffer
        //        [rsp+0x38]=rtv [rsp+0x40..0x68]=readback desc [rsp+0x70]=readback
        //        [rsp+0x78..0x8F]=mapped [rsp+0x90]=written [rsp+0xA0..]=trace payload

        // dump hwnd/device/context/swapChain
        emit8(0x48); emit8(0x8B); emit8(0x4B); emit8(0x08);
        emit8(0x48); emit8(0x89); emit8(0x8C); emit8(0x24); emit32(0xA0);
        emit8(0x48); emit8(0x8B); emit8(0x4B); emit8(0x38);
        emit8(0x48); emit8(0x89); emit8(0x8C); emit8(0x24); emit32(0xA8);
        emit8(0x48); emit8(0x8B); emit8(0x4B); emit8(0x40);
        emit8(0x48); emit8(0x89); emit8(0x8C); emit8(0x24); emit32(0xB0);
        emit8(0x48); emit8(0x8B); emit8(0x4B); emit8(0x48);
        emit8(0x48); emit8(0x89); emit8(0x8C); emit8(0x24); emit32(0xB8);

        // color[4] = {1,0,0,1}
        emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x20); emit32(0x3F800000);
        emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x24); emit32(0);
        emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x28); emit32(0);
        emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x2C); emit32(0x3F800000);

        // --- swapChain->GetBuffer(0, &IID, &backBuffer) vtable@0x48 ---
        emit8(0x4C); emit8(0x8B); emit8(0x53); emit8(0x48);
        emit8(0x4D); emit8(0x8B); emit8(0x12);
        emit8(0x4D); emit8(0x8B); emit8(0x52); emit8(0x48);
        emit8(0x4C); emit8(0x8B); emit8(0x5B); emit8(0x48);
        emit8(0x4C); emit8(0x89); emit8(0xD9);
        emit8(0x33); emit8(0xD2);
        emit8(0x4C); emit8(0x8D); emit8(0x05);
        heapFixups.push_back({code.size(), stringRVA + stringOffsets[iidIdx]});
        emit32(0);
        emit8(0x4C); emit8(0x8D); emit8(0x4C); emit8(0x24); emit8(0x30);
        emit8(0x41); emit8(0xFF); emit8(0xD2);
        emit8(0x89); emit8(0x84); emit8(0x24); emit32(0xC0);
        emit8(0x48); emit8(0x8B); emit8(0x44); emit8(0x24); emit8(0x30);
        emit8(0x48); emit8(0x89); emit8(0x84); emit8(0x24); emit32(0xC4);

        // --- device->CreateRenderTargetView(device, back, NULL, &rtv) vtable@0x48 ---
        emit8(0x4C); emit8(0x8B); emit8(0x53); emit8(0x38);
        emit8(0x4D); emit8(0x8B); emit8(0x12);
        emit8(0x4D); emit8(0x8B); emit8(0x52); emit8(0x48);
        emit8(0x4C); emit8(0x8B); emit8(0x5B); emit8(0x38);
        emit8(0x4C); emit8(0x89); emit8(0xD9);
        emit8(0x48); emit8(0x8B); emit8(0x54); emit8(0x24); emit8(0x30);
        emit8(0x45); emit8(0x33); emit8(0xC0);
        emit8(0x4C); emit8(0x8D); emit8(0x4C); emit8(0x24); emit8(0x38);
        emit8(0x41); emit8(0xFF); emit8(0xD2);
        emit8(0x89); emit8(0x84); emit8(0x24); emit32(0xCC);
        emit8(0x48); emit8(0x8B); emit8(0x44); emit8(0x24); emit8(0x38);
        emit8(0x48); emit8(0x89); emit8(0x84); emit8(0x24); emit32(0xD0);

        // --- OMSetRenderTargets(context, 1, &rtv, NULL) vtable@0x108 ---
        emit8(0x4C); emit8(0x8B); emit8(0x53); emit8(0x40);
        emit8(0x4D); emit8(0x8B); emit8(0x12);
        emit8(0x4D); emit8(0x8B); emit8(0x92); emit32(0x108);
        emit8(0x4C); emit8(0x8B); emit8(0x5B); emit8(0x40);
        emit8(0x4C); emit8(0x89); emit8(0xD9);
        emit8(0x48); emit8(0xC7); emit8(0xC2); emit32(1);
        emit8(0x48); emit8(0x8D); emit8(0x44); emit8(0x24); emit8(0x38);
        emit8(0x49); emit8(0x89); emit8(0xC0);
        emit8(0x45); emit8(0x33); emit8(0xC9);
        emit8(0x41); emit8(0xFF); emit8(0xD2);

        // --- ClearRenderTargetView(context, rtv, color) vtable@0x190 ---
        emit8(0x4C); emit8(0x8B); emit8(0x53); emit8(0x40);
        emit8(0x4D); emit8(0x8B); emit8(0x12);
        emit8(0x4D); emit8(0x8B); emit8(0x92); emit32(0x190);
        emit8(0x4C); emit8(0x8B); emit8(0x5B); emit8(0x40);
        emit8(0x4C); emit8(0x89); emit8(0xD9);
        emit8(0x48); emit8(0x8B); emit8(0x54); emit8(0x24); emit8(0x38);
        emit8(0x48); emit8(0x8D); emit8(0x44); emit8(0x24); emit8(0x20);
        emit8(0x49); emit8(0x89); emit8(0xC0);
        emit8(0x41); emit8(0xFF); emit8(0xD2);

        // ---- Fill readback desc at [rsp+0x40] (D3D11_TEXTURE2D_DESC) ----
        emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x40); emit32(800);    // Width
        emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x44); emit32(600);    // Height
        emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x48); emit32(1);      // MipLevels
        emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x4C); emit32(1);      // ArraySize
        emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x50); emit32(28);     // Format R8G8B8A8_UNORM
        emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x54); emit32(1);      // SampleDesc.Count
        emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x58); emit32(0);      // SampleDesc.Quality
        emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x5C); emit32(3);      // Usage STAGING
        emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x60); emit32(0);      // BindFlags
        emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x64); emit32(0x20000);// CPUAccessFlags READ
        emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x68); emit32(0);      // MiscFlags

        // ---- device->CreateTexture2D(device, &desc, NULL, &readback) vtable@0x28 ----
        emit8(0x4C); emit8(0x8B); emit8(0x53); emit8(0x38);
        emit8(0x4D); emit8(0x8B); emit8(0x12);
        emit8(0x4D); emit8(0x8B); emit8(0x52); emit8(0x28);
        emit8(0x4C); emit8(0x8B); emit8(0x5B); emit8(0x38);
        emit8(0x4C); emit8(0x89); emit8(0xD9);
        emit8(0x48); emit8(0x8D); emit8(0x54); emit8(0x24); emit8(0x40);
        emit8(0x45); emit8(0x33); emit8(0xC0);
        emit8(0x4C); emit8(0x8D); emit8(0x8C); emit8(0x24); emit32(0x70);
        emit8(0x41); emit8(0xFF); emit8(0xD2);
        emit8(0x89); emit8(0x84); emit8(0x24); emit32(0xD8);

        // ---- context->CopyResource(context, readback, backBuffer) vtable@0x178 ----
        emit8(0x4C); emit8(0x8B); emit8(0x53); emit8(0x40);
        emit8(0x4D); emit8(0x8B); emit8(0x12);
        emit8(0x4D); emit8(0x8B); emit8(0x92); emit32(0x178);
        emit8(0x4C); emit8(0x8B); emit8(0x5B); emit8(0x40);
        emit8(0x4C); emit8(0x89); emit8(0xD9);
        emit8(0x48); emit8(0x8B); emit8(0x94); emit8(0x24); emit32(0x70);
        emit8(0x48); emit8(0x8B); emit8(0x44); emit8(0x24); emit8(0x30);
        emit8(0x49); emit8(0x89); emit8(0xC0);
        emit8(0x41); emit8(0xFF); emit8(0xD2);

        // ---- context->Map(context, readback, 0, D3D11_MAP_READ=1, 0, &mapped) vtable@0x70 ----
        emit8(0x48); emit8(0x8D); emit8(0x84); emit8(0x24); emit32(0x78);
        emit8(0x48); emit8(0x89); emit8(0x44); emit8(0x24); emit8(0x28);
        emit8(0x4C); emit8(0x8B); emit8(0x53); emit8(0x40);
        emit8(0x4D); emit8(0x8B); emit8(0x12);
        emit8(0x4D); emit8(0x8B); emit8(0x52); emit8(0x70);
        emit8(0x4C); emit8(0x8B); emit8(0x5B); emit8(0x40);
        emit8(0x4C); emit8(0x89); emit8(0xD9);
        emit8(0x48); emit8(0x8B); emit8(0x94); emit8(0x24); emit32(0x70);
        emit8(0x45); emit8(0x33); emit8(0xC0);
        emit8(0x41); emit8(0xB9); emit32(1);
        emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x20); emit32(0);
        emit8(0x41); emit8(0xFF); emit8(0xD2);
        emit8(0x89); emit8(0x84); emit8(0x24); emit32(0xDC);

        // ---- read 4 pixels: (0,0), (400,300), (650,450), (790,590) ----
        emit8(0x48); emit8(0x8B); emit8(0x84); emit8(0x24); emit32(0x78);
        emit8(0x8B); emit8(0x08);
        emit8(0x89); emit8(0x8C); emit8(0x24); emit32(0xE0);
        emit8(0x8B); emit8(0x8C); emit8(0x24); emit32(0x80);
        emit8(0x48); emit8(0x69); emit8(0xC9); emit32(300);
        emit8(0x48); emit8(0x01); emit8(0xC1);
        emit8(0x48); emit8(0x8D); emit8(0x89); emit32(1600);
        emit8(0x8B); emit8(0x11);
        emit8(0x89); emit8(0x94); emit8(0x24); emit32(0xE4);
        emit8(0x8B); emit8(0x8C); emit8(0x24); emit32(0x80);
        emit8(0x48); emit8(0x69); emit8(0xC9); emit32(450);
        emit8(0x48); emit8(0x01); emit8(0xC1);
        emit8(0x48); emit8(0x8D); emit8(0x89); emit32(2600);
        emit8(0x8B); emit8(0x11);
        emit8(0x89); emit8(0x94); emit8(0x24); emit32(0xE8);
        emit8(0x8B); emit8(0x8C); emit8(0x24); emit32(0x80);
        emit8(0x48); emit8(0x69); emit8(0xC9); emit32(590);
        emit8(0x48); emit8(0x01); emit8(0xC1);
        emit8(0x48); emit8(0x8D); emit8(0x89); emit32(3160);
        emit8(0x8B); emit8(0x11);
        emit8(0x89); emit8(0x94); emit8(0x24); emit32(0xEC);

        // ---- swapChain->Present(0,0) vtable@0x40 ----
        emit8(0x4C); emit8(0x8B); emit8(0x53); emit8(0x48);
        emit8(0x4D); emit8(0x8B); emit8(0x12);
        emit8(0x4D); emit8(0x8B); emit8(0x52); emit8(0x40);
        emit8(0x4C); emit8(0x8B); emit8(0x5B); emit8(0x48);
        emit8(0x4C); emit8(0x89); emit8(0xD9);
        emit8(0x33); emit8(0xD2);
        emit8(0x45); emit8(0x33); emit8(0xC0);
        emit8(0x41); emit8(0xFF); emit8(0xD2);
        emit8(0x89); emit8(0x84); emit8(0x24); emit32(0xF0);

        // ---- Write 0xF4 bytes from [rsp+0xA0] to trace.bin ----
        emit8(0x48); emit8(0x8D); emit8(0x0D);
        heapFixups.push_back({code.size(), stringRVA + stringOffsets[pathIdx]});
        emit32(0);
        emit8(0xBA); emit32(0x40000000);
        emit8(0x45); emit8(0x31); emit8(0xC0);
        emit8(0x45); emit8(0x31); emit8(0xC9);
        emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x20); emit32(2);
        emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x28); emit32(0x80);
        emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x30); emit32(0);
        emit8(0xFF); emit8(0x15);
        importCallFixups.push_back({code.size(), "CreateFileA", "kernel32.dll"});
        emit32(0);
        emit8(0x49); emit8(0x89); emit8(0xC4);
        emit8(0x49); emit8(0x83); emit8(0xFC); emit8(0xFF);
        int sFailT = newLabel();
        emitJcc("==", sFailT);
        emit8(0x4C); emit8(0x89); emit8(0xE1);
        emit8(0x48); emit8(0x8D); emit8(0x94); emit8(0x24); emit32(0xA0);
        emit8(0x41); emit8(0xB8); emit32(0xF4);
        emit8(0x4C); emit8(0x8D); emit8(0x8C); emit8(0x24); emit32(0x90);
        emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x20); emit32(0);
        emit8(0xFF); emit8(0x15);
        importCallFixups.push_back({code.size(), "WriteFile", "kernel32.dll"});
        emit32(0);
        emit8(0x4C); emit8(0x89); emit8(0xE1);
        emit8(0xFF); emit8(0x15);
        importCallFixups.push_back({code.size(), "CloseHandle", "kernel32.dll"});
        emit32(0);
        emitLabel(sFailT);

        emit8(0x48); emit8(0x81); emit8(0xC4); emit32(0x1D0);

        regsUsed = 1;
        emitMovRegImm(0, 0);
        resultReg = 0;
        return true;
    }

    // === dxDumpState() - TEMPORARY DIAGNOSTIC (kept) ===
    // Calls VSGetShader/PSGetShader/IAGetInputLayout/IAGetPrimitiveTopology on
    // the context and writes the 4 returned handles to a hardcoded file
    // (8 bytes each). 0 => that pipeline stage is NOT bound.
    if (call->name == "dxDumpState" && call->args.size() == 0) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;

        int dumpPathIdx = ensureString("C:\\Users\\user\\Desktop\\b\\zenith\\build\\state.bin");
        emit8(0x48); emit8(0x8D); emit8(0x1D);
        heapFixups.push_back({code.size(), win32GlobalsRVA});
        emit32(0);

        // Stack 0xA0 new: shadow [rsp+0x20..0x28]; outputs:
        // [rsp+0x40]=vs [rsp+0x48]=ps [rsp+0x50]=layout [rsp+0x58]=topo
        // buffer [rsp+0x70..0x8F]; written [rsp+0x60]; marker scratch [rsp+0x68]
        emit8(0x48); emit8(0x81); emit8(0xEC); emit32(0xA0);

        // Progress markers (single 0xAA byte each) so a crash pinpoints the step.
        int mDa = ensureString("C:\\Users\\user\\Desktop\\b\\zenith\\build\\d_a.bin");
        int mDb = ensureString("C:\\Users\\user\\Desktop\\b\\zenith\\build\\d_b.bin");
        int mDc = ensureString("C:\\Users\\user\\Desktop\\b\\zenith\\build\\d_c.bin");
        int mDd = ensureString("C:\\Users\\user\\Desktop\\b\\zenith\\build\\d_d.bin");

        auto writeMarkerD = [&](int pIdx) {
            emit8(0x48); emit8(0x8D); emit8(0x0D);
            heapFixups.push_back({code.size(), stringRVA + stringOffsets[pIdx]});
            emit32(0);
            emit8(0xBA); emit32(0x40000000);
            emit8(0x45); emit8(0x31); emit8(0xC0);
            emit8(0x45); emit8(0x31); emit8(0xC9);
            emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x20); emit32(2);
            emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x28); emit32(0x80);
            emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x30); emit32(0);
            emit8(0xFF); emit8(0x15);
            importCallFixups.push_back({code.size(), "CreateFileA", "kernel32.dll"});
            emit32(0);
            emit8(0x49); emit8(0x89); emit8(0xC4);
            emit8(0x49); emit8(0x83); emit8(0xFC); emit8(0xFF);
            int mF = newLabel();
            emitJcc("==", mF);
            emit8(0x4C); emit8(0x89); emit8(0xE1);
            emit8(0x48); emit8(0x8D); emit8(0x94); emit8(0x24); emit32(0x68);
            emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x68); emit32(0xAA);
            emit8(0x41); emit8(0xB8); emit32(1);
            emit8(0x4C); emit8(0x8D); emit8(0x4C); emit8(0x24); emit8(0x6C);
            emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x20); emit32(0);
            emit8(0xFF); emit8(0x15);
            importCallFixups.push_back({code.size(), "WriteFile", "kernel32.dll"});
            emit32(0);
            emit8(0x4C); emit8(0x89); emit8(0xE1);
            emit8(0xFF); emit8(0x15);
            importCallFixups.push_back({code.size(), "CloseHandle", "kernel32.dll"});
            emit32(0);
            emitLabel(mF);
        };

        // Zero init outputs so a skipped/absent Get still reports 0.
        emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x40); emit32(0);
        emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x48); emit32(0);
        emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x50); emit32(0);
        emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x58); emit32(0);

        // Guarded Get helper: if vtable slot is NULL, skip the call (output stays 0).
        auto guardedGet3 = [&](int slotOff, int outOff) {   // 3-arg Get: (this,&out,NULL)
            emit8(0x4C); emit8(0x8B); emit8(0x43); emit8(0x40);   // r8 = context
            emit8(0x4D); emit8(0x8B); emit8(0x00);                // r8 = vtable
            emit8(0x4D); emit8(0x8B); emit8(0x90); emit32((uint32_t)slotOff); // r10 = fn
            emit8(0x4D); emit8(0x85); emit8(0xD2);                // test r10, r10
            int gSkip = newLabel();
            emitJcc("==", gSkip);
            emit8(0x4C); emit8(0x8B); emit8(0x5B); emit8(0x40);   // r11 = context
            emit8(0x4C); emit8(0x89); emit8(0xD9);                // rcx = context
            emit8(0x48); emit8(0x8D); emit8(0x94); emit8(0x24); emit32((uint32_t)outOff); // rdx = &out
            emit8(0x45); emit8(0x33); emit8(0xC0);                // r8 = 0 (ppClassInstances)
            emit8(0x45); emit8(0x33); emit8(0xC9);                // r9 = 0
            emit8(0x41); emit8(0xFF); emit8(0xD2);                // call r10
            emitLabel(gSkip);
        };
        auto guardedGet2 = [&](int slotOff, int outOff) {   // 2-arg Get: (this,&out)
            emit8(0x4C); emit8(0x8B); emit8(0x43); emit8(0x40);   // r8 = context
            emit8(0x4D); emit8(0x8B); emit8(0x00);                // r8 = vtable
            emit8(0x4D); emit8(0x8B); emit8(0x90); emit32((uint32_t)slotOff); // r10 = fn
            emit8(0x4D); emit8(0x85); emit8(0xD2);                // test r10, r10
            int gSkip = newLabel();
            emitJcc("==", gSkip);
            emit8(0x4C); emit8(0x8B); emit8(0x5B); emit8(0x40);   // r11 = context
            emit8(0x4C); emit8(0x89); emit8(0xD9);                // rcx = context
            emit8(0x48); emit8(0x8D); emit8(0x94); emit8(0x24); emit32((uint32_t)outOff); // rdx = &out
            emit8(0x41); emit8(0xFF); emit8(0xD2);                // call r10
            emitLabel(gSkip);
        };

        // VSGetShader(76) -> off 0x260 : (ctx, &vs, NULL, NULL)
        writeMarkerD(mDa);
        guardedGet3(0x260, 0x40);

        // PSGetShader(74) -> off 0x250 : (ctx, &ps, NULL, NULL)
        writeMarkerD(mDb);
        guardedGet3(0x250, 0x48);

        // IAGetInputLayout(78) -> off 0x270 : (ctx, &layout)
        writeMarkerD(mDc);
        guardedGet2(0x270, 0x50);

        // IAGetPrimitiveTopology(83) -> off 0x298 : (ctx, &topo)
        writeMarkerD(mDd);
        guardedGet2(0x298, 0x58);

        // Copy 4 QWORDs -> buffer [rsp+0x70..0x8F]
        emit8(0x48); emit8(0x8B); emit8(0x44); emit8(0x24); emit8(0x40); emit8(0x48); emit8(0x89); emit8(0x84); emit8(0x24); emit32(0x70);
        emit8(0x48); emit8(0x8B); emit8(0x44); emit8(0x24); emit8(0x48); emit8(0x48); emit8(0x89); emit8(0x84); emit8(0x24); emit32(0x78);
        emit8(0x48); emit8(0x8B); emit8(0x44); emit8(0x24); emit8(0x50); emit8(0x48); emit8(0x89); emit8(0x84); emit8(0x24); emit32(0x80);
        emit8(0x48); emit8(0x8B); emit8(0x44); emit8(0x24); emit8(0x58); emit8(0x48); emit8(0x89); emit8(0x84); emit8(0x24); emit32(0x88);

        // Write file: CreateFile(path, WRITE,0,0,CREATE_ALWAYS,NORMAL,0)
        emit8(0x48); emit8(0x8D); emit8(0x0D);
        heapFixups.push_back({code.size(), stringRVA + stringOffsets[dumpPathIdx]});
        emit32(0);
        emit8(0xBA); emit32(0x40000000);
        emit8(0x45); emit8(0x31); emit8(0xC0);
        emit8(0x45); emit8(0x31); emit8(0xC9);
        emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x20); emit32(2);
        emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x28); emit32(0x80);
        emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x60); emit32(0);
        emit8(0xFF); emit8(0x15);
        importCallFixups.push_back({code.size(), "CreateFileA", "kernel32.dll"});
        emit32(0);
        emit8(0x49); emit8(0x89); emit8(0xC4);
        emit8(0x49); emit8(0x83); emit8(0xFC); emit8(0xFF);
        int sFailD = newLabel();
        emitJcc("==", sFailD);
        emit8(0x4C); emit8(0x89); emit8(0xE1);              // rcx = hFile
        emit8(0x48); emit8(0x8D); emit8(0x94); emit8(0x24); emit32(0x70); // rdx = &buffer
        emit8(0x41); emit8(0xB8); emit32(32);               // r8 = 32 bytes
        emit8(0x4C); emit8(0x8D); emit8(0x4C); emit8(0x24); emit8(0x60); // r9 = &written
        emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x20); emit32(0);
        emit8(0xFF); emit8(0x15);
        importCallFixups.push_back({code.size(), "WriteFile", "kernel32.dll"});
        emit32(0);
        emit8(0x4C); emit8(0x89); emit8(0xE1);              // rcx = hFile
        emit8(0xFF); emit8(0x15);
        importCallFixups.push_back({code.size(), "CloseHandle", "kernel32.dll"});
        emit32(0);
        emitLabel(sFailD);

        emit8(0x48); emit8(0x81); emit8(0xC4); emit32(0xA0);

        regsUsed = 1;
        emitMovRegImm(0, 0);
        resultReg = 0;
        return true;
    }

    // === dxGetVS() - TEMPORARY DIAGNOSTIC (kept) ===
    // Returns constant test value (no COM) to isolate whether crash is in
    // the COM call vs the builtin plumbing itself.
    if (call->name == "dxGetVS" && call->args.size() == 0) {
        int saved = regsUsed;
        spillRegs();
        regsUsed = 0;
        regsUsed = 1;
        emitMovRegImm(0, 123);
        resultReg = 0;
        return true;
    }

    return false;
}
