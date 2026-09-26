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
        if (bufReg != 0) { emitMovReg(0, bufReg); freeReg(bufReg); }
        else freeReg(0);
        if (dataReg != 0) { emitMovReg(1, dataReg); freeReg(dataReg); }
        else freeReg(1);

        emit8(0x48); emit8(0x8D); emit8(0x1D);
        heapFixups.push_back({code.size(), win32GlobalsRVA});
        emit32(0);

        // UpdateSubresource(context, buffer, 0, NULL, data, 0, 0) - vtable[48]
        emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x40);
        emit8(0x48); emit8(0x89); emit8(0x4C); emit8(0x24); emit8(0x20); // [rsp+0x20] = pSrcData
        emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x28); emit32(0); // SrcRowPitch
        emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x30); emit32(0); // SrcDepthPitch

        emit8(0x4C); emit8(0x8B); emit8(0x53); emit8(0x40); // r10 = context
        emit8(0x4D); emit8(0x8B); emit8(0x12);
        emit8(0x4D); emit8(0x8B); emit8(0x92); emit32(384); // [r10+384] = UpdateSubresource (48*8)
        emit8(0x4C); emit8(0x8B); emit8(0x5B); emit8(0x40); // r11 = context
        emit8(0x4C); emit8(0x89); emit8(0xD9);  // rcx = context
        emit8(0x48); emit8(0x89); emit8(0xC2);  // rdx = buffer
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
        // Store 1.0f on stack then load into xmm0
        emit8(0xC7); emit8(0x84); emit8(0x24); emit32(0x28); emit32(0x3F800000); // mov dword [rsp+0x28], 1.0f
        emit8(0xF3); emit8(0x0F); emit8(0x10); emit8(0x84); emit8(0x24); emit32(0x28); // movss xmm0, [rsp+0x28]
        emit8(0x45); emit8(0x33); emit8(0xC9);               // r9d = 0
        emit8(0xFF); emit8(0xD0);                             // call rax
        emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x20);

        emitLabel(skipClear);

        regsUsed = 1;
        emitMovRegImm(0, 0);
        resultReg = 0;
        return true;
    }

    return false;
}
