#include "codegen.h"
#include "ast.h"
#include "parser.h"
#include <iostream>
#include <cstring>
#include <algorithm>

using namespace std;

void Codegen::emitDX11Init() {
    // ========== DX11 Initialization ==========
    // After UpdateWindow: rbx = &globals, rsi = hwnd

    // --- D3D11CreateDeviceAndSwapChain ---
    // Stack frame: 0x120 bytes
    // [rsp+0x00..0x1F]: shadow (32)
    // [rsp+0x20..0x5F]: 8 params for D3D11CreateDeviceAndSwapChain (64)
    // [rsp+0x60..0x7F]: padding (32)
    // [rsp+0x80..0xBF]: DXGI_SWAP_CHAIN_DESC (64)
    // [rsp+0xC0]: swapChain ptr (8)
    // [rsp+0xC8]: device ptr (8)
    // [rsp+0xD0]: context ptr (8)
    // [rsp+0xD8]: featureLevel (4) + pad (4)
    // [rsp+0xE0..0x11F]: extra local space
    // [rsp+0x100..0x12F]: DS texture desc + DS view output
    // [rsp+0x130]: dsTexture, [rsp+0x138]: dsv
    // [rsp+0x140..0x154]: DS view desc
    emit8(0x48); emit8(0x81); emit8(0xEC); emit32(0x160);

    // Fill DXGI_SWAP_CHAIN_DESC at [rsp+0x80]
    emit8(0x8B); emit8(0x43); emit8(0x20);             // eax = width
    emit8(0x89); emit8(0x84); emit8(0x24); emit32(0x80); // Width
    emit8(0x8B); emit8(0x43); emit8(0x24);             // eax = height
    emit8(0x89); emit8(0x84); emit8(0x24); emit32(0x84); // Height
    // RefreshRate = {0,0}
    emit8(0xC7); emit8(0x84); emit8(0x24); emit32(0x88); emit32(0);
    emit8(0xC7); emit8(0x84); emit8(0x24); emit32(0x8C); emit32(0);
    // Format = DXGI_FORMAT_R8G8B8A8_UNORM (28)
    emit8(0xC7); emit8(0x84); emit8(0x24); emit32(0x90); emit32(28);
    // ScanlineOrdering = 0, Scaling = 0
    emit8(0xC7); emit8(0x84); emit8(0x24); emit32(0x94); emit32(0);
    emit8(0xC7); emit8(0x84); emit8(0x24); emit32(0x98); emit32(0);
    // SampleDesc = {1, 0}
    emit8(0xC7); emit8(0x84); emit8(0x24); emit32(0x9C); emit32(1);
    emit8(0xC7); emit8(0x84); emit8(0x24); emit32(0xA0); emit32(0);
    // BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT (0x20)
    emit8(0xC7); emit8(0x84); emit8(0x24); emit32(0xA4); emit32(0x20);
    // BufferCount = 1
    emit8(0xC7); emit8(0x84); emit8(0x24); emit32(0xA8); emit32(1);
    // Padding 4 bytes
    emit8(0xC7); emit8(0x84); emit8(0x24); emit32(0xAC); emit32(0);
    // OutputWindow = hwnd (from globals+8)
    emit8(0x48); emit8(0x8B); emit8(0x43); emit8(0x08); // rax = [rbx+8] = hwnd
    emit8(0x48); emit8(0x89); emit8(0x84); emit8(0x24); emit32(0xB0);
    // Windowed = TRUE (1)
    emit8(0xC7); emit8(0x84); emit8(0x24); emit32(0xB8); emit32(1);
    // SwapEffect = DXGI_SWAP_EFFECT_DISCARD (0)
    emit8(0xC7); emit8(0x84); emit8(0x24); emit32(0xBC); emit32(0);
    // Flags = 0
    emit8(0xC7); emit8(0x84); emit8(0x24); emit32(0xC0); emit32(0);
    // Padding
    emit8(0xC7); emit8(0x84); emit8(0x24); emit32(0xC4); emit32(0);

    // Set up call parameters
    // [rsp+0xF0] = D3D_FEATURE_LEVEL_11_0 (0xB000) - force FL 11_0 to avoid
    // the NVIDIA driver's convolution path that crashes with our layout
    emit8(0xC7); emit8(0x84); emit8(0x24); emit32(0xF0); emit32(0xB000);
    // [rsp+0x20] = pFeatureLevels = &level
    emit8(0x48); emit8(0x8D); emit8(0x84); emit8(0x24); emit32(0xF0);
    emit8(0x48); emit8(0x89); emit8(0x44); emit8(0x24); emit8(0x20);
    // [rsp+0x28] = FeatureLevels = 1
    emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x28); emit32(1);
    // [rsp+0x30] = SDKVersion = D3D11_SDK_VERSION (7)
    emit8(0x48); emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x30); emit32(7);
    // [rsp+0x38] = &SWAP_CHAIN_DESC
    emit8(0x48); emit8(0x8D); emit8(0x84); emit8(0x24); emit32(0x80);
    emit8(0x48); emit8(0x89); emit8(0x44); emit8(0x24); emit8(0x38);
    // [rsp+0x40] = &swapChain
    emit8(0x48); emit8(0x8D); emit8(0x84); emit8(0x24); emit32(0xC0);
    emit8(0x48); emit8(0x89); emit8(0x44); emit8(0x24); emit8(0x40);
    // [rsp+0x48] = &device
    emit8(0x48); emit8(0x8D); emit8(0x84); emit8(0x24); emit32(0xC8);
    emit8(0x48); emit8(0x89); emit8(0x44); emit8(0x24); emit8(0x48);
    // [rsp+0x50] = &featureLevel
    emit8(0x48); emit8(0x8D); emit8(0x84); emit8(0x24); emit32(0xD8);
    emit8(0x48); emit8(0x89); emit8(0x44); emit8(0x24); emit8(0x50);
    // [rsp+0x58] = &context
    emit8(0x48); emit8(0x8D); emit8(0x84); emit8(0x24); emit32(0xD0);
    emit8(0x48); emit8(0x89); emit8(0x44); emit8(0x24); emit8(0x58);

    // rcx = NULL (pAdapter)
    emit8(0x33); emit8(0xC9);                            // xor ecx, ecx
    // edx = D3D_DRIVER_TYPE_HARDWARE (1)
    emit8(0xBA); emit32(1);
    // r8 = NULL (Software)
    emit8(0x45); emit8(0x33); emit8(0xC0);               // xor r8d, r8d
    // r9 = 0 (Flags)
    emit8(0x45); emit8(0x33); emit8(0xC9);               // xor r9d, r9d

    emit8(0xFF); emit8(0x15);
    importCallFixups.push_back({code.size(), "D3D11CreateDeviceAndSwapChain", "d3d11.dll"});
    emit32(0);

    // Check HRESULT, skip DX11 init if failed
    int dx11Failed = newLabel();
    emit8(0x85); emit8(0xC0);  // test eax, eax
    emitJcc("<", dx11Failed);  // jl = jump if sign (FAILED)

    // Store device, context, swapChain in globals
    // [globals+56] = device
    emit8(0x48); emit8(0x8B); emit8(0x84); emit8(0x24); emit32(0xC8); // rax = device
    emit8(0x48); emit8(0x89); emit8(0x43); emit8(0x38);              // [rbx+56] = device
    // [globals+64] = context
    emit8(0x48); emit8(0x8B); emit8(0x84); emit8(0x24); emit32(0xD0); // rax = context
    emit8(0x48); emit8(0x89); emit8(0x43); emit8(0x40);              // [rbx+64] = context
    // [globals+72] = swapChain
    emit8(0x48); emit8(0x8B); emit8(0x84); emit8(0x24); emit32(0xC0); // rax = swapChain
    emit8(0x48); emit8(0x89); emit8(0x43); emit8(0x48);              // [rbx+72] = swapChain

    // --- IDXGISwapChain::GetBuffer(swapChain, 0, &IID_ID3D11Texture2D, &backBuffer) ---
    // IID_ID3D11Texture2D = {6F15AAF2-D208-4E89-9AB4-489535D34F9C}
    int iidIdx = -1;
    {
        std::string iidBytes(16, '\0');
        iidBytes[0] = '\xF2'; iidBytes[1] = '\xAA'; iidBytes[2] = '\x15'; iidBytes[3] = '\x6F';
        iidBytes[4] = '\x08'; iidBytes[5] = '\xD2'; iidBytes[6] = '\x89'; iidBytes[7] = '\x4E';
        iidBytes[8] = '\x9A'; iidBytes[9] = '\xB4'; iidBytes[10] = '\x48'; iidBytes[11] = '\x95';
        iidBytes[12] = '\x35'; iidBytes[13] = '\xD3'; iidBytes[14] = '\x4F'; iidBytes[15] = '\x9C';
        for (size_t i = 0; i < stringPool.size(); i++) {
            if (stringPool[i] == iidBytes) { iidIdx = (int)i; break; }
        }
        if (iidIdx < 0) {
            iidIdx = (int)stringPool.size();
            stringPool.push_back(iidBytes);
        }
    }

    // COM call: swapChain->vtable[9](swapChain, 0, &IID, &backBuffer)
    // [rsp+0x80] will store backBuffer
    // Load swapChain from globals+72
    emit8(0x48); emit8(0x8B); emit8(0x43); emit8(0x48);  // rax = [rbx+72] = swapChain
    emit8(0x48); emit8(0x8B); emit8(0x00);                // rax = [rax] = vtable
    emit8(0x48); emit8(0x8B); emit8(0x40); emit8(0x48);  // rax = [rax+72] = GetBuffer fn
    emit8(0x48); emit8(0x8B); emit8(0x4B); emit8(0x48);  // rcx = [rbx+72] = swapChain (this)
    emit8(0x33); emit8(0xD2);                             // rdx = 0 (buffer index)
    emit8(0x45); emit8(0x33); emit8(0xC0);               // r8d = 0
    // lea r8, [rip+IID] or use heap fixup
    emit8(0x4C); emit8(0x8D); emit8(0x05);
    heapFixups.push_back({code.size(), stringRVA + stringOffsets[iidIdx]});
    emit32(0);
    // r9 = &backBuffer at [rsp+0x80]
    emit8(0x4C); emit8(0x8D); emit8(0x8C); emit8(0x24); emit32(0x80);
    emit8(0xFF); emit8(0xD0);                             // call rax
    // backBuffer is now at [rsp+0x80]

    // --- ID3D11Device::CreateRenderTargetView(device, backBuffer, NULL, &rtv) ---
    // [rsp+0x88] will store rtv
    emit8(0x48); emit8(0x8B); emit8(0x43); emit8(0x38);  // rax = [rbx+56] = device
    emit8(0x48); emit8(0x8B); emit8(0x00);                // rax = vtable
    emit8(0x48); emit8(0x8B); emit8(0x40); emit8(0x48);  // rax = [rax+72] = CreateRenderTargetView fn
    emit8(0x48); emit8(0x8B); emit8(0x4B); emit8(0x38);  // rcx = device (this)
    emit8(0x48); emit8(0x8B); emit8(0x94); emit8(0x24); emit32(0x80); // rdx = backBuffer
    emit8(0x45); emit8(0x33); emit8(0xC0);               // r8d = 0 (pDesc = NULL)
    emit8(0x4C); emit8(0x8D); emit8(0x8C); emit8(0x24); emit32(0x88); // r9 = &rtv
    emit8(0xFF); emit8(0xD0);                             // call rax
    // rtv is now at [rsp+0x88]
    // Store rtv in globals+80 for cleanup
    emit8(0x48); emit8(0x8B); emit8(0x84); emit8(0x24); emit32(0x88); // rax = [rsp+0x88]
    emit8(0x48); emit8(0x89); emit8(0x43); emit8(0x50);               // [rbx+80] = rtv

    // --- Create depth-stencil texture ---
    // D3D11_TEXTURE2D_DESC at [rsp+0x100] (48 bytes)
    emit8(0x8B); emit8(0x43); emit8(0x20);             // eax = width
    emit8(0x89); emit8(0x84); emit8(0x24); emit32(0x100); // Width
    emit8(0x8B); emit8(0x43); emit8(0x24);             // eax = height
    emit8(0x89); emit8(0x84); emit8(0x24); emit32(0x104); // Height
    emit8(0xC7); emit8(0x84); emit8(0x24); emit32(0x108); emit32(1);  // MipLevels = 1
    emit8(0xC7); emit8(0x84); emit8(0x24); emit32(0x10C); emit32(1);  // ArraySize = 1
    emit8(0xC7); emit8(0x84); emit8(0x24); emit32(0x110); emit32(3); // Format = DXGI_FORMAT_D16_UNORM (3) - D32/D24 rejected by this AMD driver (E_INVALIDARG)
    emit8(0xC7); emit8(0x84); emit8(0x24); emit32(0x114); emit32(1);  // SampleDesc.Count = 1
    emit8(0xC7); emit8(0x84); emit8(0x24); emit32(0x118); emit32(0);  // SampleDesc.Quality = 0
    emit8(0xC7); emit8(0x84); emit8(0x24); emit32(0x11C); emit32(0);  // Usage = D3D11_USAGE_DEFAULT
    emit8(0xC7); emit8(0x84); emit8(0x24); emit32(0x120); emit32(0x20);// BindFlags = D3D11_BIND_DEPTH_STENCIL (0x20)
    emit8(0xC7); emit8(0x84); emit8(0x24); emit32(0x124); emit32(0);  // CPUAccessFlags = 0
    emit8(0xC7); emit8(0x84); emit8(0x24); emit32(0x128); emit32(0);  // MiscFlags = 0

    // device->CreateTexture2D(device, &dsDesc, NULL, &dsTexture) - vtable[5]
    emit8(0x48); emit8(0x8B); emit8(0x43); emit8(0x38);  // rax = device
    emit8(0x48); emit8(0x8B); emit8(0x00);                // rax = vtable
    emit8(0x48); emit8(0x8B); emit8(0x40); emit8(0x28);  // rax = [rax+40] = CreateTexture2D
    emit8(0x48); emit8(0x8B); emit8(0x4B); emit8(0x38);  // rcx = device
    emit8(0x48); emit8(0x8D); emit8(0x94); emit8(0x24); emit32(0x100); // rdx = &dsDesc
    emit8(0x45); emit8(0x33); emit8(0xC0);               // r8d = 0
    emit8(0x4C); emit8(0x8D); emit8(0x8C); emit8(0x24); emit32(0x130); // r9 = &dsTexture [rsp+0x130]
    emit8(0xFF); emit8(0xD0);                             // call rax

    // Store dsTexture in globals+100
    emit8(0x48); emit8(0x8B); emit8(0x84); emit8(0x24); emit32(0x130);
    emit8(0x48); emit8(0x89); emit8(0x43); emit8(0x64);  // [rbx+100] = dsTexture

    // --- Create depth-stencil view ---
    // D3D11_DEPTH_STENCIL_VIEW_DESC at [rsp+0x140] (20 bytes)
    emit8(0xC7); emit8(0x84); emit8(0x24); emit32(0x140); emit32(3); // Format = DXGI_FORMAT_D16_UNORM (3) - must match D16 depth texture
    emit8(0xC7); emit8(0x84); emit8(0x24); emit32(0x144); emit32(0);  // ViewDimension = D3D11_DSV_DIMENSION_TEXTURE2D
    emit8(0xC7); emit8(0x84); emit8(0x24); emit32(0x148); emit32(0);  // Flags = 0
    emit8(0xC7); emit8(0x84); emit8(0x24); emit32(0x14C); emit32(0);  // Texture2D.MipSlice = 0
    emit8(0xC7); emit8(0x84); emit8(0x24); emit32(0x150); emit32(0);  // pad

    // device->CreateDepthStencilView(device, dsTexture, &dsDesc2, &dsv) - vtable[10] (offset 0x50)
    emit8(0x48); emit8(0x8B); emit8(0x43); emit8(0x38);  // rax = device
    emit8(0x48); emit8(0x8B); emit8(0x00);                // rax = vtable
    emit8(0x48); emit8(0x8B); emit8(0x40); emit8(0x50);   // rax = [rax+0x50] = CreateDepthStencilView (10*8)
    emit8(0x48); emit8(0x8B); emit8(0x4B); emit8(0x38);  // rcx = device
    emit8(0x48); emit8(0x8B); emit8(0x94); emit8(0x24); emit32(0x130); // rdx = dsTexture
    emit8(0x4C); emit8(0x8D); emit8(0x84); emit8(0x24); emit32(0x140); // r8 = &dsViewDesc
    emit8(0x4C); emit8(0x8D); emit8(0x8C); emit8(0x24); emit32(0x138); // r9 = &dsv [rsp+0x138]
    emit8(0xFF); emit8(0xD0);                             // call rax

    // Store dsv in globals+108
    emit8(0x48); emit8(0x8B); emit8(0x84); emit8(0x24); emit32(0x138);
    emit8(0x48); emit8(0x89); emit8(0x43); emit8(0x6C);  // [rbx+108] = dsv

    // --- Release backBuffer ---
    // backBuffer->vtable[2](backBuffer) = Release
    emit8(0x48); emit8(0x8B); emit8(0x84); emit8(0x24); emit32(0x80); // rax = backBuffer
    emit8(0x48); emit8(0x85); emit8(0xC0);                          // test rax, rax
    int skipReleaseBB = newLabel();
    emit8(0x74); emit8(0x11);                                       // jz skipReleaseBB
    emit8(0x48); emit8(0x8B); emit8(0x00);                          // rax = vtable
    emit8(0x48); emit8(0x8B); emit8(0x40); emit8(0x10);            // rax = Release
    emit8(0x48); emit8(0x8B); emit8(0x8C); emit8(0x24); emit32(0x80); // rcx = backBuffer
    emit8(0xFF); emit8(0xD0);                                       // call rax
    emitLabel(skipReleaseBB);

    // --- ID3D11DeviceContext::OMSetRenderTargets(context, 1, &rtv, dsv) ---
    emit8(0x48); emit8(0x8B); emit8(0x43); emit8(0x40);  // rax = [rbx+64] = context
    emit8(0x48); emit8(0x8B); emit8(0x00);                // rax = vtable
    emit8(0x48); emit8(0x8B); emit8(0x80); emit32(0x108); // rax = [rax+264] = OMSetRenderTargets
    emit8(0x48); emit8(0x8B); emit8(0x4B); emit8(0x40);  // rcx = context (this)
    emit8(0xBA); emit32(1);                               // rdx = 1 (NumViews)
    emit8(0x4C); emit8(0x8D); emit8(0x84); emit8(0x24); emit32(0x88); // r8 = &rtv
    emit8(0x4C); emit8(0x8B); emit8(0x8C); emit8(0x24); emit32(0x138); // r9 = dsv (from CreateDepthStencilView output)
    emit8(0xFF); emit8(0xD0);                             // call rax

    // --- ID3D11DeviceContext::ClearRenderTargetView(context, rtv, {0,0,0,1}) ---
    // vtable index 50 (offset 0x190), verified via runtime probe (RTV cleared to red)
    // color array at [rsp+0xD0] (16 bytes, overwritten later by D3D11_MAPPED_SUBRESOURCE)
    emit8(0xC7); emit8(0x84); emit8(0x24); emit32(0xD0); emit32(0);        // [rsp+0xD0] = 0.0f R
    emit8(0xC7); emit8(0x84); emit8(0x24); emit32(0xD4); emit32(0);        // [rsp+0xD4] = 0.0f G
    emit8(0xC7); emit8(0x84); emit8(0x24); emit32(0xD8); emit32(0);        // [rsp+0xD8] = 0.0f B
    emit8(0xC7); emit8(0x84); emit8(0x24); emit32(0xDC); emit32(0x3F800000); // [rsp+0xDC] = 1.0f A
    emit8(0x48); emit8(0x8B); emit8(0x43); emit8(0x40);  // rax = [rbx+64] = context
    emit8(0x48); emit8(0x8B); emit8(0x00);                // rax = vtable
    emit8(0x48); emit8(0x8B); emit8(0x80); emit32(0x190); // rax = [rax+400] = ClearRenderTargetView
    emit8(0x48); emit8(0x8B); emit8(0x4B); emit8(0x40);  // rcx = context (this)
    emit8(0x48); emit8(0x8B); emit8(0x94); emit8(0x24); emit32(0x88); // rdx = rtv
    emit8(0x4C); emit8(0x8D); emit8(0x84); emit8(0x24); emit32(0xD0); // r8 = &color
    emit8(0xFF); emit8(0xD0);                             // call rax

    // --- ID3D11DeviceContext::ClearDepthStencilView(context, dsv, D3D11_CLEAR_DEPTH, 1.0, 0) ---
    // vtable index 53 (offset 0x1A8)
    emit8(0x48); emit8(0x8B); emit8(0x43); emit8(0x6C);  // rax = [rbx+108] = dsv
    emit8(0x48); emit8(0x85); emit8(0xC0);               // test rax, rax
    int skipClearDS = newLabel();
    emitJcc("==", skipClearDS);
    emit8(0x48); emit8(0x8B); emit8(0x43); emit8(0x40);  // rax = [rbx+64] = context
    emit8(0x48); emit8(0x8B); emit8(0x00);                // rax = vtable
    emit8(0x48); emit8(0x8B); emit8(0x80); emit32(0x1A8); // rax = [rax+0x1A8] = ClearDepthStencilView (53*8)
    emit8(0x48); emit8(0x8B); emit8(0x4B); emit8(0x40);  // rcx = context
    emit8(0x48); emit8(0x8B); emit8(0x53); emit8(0x6C);  // rdx = dsv
    emit8(0x41); emit8(0xB8); emit32(1);                  // r8d = D3D11_CLEAR_DEPTH (1)
    // Store 1.0f on stack then load into xmm0
    emit8(0xC7); emit8(0x84); emit8(0x24); emit32(0xD0); emit32(0x3F800000); // mov dword [rsp+0xD0], 1.0f
    emit8(0xF3); emit8(0x0F); emit8(0x10); emit8(0x84); emit8(0x24); emit32(0xD0); // movss xmm0, [rsp+0xD0]
    emit8(0x45); emit8(0x33); emit8(0xC9);               // r9d = 0 (Stencil = 0)
    emit8(0xFF); emit8(0xD0);                             // call rax
    emitLabel(skipClearDS);

    // --- ID3D11DeviceContext::RSSetViewports(context, 1, &viewport) ---
    // Without a bound viewport D3D11 clips all geometry (GPU draws render nothing).
    // D3D11_VIEWPORT at [rsp+0xE8] (24 bytes): TopLeftX, TopLeftY, Width, Height, MinDepth, MaxDepth
    emit8(0xC7); emit8(0x84); emit8(0x24); emit32(0xE8); emit32(0);        // TopLeftX = 0
    emit8(0xC7); emit8(0x84); emit8(0x24); emit32(0xEC); emit32(0);        // TopLeftY = 0
    emit8(0xF3); emit8(0x0F); emit8(0x2A); emit8(0x43); emit8(0x20);      // cvtsi2ss xmm0, [rbx+32] = width
    emit8(0xF3); emit8(0x0F); emit8(0x11); emit8(0x84); emit8(0x24); emit32(0xF0); // movss [rsp+0xF0], xmm0
    emit8(0xF3); emit8(0x0F); emit8(0x2A); emit8(0x43); emit8(0x24);      // cvtsi2ss xmm0, [rbx+36] = height
    emit8(0xF3); emit8(0x0F); emit8(0x11); emit8(0x84); emit8(0x24); emit32(0xF4); // movss [rsp+0xF4], xmm0
    emit8(0xC7); emit8(0x84); emit8(0x24); emit32(0xF8); emit32(0);        // MinDepth = 0
    emit8(0xC7); emit8(0x84); emit8(0x24); emit32(0xFC); emit32(0x3F800000); // MaxDepth = 1
    emit8(0x48); emit8(0x8B); emit8(0x43); emit8(0x40);  // rax = [rbx+64] = context
    emit8(0x48); emit8(0x8B); emit8(0x00);                // rax = vtable
    emit8(0x48); emit8(0x8B); emit8(0x80); emit32(0x160); // rax = [rax+352] = RSSetViewports
    emit8(0x48); emit8(0x8B); emit8(0x4B); emit8(0x40);  // rcx = context (this)
    emit8(0xBA); emit32(1);                               // rdx = 1 (NumViewports)
    emit8(0x4C); emit8(0x8D); emit8(0x84); emit8(0x24); emit32(0xE8); // r8 = &viewport
    emit8(0xFF); emit8(0xD0);                             // call rax

    // --- Create staging texture ---
    // D3D11_TEXTURE2D_DESC at [rsp+0x90] (48 bytes)
    emit8(0x8B); emit8(0x43); emit8(0x20);             // eax = width
    emit8(0x89); emit8(0x84); emit8(0x24); emit32(0x90); // Width
    emit8(0x8B); emit8(0x43); emit8(0x24);             // eax = height
    emit8(0x89); emit8(0x84); emit8(0x24); emit32(0x94); // Height
    emit8(0xC7); emit8(0x84); emit8(0x24); emit32(0x98); emit32(1);  // MipLevels = 1
    emit8(0xC7); emit8(0x84); emit8(0x24); emit32(0x9C); emit32(1);  // ArraySize = 1
    emit8(0xC7); emit8(0x84); emit8(0x24); emit32(0xA0); emit32(28); // Format = R8G8B8A8_UNORM
    emit8(0xC7); emit8(0x84); emit8(0x24); emit32(0xA4); emit32(1);  // SampleDesc.Count = 1
    emit8(0xC7); emit8(0x84); emit8(0x24); emit32(0xA8); emit32(0);  // SampleDesc.Quality = 0
    emit8(0xC7); emit8(0x84); emit8(0x24); emit32(0xAC); emit32(3);  // Usage = D3D11_USAGE_STAGING
    emit8(0xC7); emit8(0x84); emit8(0x24); emit32(0xB0); emit32(0);  // BindFlags = 0
    emit8(0xC7); emit8(0x84); emit8(0x24); emit32(0xB4); emit32(0x10000); // CPUAccessFlags = D3D11_CPU_ACCESS_WRITE
    emit8(0xC7); emit8(0x84); emit8(0x24); emit32(0xB8); emit32(0);  // MiscFlags = 0

    // ID3D11Device::CreateTexture2D(device, &desc, NULL, &stagingTexture)
    // stagingTexture at [rsp+0xC0]
    emit8(0x48); emit8(0x8B); emit8(0x43); emit8(0x38);  // rax = device
    emit8(0x48); emit8(0x8B); emit8(0x00);                // rax = vtable
    emit8(0x48); emit8(0x8B); emit8(0x40); emit8(0x28);  // rax = [rax+40] = CreateTexture2D
    emit8(0x48); emit8(0x8B); emit8(0x4B); emit8(0x38);  // rcx = device (this)
    emit8(0x48); emit8(0x8D); emit8(0x94); emit8(0x24); emit32(0x90); // rdx = &desc
    emit8(0x45); emit8(0x33); emit8(0xC0);               // r8d = 0 (pInitialData)
    emit8(0x4C); emit8(0x8D); emit8(0x8C); emit8(0x24); emit32(0xC0); // r9 = &stagingTexture
    emit8(0xFF); emit8(0xD0);                             // call rax
    // stagingTexture at [rsp+0xC0]

    // Store stagingTexture in globals+88
    emit8(0x48); emit8(0x8B); emit8(0x84); emit8(0x24); emit32(0xC0); // rax = [rsp+0xC0]
    emit8(0x48); emit8(0x89); emit8(0x43); emit8(0x58);  // [rbx+88] = stagingTexture

    // --- Map staging texture ---
    // ID3D11DeviceContext::Map(context, stagingTexture, 0, D3D11_MAP_WRITE, 0, &mapped)
    // D3D11_MAPPED_SUBRESOURCE at [rsp+0xD0] (24 bytes: pData(8), RowPitch(4), DepthPitch(4), pad(8))
    // Compute &mapped and store as 6th param BEFORE loading Map fn into rax
    emit8(0x48); emit8(0x8D); emit8(0x84); emit8(0x24); emit32(0xD0); // rax = &mapped
    emit8(0x48); emit8(0x89); emit8(0x44); emit8(0x24); emit8(0x28); // [rsp+0x28] = &mapped
    // Load Map fn via vtable
    emit8(0x48); emit8(0x8B); emit8(0x43); emit8(0x40);  // rax = context
    emit8(0x48); emit8(0x8B); emit8(0x00);                // rax = vtable
    emit8(0x48); emit8(0x8B); emit8(0x40); emit8(0x70);  // rax = [rax+112] = Map fn
    // Set up parameters
    emit8(0x48); emit8(0x8B); emit8(0x4B); emit8(0x40);  // rcx = context (this)
    emit8(0x48); emit8(0x8B); emit8(0x53); emit8(0x58);  // rdx = [rbx+88] stagingTexture
    emit8(0x45); emit8(0x33); emit8(0xC0);               // r8d = 0 (Subresource)
    emit8(0x41); emit8(0xB9); emit32(2);                  // r9d = D3D11_MAP_WRITE (2)
    emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x20); emit32(0); // [rsp+0x20] = MapFlags = 0
    emit8(0xFF); emit8(0xD0);                             // call rax

    // Store mapped.pData in globals+40 (framebuffer pointer)
    emit8(0x48); emit8(0x8B); emit8(0x84); emit8(0x24); emit32(0xD0); // rax = mapped.pData
    emit8(0x48); emit8(0x89); emit8(0x43); emit8(0x28);  // [rbx+40] = framebuf

    // --- Create rasterizer state with CullMode=NONE ---
    // D3D11's default rasterizer uses CullMode=BACK, which culls
    // back-facing triangles (counter-clockwise in screen space with
    // FrontCounterClockwise=FALSE). User geometry has arbitrary
    // winding, so disable culling to ensure draws always render.
    // D3D11_RASTERIZER_DESC at [rsp+0xE0] (40 bytes)
    emit8(0xC7); emit8(0x84); emit8(0x24); emit32(0xE0); emit32(3);     // FillMode = D3D11_FILL_SOLID (3)
    emit8(0xC7); emit8(0x84); emit8(0x24); emit32(0xE4); emit32(1);     // CullMode = D3D11_CULL_NONE (1)
    emit8(0xC7); emit8(0x84); emit8(0x24); emit32(0xE8); emit32(0);     // FrontCounterClockwise = FALSE
    emit8(0xC7); emit8(0x84); emit8(0x24); emit32(0xEC); emit32(0);     // DepthBias = 0
    emit8(0xC7); emit8(0x84); emit8(0x24); emit32(0xF0); emit32(0);     // DepthBiasClamp = 0.0f
    emit8(0xC7); emit8(0x84); emit8(0x24); emit32(0xF4); emit32(0);     // SlopeScaledDepthBias = 0.0f
    emit8(0xC7); emit8(0x84); emit8(0x24); emit32(0xF8); emit32(1);     // DepthClipEnable = TRUE
    emit8(0xC7); emit8(0x84); emit8(0x24); emit32(0xFC); emit32(0);     // ScissorEnable = FALSE
    emit8(0xC7); emit8(0x84); emit8(0x24); emit32(0x100); emit32(0);    // MultisampleEnable = FALSE
    emit8(0xC7); emit8(0x84); emit8(0x24); emit32(0x104); emit32(0);    // AntialiasedLineEnable = FALSE

    // device->CreateRasterizerState(device, &desc, &rs) - vtable[22]
    emit8(0x48); emit8(0x8B); emit8(0x43); emit8(0x38);  // rax = [rbx+56] = device
    emit8(0x48); emit8(0x8B); emit8(0x00);                // rax = vtable
    emit8(0x48); emit8(0x8B); emit8(0x80); emit32(0xB0);  // rax = [rax+176] = CreateRasterizerState
    emit8(0x48); emit8(0x8B); emit8(0x4B); emit8(0x38);  // rcx = device (this)
    emit8(0x48); emit8(0x8D); emit8(0x94); emit8(0x24); emit32(0xE0);  // rdx = &desc
    emit8(0x4C); emit8(0x8D); emit8(0x84); emit8(0x24); emit32(0x108); // r8 = &rs
    emit8(0xFF); emit8(0xD0);                             // call rax
    // rs at [rsp+0x108]; kept alive for program lifetime (D3D11 setters
    // do not retain a reference, so do not release here).

    // context->RSSetState(context, rs) - vtable[43]
    emit8(0x48); emit8(0x8B); emit8(0x43); emit8(0x40);   // rax = [rbx+64] = context
    emit8(0x48); emit8(0x8B); emit8(0x00);                // rax = vtable
    emit8(0x48); emit8(0x8B); emit8(0x80); emit32(0x158); // rax = [rax+344] = RSSetState
    emit8(0x48); emit8(0x8B); emit8(0x4B); emit8(0x40);   // rcx = context (this)
    emit8(0x48); emit8(0x8B); emit8(0x94); emit8(0x24); emit32(0x108); // rdx = rs
    emit8(0xFF); emit8(0xD0);                             // call rax

    // Jump over error handler
    int dx11Done = newLabel();
    emitJmp(dx11Done);
    emitLabel(dx11Failed);

    // D3D11CreateDeviceAndSwapChain failed - zero out COM pointers and framebuf
    emit8(0x48); emit8(0xC7); emit8(0x43); emit8(0x38); emit32(0);  // [rbx+56] = device = 0
    emit8(0x48); emit8(0xC7); emit8(0x43); emit8(0x40); emit32(0);  // [rbx+64] = context = 0
    emit8(0x48); emit8(0xC7); emit8(0x43); emit8(0x48); emit32(0);  // [rbx+72] = swapChain = 0
    emit8(0x48); emit8(0xC7); emit8(0x43); emit8(0x50); emit32(0);  // [rbx+80] = rtv = 0
    emit8(0x48); emit8(0xC7); emit8(0x43); emit8(0x58); emit32(0);  // [rbx+88] = stagingTexture = 0
    emit8(0x48); emit8(0xC7); emit8(0x43); emit8(0x28); emit32(0);  // [rbx+40] = framebuf = 0
    emit8(0x48); emit8(0xC7); emit8(0x43); emit8(0x64); emit32(0);  // [rbx+100] = dsTexture = 0
    emit8(0x48); emit8(0xC7); emit8(0x43); emit8(0x6C); emit32(0);  // [rbx+108] = dsv = 0

    emitLabel(dx11Done);

    // Restore stack
    emit8(0x48); emit8(0x81); emit8(0xC4); emit32(0x160);
}

void Codegen::emitDX11Present() {
    // ========== DX11 Present ==========
    // Stack: 0x80 bytes
    // [rsp+0x00..0x1F]: shadow
    // [rsp+0x38]: backBuffer ptr (local)
    // [rsp+0x40]: rtv ptr (local)
    // [rsp+0x50..0x67]: D3D11_MAPPED_SUBRESOURCE
    emit8(0x48); emit8(0x81); emit8(0xEC); emit32(0x80);

    // --- Unmap staging texture ---
    // context->vtable[13](context, stagingTexture, 0)
    emit8(0x48); emit8(0x8B); emit8(0x43); emit8(0x40);  // rax = context
    emit8(0x48); emit8(0x8B); emit8(0x00);                // rax = vtable
    emit8(0x48); emit8(0x8B); emit8(0x40); emit8(0x78);  // rax = [rax+120] = Unmap
    emit8(0x48); emit8(0x8B); emit8(0x4B); emit8(0x40);  // rcx = context (this)
    emit8(0x48); emit8(0x8B); emit8(0x53); emit8(0x58);  // rdx = [rbx+88] = stagingTexture
    emit8(0x45); emit8(0x33); emit8(0xC0);               // r8d = 0 (Subresource)
    emit8(0xFF); emit8(0xD0);                             // call rax

    // --- GetBuffer to get current back buffer ---
    // swapChain->vtable[9](swapChain, 0, &IID, &backBuffer)
    // backBuffer at [rsp+0x38]
    emit8(0x48); emit8(0x8B); emit8(0x43); emit8(0x48);  // rax = swapChain
    emit8(0x48); emit8(0x8B); emit8(0x00);                // rax = vtable
    emit8(0x48); emit8(0x8B); emit8(0x40); emit8(0x48);  // rax = [rax+72] = GetBuffer
    emit8(0x48); emit8(0x8B); emit8(0x4B); emit8(0x48);  // rcx = swapChain (this)
    emit8(0x33); emit8(0xD2);                             // rdx = 0 (buffer index)
    emit8(0x45); emit8(0x33); emit8(0xC0);               // r8d = 0
    // lea r8, [IID_ID3D11Texture2D]
    emit8(0x4C); emit8(0x8D); emit8(0x05);
    {
        // Find the IID string we added in createWindow
        std::string iidBytes(16, '\0');
        iidBytes[0] = '\xF2'; iidBytes[1] = '\xAA'; iidBytes[2] = '\x15'; iidBytes[3] = '\x6F';
        iidBytes[4] = '\x08'; iidBytes[5] = '\xD2'; iidBytes[6] = '\x89'; iidBytes[7] = '\x4E';
        iidBytes[8] = '\x9A'; iidBytes[9] = '\xB4'; iidBytes[10] = '\x48'; iidBytes[11] = '\x95';
        iidBytes[12] = '\x35'; iidBytes[13] = '\xD3'; iidBytes[14] = '\x4F'; iidBytes[15] = '\x9C';
        int iidIdx = -1;
        for (size_t i = 0; i < stringPool.size(); i++) {
            if (stringPool[i] == iidBytes) { iidIdx = (int)i; break; }
        }
        if (iidIdx < 0) {
            iidIdx = (int)stringPool.size();
            stringPool.push_back(iidBytes);
        }
        heapFixups.push_back({code.size(), stringRVA + stringOffsets[iidIdx]});
    }
    emit32(0);
    // r9 = &backBuffer
    emit8(0x4C); emit8(0x8D); emit8(0x4C); emit8(0x24); emit8(0x38);
    emit8(0xFF); emit8(0xD0);                             // call rax

    // --- CopyResource(context, backBuffer, stagingTexture) ---
    // context->vtable[47](context, backBuffer, stagingTexture)
    emit8(0x48); emit8(0x8B); emit8(0x43); emit8(0x40);  // rax = context
    emit8(0x48); emit8(0x8B); emit8(0x00);                // rax = vtable
    emit8(0x48); emit8(0x8B); emit8(0x80); emit32(0x178); // rax = [rax+376] = CopyResource
    emit8(0x48); emit8(0x8B); emit8(0x4B); emit8(0x40);  // rcx = context (this)
    emit8(0x48); emit8(0x8B); emit8(0x54); emit8(0x24); emit8(0x38); // rdx = backBuffer
    emit8(0x4C); emit8(0x8B); emit8(0x43); emit8(0x58);  // r8 = [rbx+88] = stagingTexture
    emit8(0xFF); emit8(0xD0);                             // call rax

    // --- Release backBuffer ---
    // backBuffer->vtable[2](backBuffer)
    emit8(0x48); emit8(0x8B); emit8(0x44); emit8(0x24); emit8(0x38); // rax = backBuffer
    emit8(0x48); emit8(0x8B); emit8(0x00);                // rax = vtable
    emit8(0x48); emit8(0x8B); emit8(0x40); emit8(0x10);  // rax = [rax+16] = Release
    emit8(0x48); emit8(0x8B); emit8(0x4C); emit8(0x24); emit8(0x38); // rcx = backBuffer (this)
    emit8(0xFF); emit8(0xD0);                             // call rax

    // --- Clear depth stencil before present ---
    emit8(0x48); emit8(0x8B); emit8(0x43); emit8(0x6C);  // rax = [rbx+108] = dsv
    emit8(0x48); emit8(0x85); emit8(0xC0);               // test rax, rax
    int skipDSPresent = newLabel();
    emitJcc("==", skipDSPresent);
    emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x20);  // sub rsp, 0x20
    emit8(0x48); emit8(0x8B); emit8(0x43); emit8(0x40);  // rax = context
    emit8(0x48); emit8(0x8B); emit8(0x00);                // rax = vtable
    emit8(0x48); emit8(0x8B); emit8(0x80); emit32(0x1A8); // rax = [rax+0x1A8] = ClearDepthStencilView
    emit8(0x48); emit8(0x8B); emit8(0x4B); emit8(0x40);  // rcx = context
    emit8(0x48); emit8(0x8B); emit8(0x53); emit8(0x6C);  // rdx = dsv
    emit8(0x41); emit8(0xB8); emit32(1);                  // r8d = D3D11_CLEAR_DEPTH
    // Store 1.0f on stack then load into xmm0
    emit8(0xC7); emit8(0x84); emit8(0x24); emit32(0x50); emit32(0x3F800000); // mov dword [rsp+0x50], 1.0f
    emit8(0xF3); emit8(0x0F); emit8(0x10); emit8(0x84); emit8(0x24); emit32(0x50); // movss xmm0, [rsp+0x50]
    emit8(0x45); emit8(0x33); emit8(0xC9);               // r9d = 0
    emit8(0xFF); emit8(0xD0);                             // call rax
    emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x20);  // add rsp, 0x20
    emitLabel(skipDSPresent);

    // --- Present(1, 0) ---
    // swapChain->vtable[8](swapChain, 1, 0)
    emit8(0x48); emit8(0x8B); emit8(0x43); emit8(0x48);  // rax = swapChain
    emit8(0x48); emit8(0x8B); emit8(0x00);                // rax = vtable
    emit8(0x48); emit8(0x8B); emit8(0x40); emit8(0x40);  // rax = [rax+64] = Present
    emit8(0x48); emit8(0x8B); emit8(0x4B); emit8(0x48);  // rcx = swapChain (this)
    emit8(0xBA); emit32(1);                               // rdx = SyncInterval = 1
    emit8(0x45); emit8(0x33); emit8(0xC0);               // r8d = Flags = 0
    emit8(0xFF); emit8(0xD0);                             // call rax

    // --- Map staging texture for next frame ---
    // context->vtable[11](context, stagingTexture, 0, D3D11_MAP_WRITE, 0, &mapped)
    // D3D11_MAPPED_SUBRESOURCE at [rsp+0x50]
    // Compute &mapped and store as 6th param BEFORE loading Map fn into rax
    emit8(0x48); emit8(0x8D); emit8(0x44); emit8(0x24); emit8(0x50); // rax = &mapped
    emit8(0x48); emit8(0x89); emit8(0x44); emit8(0x24); emit8(0x28); // [rsp+0x28] = &mapped
    // Load Map fn via vtable
    emit8(0x48); emit8(0x8B); emit8(0x43); emit8(0x40);  // rax = context
    emit8(0x48); emit8(0x8B); emit8(0x00);                // rax = vtable
    emit8(0x48); emit8(0x8B); emit8(0x40); emit8(0x70);  // rax = [rax+112] = Map
    // Set up parameters
    emit8(0x48); emit8(0x8B); emit8(0x4B); emit8(0x40);  // rcx = context (this)
    emit8(0x48); emit8(0x8B); emit8(0x53); emit8(0x58);  // rdx = stagingTexture
    emit8(0x45); emit8(0x33); emit8(0xC0);               // r8d = 0 (Subresource)
    emit8(0x41); emit8(0xB9); emit32(2);                  // r9d = D3D11_MAP_WRITE (2)
    emit8(0xC7); emit8(0x44); emit8(0x24); emit8(0x20); emit32(0); // MapFlags = 0
    emit8(0xFF); emit8(0xD0);                             // call rax

    // Store mapped.pData in globals+40 (framebuffer pointer)
    emit8(0x48); emit8(0x8B); emit8(0x44); emit8(0x24); emit8(0x50); // rax = mapped.pData
    emit8(0x48); emit8(0x89); emit8(0x43); emit8(0x28);  // [rbx+40] = framebuf

    // Restore stack
    emit8(0x48); emit8(0x81); emit8(0xC4); emit32(0x80);
}

void Codegen::emitDX11Cleanup() {
    // Allocate shadow space for all Release calls (5 * 8 < 32, but each needs 32-byte aligned)
    emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x20);  // sub rsp, 0x20 (shadow space)

    // Release staging texture: stagingTexture->vtable[2](stagingTexture)
    emit8(0x48); emit8(0x8B); emit8(0x43); emit8(0x58);  // rax = [rbx+88]
    emit8(0x48); emit8(0x85); emit8(0xC0);               // test rax, rax
    int skipStaging = newLabel();
    emit8(0x74); emit8(0x0D);                             // jz skipStaging
    emit8(0x48); emit8(0x8B); emit8(0x00);               // rax = vtable
    emit8(0x48); emit8(0x8B); emit8(0x40); emit8(0x10); // rax = Release
    emit8(0x48); emit8(0x8B); emit8(0x4B); emit8(0x58); // rcx = stagingTexture
    emit8(0xFF); emit8(0xD0);                            // call rax
    emitLabel(skipStaging);

    // Release RTV: rtv->vtable[2](rtv)
    emit8(0x48); emit8(0x8B); emit8(0x43); emit8(0x50);  // rax = [rbx+80]
    emit8(0x48); emit8(0x85); emit8(0xC0);
    int skipRTV = newLabel();
    emit8(0x74); emit8(0x0D);
    emit8(0x48); emit8(0x8B); emit8(0x00);
    emit8(0x48); emit8(0x8B); emit8(0x40); emit8(0x10);
    emit8(0x48); emit8(0x8B); emit8(0x4B); emit8(0x50);
    emit8(0xFF); emit8(0xD0);
    emitLabel(skipRTV);

    // Release depth-stencil view: dsv->vtable[2](dsv)
    emit8(0x48); emit8(0x8B); emit8(0x43); emit8(0x6C);  // rax = [rbx+108]
    emit8(0x48); emit8(0x85); emit8(0xC0);
    int skipDSV = newLabel();
    emit8(0x74); emit8(0x0D);
    emit8(0x48); emit8(0x8B); emit8(0x00);
    emit8(0x48); emit8(0x8B); emit8(0x40); emit8(0x10);
    emit8(0x48); emit8(0x8B); emit8(0x4B); emit8(0x6C);
    emit8(0xFF); emit8(0xD0);
    emitLabel(skipDSV);

    // Release depth-stencil texture: dsTexture->vtable[2](dsTexture)
    emit8(0x48); emit8(0x8B); emit8(0x43); emit8(0x64);  // rax = [rbx+100]
    emit8(0x48); emit8(0x85); emit8(0xC0);
    int skipDSTex = newLabel();
    emit8(0x74); emit8(0x0D);
    emit8(0x48); emit8(0x8B); emit8(0x00);
    emit8(0x48); emit8(0x8B); emit8(0x40); emit8(0x10);
    emit8(0x48); emit8(0x8B); emit8(0x4B); emit8(0x64);
    emit8(0xFF); emit8(0xD0);
    emitLabel(skipDSTex);

    // Release context: context->vtable[2](context)
    emit8(0x48); emit8(0x8B); emit8(0x43); emit8(0x40);  // rax = [rbx+64]
    emit8(0x48); emit8(0x85); emit8(0xC0);
    int skipCtx = newLabel();
    emit8(0x74); emit8(0x0D);
    emit8(0x48); emit8(0x8B); emit8(0x00);
    emit8(0x48); emit8(0x8B); emit8(0x40); emit8(0x10);
    emit8(0x48); emit8(0x8B); emit8(0x4B); emit8(0x40);
    emit8(0xFF); emit8(0xD0);
    emitLabel(skipCtx);

    // Release swapChain: swapChain->vtable[2](swapChain)
    emit8(0x48); emit8(0x8B); emit8(0x43); emit8(0x48);  // rax = [rbx+72]
    emit8(0x48); emit8(0x85); emit8(0xC0);
    int skipSC = newLabel();
    emit8(0x74); emit8(0x0D);
    emit8(0x48); emit8(0x8B); emit8(0x00);
    emit8(0x48); emit8(0x8B); emit8(0x40); emit8(0x10);
    emit8(0x48); emit8(0x8B); emit8(0x4B); emit8(0x48);
    emit8(0xFF); emit8(0xD0);
    emitLabel(skipSC);

    // Release device: device->vtable[2](device)
    emit8(0x48); emit8(0x8B); emit8(0x43); emit8(0x38);  // rax = [rbx+56]
    emit8(0x48); emit8(0x85); emit8(0xC0);
    int skipDev = newLabel();
    emit8(0x74); emit8(0x0D);
    emit8(0x48); emit8(0x8B); emit8(0x00);
    emit8(0x48); emit8(0x8B); emit8(0x40); emit8(0x10);
    emit8(0x48); emit8(0x8B); emit8(0x4B); emit8(0x38);
    emit8(0xFF); emit8(0xD0);
    emitLabel(skipDev);

    emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x20);  // add rsp, 0x20
}
