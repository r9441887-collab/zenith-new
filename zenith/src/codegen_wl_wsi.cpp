#include "codegen.h"

// =====================================================================
// Linux Vulkan WSI surface builtins (vk_surface_*).
//
// NOTE: This is a build-unblocking stub. The vk_surface_* feature is
// mid-flight (declarations/call-sites/members exist in codegen.h/.cpp but
// the implementation was not committed yet). These two functions exist so
// the Zenith binary links; a real WSI backend will replace them.
//     tryLinuxVkSurfaceCall returns false (no vk_surface_* builtin is
//     handled yet), so calls fall through to normal codegen.
//     detectVkSurfaceUsage is a no-op.
// =====================================================================

void Codegen::detectVkSurfaceUsage() {
    // No builtins are handled yet; nothing to detect.
}

bool Codegen::tryLinuxVkSurfaceCall(CallExpr*, int&) {
    return false;
}