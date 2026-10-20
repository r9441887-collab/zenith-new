#pragma once
#include <string>

// Host-side standard-library discovery for the C/C++ mixing feature.
//
// Two backends:
//   * LinuxELF — the compiler itself runs on a Linux host, so the real
//     system shared libraries are probed with dlopen/dlsym. Undefined
//     symbols from mixed-in C/C++ objects are routed to whichever standard
//     library actually provides them (libc.so.6, libm.so.6, libstdc++.so.6,
//     libgcc_s.so.1, libpthread.so.0, librt.so.1, libdl.so.2, libz.so.1 ...).
//   * WindowsPE — the binary is produced by a mingw toolchain. Undefined
//     symbols are mapped to the runtime DLL (msvcrt.dll, libstdc++-6.dll,
//     libgcc_s_seh-1.dll, libwinpthread-1.dll) by reading the import
//     libraries the toolchain ships, with a Win32 API fallback table.
//
// "Where they exist in the system": a candidate library is only used when
// it is actually present/loadable; symbols the system cannot provide are
// reported to the caller via the *Found() queries and the fallback return.

namespace mix {

// soname (e.g. "libc.so.6") of the system shared library that provides the
// symbol, or "libc.so.6" as a fallback when nothing matches.
std::string linuxSonameFor(const std::string& sym);
// True when linuxSonameFor() matched a real provider instead of the fallback.
bool linuxProbeFound(const std::string& sym);

// DLL name (e.g. "msvcrt.dll") that provides the symbol in a mingw-built PE,
// or "msvcrt.dll" as a fallback when nothing matches.
std::string mingwDllFor(const std::string& sym);
// True when mingwDllFor() routed the symbol to a known library (mingw import
// library or Win32 API table) instead of the blind fallback.
bool mingwRouted(const std::string& sym);

// Byte size of an externally-provided data symbol (stdout, _ZSt4cout, ...)
// taken from the host shared library's .dynsym; 0 when not found. Used to size
// R_X86_64_COPY relocation cells.
size_t linuxDynSymSize(const std::string& sym);
// 1 = function/ifunc, 2 = object, 0 = unknown/missing (host .dynsym based)
int linuxSymbolKind(const std::string& sym);

} // namespace mix