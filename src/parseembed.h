#pragma once
#include "ast.h"

#include <cstddef>
#include <cstdint>
#include <string>

// Rebuilds a Program from a ZAST blob produced by azBuild(). Returns false if
// the image is truncated or carries an out-of-range id; `prog` is then only
// ever partially filled.
bool loadZast(const uint8_t* blob, size_t len, Program& prog);

// Runs the selfhost parser (selfhost/parseobj.z, linked into this binary as
// parseobj.o) on `src` and loads the resulting ZAST blob into `prog`.
//
// rc: 0 ok, 1 overflow (msg), 2 TError-token (msg + errLine), 3 parse error
// (msg). On rc == 0 `prog` is fully populated; `parseRelease()` is called on
// every path. `msg` is the raw error text by length (no NUL needed).
int parseZ(const std::string& src, Program& prog, std::string& msg, long long& errLine);
