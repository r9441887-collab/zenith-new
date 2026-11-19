#include <string>
#include <iostream>

/* C++ side: uses the standard C++ library so the mixer must route mangled
   libstdc++ symbols (std::string, iostream) to libstdc++.so.6. */

std::string mixcpp_upper(const std::string& in) {
    std::string out = in;
    for (char& c : out)
        if (c >= 'a' && c <= 'z') c = (char)(c - 'a' + 'A');
    return out;
}

extern "C" int mixcpp_stream(const char* s) {
    std::cout << "C++ cout: " << (s ? s : "") << " (upper=" << mixcpp_upper(s ? s : "") << ")" << std::endl;
    std::cout.flush();
    return 0;
}

extern "C" const char* mixcpp_convert(const char* s) {
    static std::string buf;
    buf = mixcpp_upper(std::string(s ? s : ""));
    return buf.c_str();
}