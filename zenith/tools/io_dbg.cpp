#include <iostream>

extern "C" int io_a(const char* s) {
    std::cout << "A:" << (s ? s : "");
    return 0;
}
extern "C" int io_b(const char* s) {
    std::cout << "B:" << (s ? s : "") << std::endl;
    return 0;
}
extern "C" int io_c() {
    std::cout.flush();
    return 0;
}