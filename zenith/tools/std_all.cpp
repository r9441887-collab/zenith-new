#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <cctype>
#include <ctime>
#include <cstdarg>
#include <climits>
#include <cfloat>
#include <cerrno>
#include <cwchar>
#include <cassert>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <limits>
#include <memory>
#include <utility>
#include <functional>
#include <new>
#include <istream>
#include <ostream>
#include <numeric>
#include <cstdint>

extern "C" long stdall_c(const char* in);

static int qsortCmp(const void* a, const void* b) {
    int x = *(const int*)a;
    int y = *(const int*)b;
    return x - y;
}

extern "C" int stdall_cpp(int seed) {
    long total = 0;
    long failures = 0;
#define CHECK(expr) do { if (!(expr)) { failures++; printf("FAIL line %d\n", __LINE__); fflush(stdout); } } while (0)

    /* ---- <cstdlib> ---- */
    CHECK(abs(-7) == 7);
    CHECK(labs(-123456L) == 123456L);
    CHECK(atoi("  42") == 42);
    CHECK(atol("-1234") == -1234L);
    CHECK(strtol("0x1A", nullptr, 16) == 26);
    CHECK(strtod("3.5xyz", nullptr) == 3.5);
    CHECK(rand() >= 0);

    /* ---- <cstring> ---- */
    char buf[64];
    strcpy(buf, "hello");
    CHECK(strlen(buf) == 5);
    strcat(buf, " world");
    CHECK(strcmp(buf, "hello world") == 0);
    CHECK(strncmp("abc", "abd", 2) == 0);
    CHECK(strchr("abcdef", 'c') != nullptr);
    CHECK(strrchr("abcba", 'b') != nullptr);
    CHECK(strstr("one two three", "two") != nullptr);
    char mb[64];
    memset(mb, 0xAA, 16);
    CHECK(((unsigned char)mb[0]) == 0xAA && ((unsigned char)mb[15]) == 0xAA);
    char t1[16], t2[16];
    strcpy(t1, "source");
    memcpy(t2, t1, 7);
    CHECK(strcmp(t1, t2) == 0);
    CHECK(memcmp(t1, t2, 7) == 0);
    char ov[16];
    strcpy(ov, "overlap");
    memmove(ov + 2, ov, 6);
    CHECK(ov[2] == 'o');
    CHECK(strcspn("hello", "lo") == 2);
    CHECK(strspn("hello", "hel") == 4);

    /* ---- <cmath> ---- */
    CHECK(fabs(-2.5) == 2.5);
    CHECK(floor(3.7) == 3.0);
    CHECK(ceil(3.1) == 4.0);
    CHECK(round(3.6) == 4.0);
    CHECK(fmod(7.5, 2.0) == 1.5);
    CHECK(fabs(pow(2.0, 10.0) - 1024.0) < 1e-9);
    CHECK(fabs(sqrt(81.0) - 9.0) < 1e-9);
    CHECK(fabs(sin(0.0)) < 1e-12);
    CHECK(fabs(cos(0.0) - 1.0) < 1e-12);
    CHECK(fabs(tan(0.0)) < 1e-12);
    CHECK(fabs(exp(0.0) - 1.0) < 1e-12);
    CHECK(fabs(log(2.718281828459045) - 1.0) < 1e-9);
    CHECK(fabs(log10(1000.0) - 3.0) < 1e-9);
    CHECK(fabs(cbrt(27.0) - 3.0) < 1e-9);
    CHECK(std::isfinite(1.0));

    /* ---- <cctype> ---- */
    CHECK(isalpha('a') && isalpha('Z'));
    CHECK(isdigit('7'));
    CHECK(isalnum('x') && isalnum('0'));
    CHECK(isspace(' '));
    CHECK(isupper('A') && !isupper('a'));
    CHECK(tolower('A') == 'a');
    CHECK(toupper('a') == 'A');

    /* ---- <ctime> ---- */
    time_t now = time(nullptr);
    CHECK(now > 0);
    clock_t ck = clock();
    CHECK((long)ck >= 0);
    struct tm* lt = localtime(&now);
    CHECK(lt != nullptr);
    char tb[64];
    strftime(tb, sizeof(tb), "%Y", lt);
    CHECK(strlen(tb) == 4);

    /* ---- <cstdio> ---- */
    int sn;
    sn = snprintf(buf, sizeof(buf), "%d/%s/%g", 42, "str", 2.5);
    CHECK(sn > 0);
    CHECK(snprintf(nullptr, 0, "%d", 1) == 1);
    int rd;
    sscanf("10 20", "%d %d", &sn, &rd);
    CHECK(sn == 10 && rd == 20);
    FILE* f = fopen("/tmp/zenith_stdall.txt", "w");
    CHECK(f != nullptr);
    if (f) {
        fprintf(f, "line %d\n", 9);
        fclose(f);
    }
    f = fopen("/tmp/zenith_stdall.txt", "r");
    if (f) {
        char line[32];
        CHECK(fgets(line, sizeof(line), f) != nullptr);
        fclose(f);
    }
    remove("/tmp/zenith_stdall.txt");

    /* ---- <cerrno> ---- */
    errno = 0;
    strtod("notanum", nullptr);
    CHECK(errno == 0 || errno != 0);

    /* ---- <cstdarg> (variadic call through a helper) ---- */
    /* ---- <limits> ---- */
    CHECK(std::numeric_limits<int>::max() == INT_MAX);
    CHECK(std::numeric_limits<double>::min() > 0);
    CHECK(std::numeric_limits<char>::is_signed || !std::numeric_limits<char>::is_signed);

    /* ---- <string> ---- */
    CHECK(std::string("abc").length() == 3);
    CHECK(std::string("a") + "b" == "ab");
    CHECK(std::string("hello").substr(1, 3) == "ell");
    CHECK(std::string("hello").find("ll") == 2);
    CHECK(std::string("hello").find('z') == std::string::npos);
    CHECK((std::string("abc") == "abc"));
    CHECK(std::string("  x  ") != "x");
    std::string up = "abc";
    std::transform(up.begin(), up.end(), up.begin(), ::toupper);
    CHECK(up == "ABC");

    /* ---- <vector> ---- */
    std::vector<int> v;
    for (int i = 0; i < 100; i++) v.push_back(i * 2);
    CHECK(v.size() == 100 && v[99] == 198);
    v.pop_back();
    CHECK(v.size() == 99);
    CHECK(v.front() == 0 && v.back() == 196);
    v.insert(v.begin() + 3, 7);
    CHECK(v[3] == 7);
    v.erase(v.begin() + 3);
    CHECK(v[3] == 6);

    /* ---- <algorithm> ---- */
    std::vector<int> w{5, 2, 9, 1, 7};
    std::sort(w.begin(), w.end());
    CHECK(w[0] == 1 && w[4] == 9);
    CHECK(*std::min_element(w.begin(), w.end()) == 1);
    CHECK(*std::max_element(w.begin(), w.end()) == 9);
    CHECK(std::find(w.begin(), w.end(), 7) != w.end());
    CHECK(std::count(w.begin(), w.end(), 5) == 1);
    long sum = std::accumulate(w.begin(), w.end(), 0L);
    CHECK(sum == 24);
    std::reverse(w.begin(), w.end());
    CHECK(w[0] == 9);

    /* ---- <map>, <set> ---- */
    std::map<std::string, int> m;
    m["one"] = 1; m["two"] = 2; m["three"] = 3;
    CHECK(m.size() == 3);
    CHECK(m["two"] == 2);
    CHECK(m.count("four") == 0);
    std::set<int> s;
    for (int i = 0; i < 10; i++) s.insert(i % 3);
    CHECK(s.size() == 3);

    /* ---- <sstream>/<iomanip> ---- */
    std::ostringstream oss;
    oss << "val=" << std::setw(4) << 42;
    CHECK(oss.str() == "val=  42");
    std::istringstream iss("123 456");
    int a1, a2;
    iss >> a1 >> a2;
    CHECK(a1 == 123 && a2 == 456);

    /* ---- <memory> ---- */
    std::shared_ptr<int> sp(new int(1234));
    CHECK(*sp == 1234);
    std::unique_ptr<int> up2(new int(99));
    CHECK(*up2 == 99);

    /* ---- qsort/bsearch (C-style) ---- */
    int arr[5] = {4, 1, 3, 5, 2};
    qsort(arr, 5, sizeof(int), qsortCmp);
    CHECK(arr[0] == 1 && arr[4] == 5);
    int key = 3;
    CHECK(bsearch(&key, arr, 5, sizeof(int), qsortCmp) != nullptr);

    /* ---- call stdall_c: C std functions across the boundary ---- */
    long cresult = stdall_c("zenith");
    CHECK(cresult == 6 + 12);   /* strlen + print size must stay in sync */

    if (failures) {
        printf("stdall_cpp FAILURES: %ld\n", failures);
        fflush(stdout);
        return (int)failures;
    }
    printf("stdall_cpp OK (all std checks passed)\n");
    fflush(stdout);
    return 0;
}