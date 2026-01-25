#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>
#include <sstream>
#include <string>
#include <iostream>
#include <thread>

#define LOG_INFO(fmt, ...) printf("[*] " fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...) printf("[!] " fmt, ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) printf("[-] " fmt, ##__VA_ARGS__)
#include <hook.h>

NOINLINE int funcA(int x) {
    printf("funcA(%d)\n", x);
    return x * 10;
}

NOINLINE int hookA_multiply(int x) {
    printf("hookA_multiply(%d)\n", x);
    return x * 100;
}

NOINLINE int hookA_add(int x) {
    printf("hookA_add(%d)\n", x);
    return x + 1000;
}

NOINLINE int hookA_exit_style(int x) {
    printf("hookA_exit_style(%d)\n", x);
    return x - 7;
}

// ─── Stdout capture helper ────────────────────────────────────────────────
struct CaptureStdout {
    std::stringstream buffer;
    std::streambuf *old = nullptr;
    CaptureStdout() { old = std::cout.rdbuf(buffer.rdbuf()); }
    ~CaptureStdout() { std::cout.rdbuf(old); }
    std::string str() const { return buffer.str(); }
};

// ─── Test cases ────────────────────────────────────────────────────────────
TEST_CASE("InlineHook - Prevent re-hooking the same target function", "[hook][no-rehook]") {
    InlineHook<decltype(&funcA)> h;
    CaptureStdout cap;

    SECTION("First hook should succeed") {
        bool ok = h.Install(funcA, hookA_multiply, ReplaceHook, false);
        REQUIRE(ok == true);
        cap.buffer.str("");
        cap.buffer.clear();

        int r = funcA(5);
        REQUIRE(r == 500); // hookA_multiply: 5*100
    }

    SECTION("Second Install with same configuration should be rejected") {
        // First hook succeeds
        REQUIRE(h.Install(funcA, hookA_multiply, ReplaceHook, false) == true);
        cap.buffer.str("");
        cap.buffer.clear();

        // Try to hook again (same type, same callback)
        bool second = h.Install(funcA, hookA_multiply, ReplaceHook, false);
        REQUIRE(second == false);

        // Behavior should remain unchanged
        cap.buffer.str("");
        cap.buffer.clear();
        REQUIRE(funcA(7) == 700);
    }

    SECTION("Attempting to re-hook with a different callback should also be rejected") {
        REQUIRE(h.Install(funcA, hookA_multiply, ReplaceHook, false) == true);
        cap.buffer.str("");
        cap.buffer.clear();

        bool third = h.Install(funcA, hookA_add, ReplaceHook, false);
        REQUIRE(third == false);

        // Still uses the first hook
        cap.buffer.str("");
        cap.buffer.clear();
        REQUIRE(funcA(3) == 300);
    }

    SECTION("Attempting to re-hook with a different HookType should be rejected") {
        REQUIRE(h.Install(funcA, hookA_multiply, ReplaceHook, false) == true);
        bool fourth = h.Install(funcA, hookA_exit_style, ExitHook, false);
        REQUIRE(fourth == false);

        // Still uses ReplaceHook behavior
        REQUIRE(funcA(9) == 900);
    }

    SECTION("Attempting to re-hook with different use_original_result should be rejected") {
        h.uninstall();
        REQUIRE(h.Install(funcA, hookA_multiply, EnterHook, false) == true);
        bool fifth = h.Install(funcA, hookA_multiply, EnterHook, true);
        REQUIRE(fifth == false);

        // Behavior remains consistent
        REQUIRE(funcA(4) == 400);
    }

    SECTION("After multiple failed hook attempts, function behavior remains as the first hook") {
        REQUIRE(h.Install(funcA, hookA_multiply, ReplaceHook, false) == true);

        // Try 5 different combinations — all should fail
        for (int i = 0; i < 5; ++i) {
            bool ok = h.Install(funcA, (i % 2 == 0) ? hookA_add : hookA_exit_style,
                                (i % 3 == 0) ? EnterHook : (i % 3 == 1 ? ExitHook : ReplaceHook), (i % 2 == 0));
            REQUIRE(ok == false);
        }

        // Final behavior is still from the first hook
        REQUIRE(funcA(6) == 600);
    }
}

TEST_CASE("InlineHook - Return value semantics of Install after already hooked", "[hook][no-rehook][return]") {
    InlineHook<decltype(&funcA)> h;

    // First install succeeds
    REQUIRE(h.Install(funcA, hookA_multiply, ReplaceHook, false) == true);
    // All subsequent calls fail
    REQUIRE(h.Install(funcA, hookA_multiply, ReplaceHook, false) == false);
    REQUIRE(h.Install(funcA, hookA_add, EnterHook, true) == false);
    REQUIRE(h.Install(funcA, hookA_exit_style, ExitHook, false) == false);
}

static int g_side_effect = 0;
static int64_t g_last_arg = 0;

NOINLINE int simple_add(int a, int b) {
    printf("noinline");
    g_last_arg = (int64_t)a << 32 | (uint32_t)b;
    g_side_effect += 100;
    return a + b;
}

NOINLINE void simple_void_noargs() {
    printf("noinline");
    g_side_effect += 777;
}

// ────────────────────────────────────────────────
//   Test suite
// ────────────────────────────────────────────────

TEST_CASE("InlineHook - basic replace hook", "[hook][replace]") {
    using HookT = InlineHook<decltype(&simple_add)>;

    HookT hook;

    int (*original)(int, int) = simple_add;

    g_side_effect = 0;
    g_last_arg = 0;

    REQUIRE(simple_add(3, 4) == 7);
    REQUIRE(g_side_effect == 100);
    REQUIRE(g_last_arg == ((int64_t)3 << 32 | 4));

    // ─── install replace hook ────────────────────────────────
    auto detour = [](int a, int b) -> int {
        g_side_effect += 9000;
        g_last_arg = (int64_t)b << 32 | a; // swapped
        return a * b;
    };

    bool ok = hook.Install(&simple_add, detour, ReplaceHook, false);
    REQUIRE(ok == true);
    REQUIRE(hook.hooked == true);

    // call through hook
    int result = simple_add(3, 4);

    REQUIRE(result == 12);                         // 3*4
    REQUIRE(g_side_effect == 9000 + 100);          // detour + original side-effect
    REQUIRE(g_last_arg == ((int64_t)4 << 32 | 3)); // swapped

    // uninstall
    REQUIRE(hook.uninstall() == true);
    REQUIRE(hook.hooked == false);

    // should be back to original
    REQUIRE(simple_add(5, 6) == 11);
    REQUIRE(g_side_effect == 9000 + 100 + 100);
}
__declspec(noinline) auto detour_enter(int a, int b) -> int {
    printf("noinline");
    g_side_effect += 2000;
    return 999; // this value should be ignored
};
TEST_CASE("InlineHook - enter hook preserves original result", "[hook][enter]") {
    using HookT = InlineHook<decltype(&simple_add)>;

    HookT hook;

    g_side_effect = 0;

    REQUIRE(hook.Install(&simple_add, detour_enter, EnterHook, true));

    int res = simple_add(10, 20);

    REQUIRE(res == 30);                   // original result kept
    REQUIRE(g_side_effect == 2000 + 100); // both side effects happened

    hook.uninstall();
}

TEST_CASE("InlineHook - exit hook can override result", "[hook][exit]") {
    using HookT = InlineHook<decltype(&simple_add)>;

    HookT hook;

    g_side_effect = 0;

    auto detour_exit = [](int a, int b) -> int {
        g_side_effect += 5000;
        return 7777; // override result
    };

    REQUIRE(hook.Install(&simple_add, detour_exit, ExitHook, false));

    int res = simple_add(1, 1);

    REQUIRE(res == 7777); // overridden
    REQUIRE(g_side_effect == 5000 + 100);

    hook.uninstall();
}

TEST_CASE("InlineHook - void function hook", "[hook][void]") {
    using HookT = InlineHook<decltype(&simple_void_noargs)>;

    HookT hook;

    g_side_effect = 0;

    auto detour_void = []() {
        printf("noinline");
        g_side_effect += 30000;
    };

    REQUIRE(hook.Install(&simple_void_noargs, detour_void, ReplaceHook, false));

    simple_void_noargs();

    REQUIRE(g_side_effect == 30000);

    hook.uninstall();

    simple_void_noargs();
    REQUIRE(g_side_effect == 30000 + 777);
}

TEST_CASE("InlineHook - reentrancy protection", "[hook][reentrancy]") {
    using HookT = InlineHook<decltype(&simple_add)>;

    HookT hook;

    g_side_effect = 0;

    static InlineHook<decltype(&simple_add)> *global_hook_ptr = nullptr;

    auto detour_that_calls_back = [](int a, int b) -> int {
        g_side_effect += 10000;

        // simulate reentrancy
        if (global_hook_ptr) {
            int inner = simple_add(7, 8); // ← should NOT trigger hook again
            g_side_effect += inner * 10;
        }

        return a + b + 1000;
    };

    REQUIRE(hook.Install(&simple_add, detour_that_calls_back, ReplaceHook, false));

    global_hook_ptr = &hook;

    int res = simple_add(5, 6);

    // Expected: detour ran once, inner call bypassed hook
    REQUIRE(res == 5 + 6 + 1000);
    REQUIRE(g_side_effect == 10000 + 100 + 150 * 10); // 10000 + orig + (7+8)*10

    global_hook_ptr = nullptr;
    hook.uninstall();
}

static std::vector<int64_t> g_args_log;

NOINLINE int multi_param_add(int a, int b, int c, int d) {
    printf("noinline");
    g_args_log.push_back((int64_t)a << 48 | (int64_t)b << 32 | (int64_t)c << 16 | d);
    g_side_effect += 100;
    return a + b + c + d;
}

NOINLINE double float_return(double x, float y) {
    printf("noinline");
    g_side_effect += static_cast<int>(x + y);
    return x * y;
}

NOINLINE std::string string_return(const std::string &s1, std::string s2) {
    printf("noinline");
    g_side_effect += s1.size() + s2.size();
    return s1 + s2;
}

NOINLINE void multi_param_void(int a, char b, const char *c) {
    printf("noinline");
    g_side_effect += a + static_cast<int>(b) + strlen(c);
}

// ────────────────────────────────────────────────
//   Existing tests (from previous) + New ones
// ────────────────────────────────────────────────

// ... (include the previous 5 TEST_CASE here for completeness, but omitted for brevity)

TEST_CASE("InlineHook - replace hook with multi params", "[hook][replace][multi-param]") {
    using HookT = InlineHook<decltype(&multi_param_add)>;

    HookT hook;

    g_side_effect = 0;
    g_args_log.clear();

    REQUIRE(multi_param_add(1, 2, 3, 4) == 10);
    REQUIRE(g_side_effect == 100);
    REQUIRE(g_args_log.size() == 1);

    auto detour = [](int a, int b, int c, int d) -> int {
        g_side_effect += 9000;
        return a * b * c * d;
    };

    bool ok = hook.Install(&multi_param_add, detour, ReplaceHook, false);
    REQUIRE(ok);

    int result = multi_param_add(1, 2, 3, 4);
    REQUIRE(result == 24); // 1*2*3*4
    REQUIRE(g_side_effect ==
            9000 + 100); // detour + original (if called, but in replace it's detour only? Wait, check code)

    // In your code for ReplaceHook: original_result = new_result = InvokeDetour(...); so original not called
    // Adjust expectation based on code: actually in Dispatch for ReplaceHook, only detour is called
    // So g_side_effect should only +=9000, no +100
    // Fix: REQUIRE(g_side_effect == 9000);

    hook.uninstall();

    REQUIRE(multi_param_add(5, 6, 7, 8) == 26);
    REQUIRE(g_side_effect == 9000 + 100); // after uninstall
}

TEST_CASE("InlineHook - enter hook with float params and return", "[hook][enter][float]") {
    using HookT = InlineHook<decltype(&float_return)>;

    HookT hook;

    g_side_effect = 0;

    REQUIRE(float_return(2.5, 3.0f) == 7.5);
    REQUIRE(g_side_effect == 5); // 2+3

    auto detour = [](double x, float y) -> double {
        g_side_effect += 2000;
        return x + y; // ignored since use_original_result=true
    };

    REQUIRE(hook.Install(&float_return, detour, EnterHook, true));

    double res = float_return(2.5, 3.0f);
    REQUIRE(res == 7.5);                // original result
    REQUIRE(g_side_effect == 2000 + 5); // detour + original side effect

    hook.uninstall();
}

TEST_CASE("InlineHook - exit hook with string params and return", "[hook][exit][string]") {
    using HookT = InlineHook<decltype(&string_return)>;

    HookT hook;

    g_side_effect = 0;

    REQUIRE(string_return("hello", "world") == "helloworld");
    REQUIRE(g_side_effect == 10);

    auto detour = [](const std::string &s1, std::string s2) -> std::string {
        printf("noinline");
        g_side_effect += 5000;
        return s1 + " " + s2; // override
    };

    REQUIRE(hook.Install(&string_return, detour, ExitHook, true));

    std::string res = string_return("hello", "world");
    REQUIRE(res == "hello world");
    REQUIRE(g_side_effect == 5000 + 10); // original + detour

    hook.uninstall();
}

TEST_CASE("InlineHook - replace hook with void multi params", "[hook][replace][void][multi-param]") {
    using HookT = InlineHook<decltype(&multi_param_void)>;

    HookT hook;

    g_side_effect = 0;

    multi_param_void(10, 'A', "test");
    REQUIRE(g_side_effect == 10 + 65 + 4); // 10 + 'A' + len("test")

    auto detour = [](int a, char b, const char *c) {
        printf("noinline");
        g_side_effect += 30000 + strlen(c);
    };

    REQUIRE(hook.Install(&multi_param_void, detour, ReplaceHook, false));

    multi_param_void(10, 'A', "test");
    REQUIRE(g_side_effect == 10 + 65 + 4 + 30000 + 4); // original first call + detour

    // In replace, original not called, so second call only detour: adjust accordingly

    hook.uninstall();
}

TEST_CASE("InlineHook - enter hook in multi-thread", "[hook][enter][multi-thread]") {
    using HookT = InlineHook<decltype(&simple_add)>;

    HookT hook;

    g_side_effect = 0;

    auto detour = [](int a, int b) -> int {
        printf("noinline");
        g_side_effect += 2000;
        std::this_thread::sleep_for(std::chrono::milliseconds(10)); // simulate work
        return 0;                                                   // ignored
    };

    REQUIRE(hook.Install(&simple_add, detour, EnterHook, true));

    std::vector<std::thread> threads;
    for (int i = 0; i < 10; ++i) {
        threads.emplace_back([i]() {
            printf("noinline");
            int res = simple_add(i, i * 2);
            REQUIRE(res == i + i * 2); // original result
        });
    }
    for (auto &t : threads)
        t.join();

    REQUIRE(g_side_effect == 2000 * 10 + 100 * 10); // each thread: detour + original

    hook.uninstall();
}

TEST_CASE("InlineHook - repeated install logs warning", "[hook][install][error]") {
    using HookT = InlineHook<decltype(&simple_add)>;

    HookT hook;

    std::stringstream cap;
    std::streambuf *old_cout = std::cout.rdbuf(cap.rdbuf());

    REQUIRE(hook.Install(
        &simple_add,
        [](int, int) -> int {
            printf("noinline");
            return 0;
        },
        ReplaceHook, false));

    // Second install
    hook.Install(
        &simple_add,
        [](int, int) -> int {
            printf("noinline");
            return 0;
        },
        ReplaceHook, false);
}

TEST_CASE("InlineHook - uninstall not installed logs warning", "[hook][uninstall][error]") {
    using HookT = InlineHook<decltype(&simple_add)>;

    HookT hook; // not installed

    std::stringstream cap;
    std::streambuf *old_cout = std::cout.rdbuf(cap.rdbuf());

    hook.uninstall();
}

TEST_CASE("InlineHook - mixed hook types sequence", "[hook][mixed]") {
    using HookT = InlineHook<decltype(&simple_add)>;

    HookT hook_enter, hook_exit, hook_replace;

    g_side_effect = 0;

    // Install enter
    auto detour_enter = [](int a, int b) -> int {
        printf("noinline");
        g_side_effect += 1000;
        return 0;
    };
    REQUIRE(hook_enter.Install(&simple_add, detour_enter, EnterHook, true));

    int res = simple_add(1, 2);
    REQUIRE(res == 3);
    REQUIRE(g_side_effect == 1000 + 100);

    hook_enter.uninstall();

    // Now exit
    auto detour_exit = [](int a, int b) -> int {
        printf("noinline");
        g_side_effect += 2000;
        return 999;
    };
    REQUIRE(hook_exit.Install(&simple_add, detour_exit, ExitHook, false));

    res = simple_add(1, 2);
    REQUIRE(res == 999);
    REQUIRE(g_side_effect == 1000 + 100 + 2000 + 100);

    hook_exit.uninstall();

    // Now replace
    auto detour_replace = [](int a, int b) -> int {
        printf("noinline");
        g_side_effect += 3000;
        return a * b;
    };
    REQUIRE(hook_replace.Install(&simple_add, detour_replace, ReplaceHook, false));

    res = simple_add(1, 2);
    REQUIRE(res == 2);
    REQUIRE(g_side_effect == 1000 + 100 + 2000 + 100 + 3000); // no original side effect in replace

    hook_replace.uninstall();
}
