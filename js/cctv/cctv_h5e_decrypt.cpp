// =============================================================================
// cctv_h5e_decrypt.cpp
// cctv_h5e_decrypt.hpp 的命令行驱动（单翻译单元，C++17 / C++20 均可）
// =============================================================================
//
// 本单元只做两件事：
//   1. 定义 CCTV_H5E_IMPLEMENTATION，把 hpp 里的 C ABI 实现编进本翻译单元，
//      cctv_h5e_session_create / _destroy / _reset / _decrypt_nal / _decrypt_ts /
//      _decrypt_ts_alloc / cctv_h5e_free / cctv_h5e_version 全部保留（见下方
//      “C ABI 保活”段，gc-sections 下也不会被裁掉）；
//   2. 提供程序入口 main —— 即从 hpp 的 CCTV_H5E_CLI 段提取出来的那份 main，
//      参数逻辑原样照搬：  <enc.ts> <out.ts> [--pid 0x100]
//
// 编译（MinGW-w64）:
//   g++ -std=c++20 -O2 -o dec.exe cctv_h5e_decrypt.cpp
//   仓库根目录的 编译cpp20.bat 就是这条命令，另外链入 version.rc 的图标/版本资源。
//
// 行为说明（与 hpp 内 CLI 完全一致，提示统一为“标签 + 正文”的终端界面风格）:
//   输出格式          -> 错误/警告/完成/提示/详情 四个汉字标签纵向对齐（内容从第 9 列开始），
//                        仅当 stderr 连着终端时上色，设 NO_COLOR 可关；重定向时是纯文本
//   双击运行          -> 自己独占控制台时打印“按回车键退出…”再退出，窗口不会一闪而过
//                        （H5E_NO_PAUSE=1 可关；从终端/管道/计划任务启动不会停）
//   参数不足          -> 错误 + 用法面板，返回 1
//   输入读不到/为空   -> 错误 + 提示，返回 1
//   解密失败          -> 错误（带返回码），返回 1
//   输出写不了        -> 错误 + 提示，返回 1
//   成功              -> 完成（字节数 → 输出路径）+ 详情（视频 PID、耗时），返回 0
//   --pid 取值异常    -> 警告（缺值 / 不可解析 / 超出 13 位），不中断执行
//   文件名/提示信息   -> 全程 UTF-8：Windows 走 wmain + _wfopen + UTF-8 输出代码页，
//                        不经 ACP(936/1252/932…) 中转，中文、emoji 在任意系统
//                        区域设置下都不乱码；重定向到文件时也是纯 UTF-8 字节流。
// =============================================================================

#define CCTV_H5E_IMPLEMENTATION
#include "cctv_h5e_decrypt.hpp"

// ===== C ABI 保活 =====
// 上面的实现段已经把 C ABI 编译进本单元；这里再用一个 used 锚点把每个入口
// 的地址固化下来，配合 -ffunction-sections -Wl,--gc-sections 也不会被回收，
// 需要导出符号时加 -Wl,--export-all-symbols 即可（DLL/静态库共用同一份源码）。
#if defined(__GNUC__) || defined(__clang__)
#define CCTV_H5E_KEEP __attribute__((used))
#else
#define CCTV_H5E_KEEP
#endif

namespace {

struct H5eCAbiAnchor {
    cctv_h5e_session* (*session_create)(void);
    void (*session_destroy)(cctv_h5e_session*);
    void (*session_reset)(cctv_h5e_session*);
    int (*decrypt_nal)(cctv_h5e_session*, uint8_t*, size_t*);
    int (*decrypt_ts)(cctv_h5e_session*, uint8_t*, size_t, uint16_t);
    int (*decrypt_ts_alloc)(const uint8_t*, size_t, uint8_t**, size_t*, uint16_t);
    void (*free_buf)(void*);
    const char* (*version)(void);
};

CCTV_H5E_KEEP const H5eCAbiAnchor kH5eCAbiAnchor = {
    &cctv_h5e_session_create,
    &cctv_h5e_session_destroy,
    &cctv_h5e_session_reset,
    &cctv_h5e_decrypt_nal,
    &cctv_h5e_decrypt_ts,
    &cctv_h5e_decrypt_ts_alloc,
    &cctv_h5e_free,
    &cctv_h5e_version,
};

}  // namespace

// ===== 程序入口（原样取自 hpp 的 CCTV_H5E_CLI 段） =====
// Windows 走 wmain + _wfopen + UTF-8 输出代码页：文件名与提示都不经过 ACP
// (936/1252/932…) 中转，中文、emoji 在任意系统区域设置下都准确；
// 其他平台保留窄 main（路径按 UTF-8 字节处理）。
#if !defined(CCTV_H5E_NO_CLI)

#if defined(_WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <windows.h>
#endif

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#if !defined(_WIN32)
#  include <unistd.h>  // isatty
#endif

namespace {

// 终端适配：只有 stderr 真的连着终端时才切 UTF-8 代码页并开启 ANSI 转义；
// 重定向到文件/管道时不换代码页、不插转义序列，输出保持纯 UTF-8 文本。
class H5eConsole {
public:
    H5eConsole() {
#if defined(_WIN32)
        HANDLE h = ::GetStdHandle(STD_ERROR_HANDLE);
        DWORD mode = 0;
        if (h && h != INVALID_HANDLE_VALUE && ::GetConsoleMode(h, &mode)) {
            is_tty_ = true;
            saved_cp_ = ::GetConsoleOutputCP();
            if (saved_cp_ != CP_UTF8) ::SetConsoleOutputCP(CP_UTF8);
            saved_mode_ = mode;
            vt_ = ::SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0;
            // 本进程独占这个控制台 => 是双击/快捷方式新开的窗口，退出后会立刻消失
            DWORD pids[2] = {0, 0};
            owns_console_ = ::GetConsoleProcessList(pids, 2) == 1;
        }
#else
        vt_ = ::isatty(::fileno(stderr)) != 0;
#endif
        if (std::getenv("H5E_NO_PAUSE") != nullptr) owns_console_ = false;  // 禁用退出暂停
        if (std::getenv("NO_COLOR") != nullptr) {
            vt_ = false;  // 遵守 NO_COLOR 约定
        } else if (const char* force = std::getenv("CLICOLOR_FORCE")) {
            if (*force && std::strcmp(force, "0") != 0) vt_ = true;  // 管道/CI 里强制上色
        }
    }
    ~H5eConsole() {
#if defined(_WIN32)
        if (is_tty_ && saved_cp_ && saved_cp_ != CP_UTF8)
            ::SetConsoleOutputCP(saved_cp_);
        if (is_tty_ && vt_) {
            HANDLE h = ::GetStdHandle(STD_ERROR_HANDLE);
            if (h && h != INVALID_HANDLE_VALUE) ::SetConsoleMode(h, saved_mode_);
        }
#endif
    }
    bool color() const { return vt_; }
    bool owns_console() const { return owns_console_; }

private:
#if defined(_WIN32)
    bool is_tty_ = false;
    DWORD saved_mode_ = 0;
    UINT saved_cp_ = 0;
#endif
    bool vt_ = false;
    bool owns_console_ = false;
};

// ANSI SGR 上色：未连终端时一律返回空串，调用点不用写分支
struct H5ePainter {
    bool on;
    const char* operator()(const char* sgr) const { return on ? sgr : ""; }
};

constexpr const char* h5e_sgr_plain = "";
constexpr const char* h5e_sgr_reset = "\x1b[0m";
constexpr const char* h5e_sgr_bold = "\x1b[1m";
constexpr const char* h5e_sgr_red = "\x1b[31m";
constexpr const char* h5e_sgr_yellow = "\x1b[33m";
constexpr const char* h5e_sgr_green = "\x1b[32m";
constexpr const char* h5e_sgr_dim = "\x1b[2m";

// 信息行统一格式：“2 空格 + 两个汉字的标签(4 列) + 3 空格 + 正文”，
// 标签固定两个汉字，所以 版本/用法/参数/示例/错误/警告/完成/提示 能纵向对齐。
void h5e_note(const H5ePainter& paint, const char* sgr, const char* label, const char* text) {
    std::fprintf(stderr, "  %s%s%s   %s\n", paint(sgr), label, paint(h5e_sgr_reset), text);
}

// 双击运行时 Windows 会为本进程新建一个控制台，程序一退出窗口就消失，用法和错误
// 根本来不及看。只有“自己独占控制台”时才停一下等回车；从终端、管道、计划任务
// 启动时（控制台里还有别的进程 / 根本没有控制台）不停，H5E_NO_PAUSE=1 可禁用。
struct H5ePauseOnExit {
    const H5eConsole& console;
    const H5ePainter& paint;
    ~H5ePauseOnExit() {
        if (!console.owns_console()) return;
        std::fprintf(stderr, "\n");
        h5e_note(paint, h5e_sgr_dim, "提示", "按回车键退出…");
        std::fflush(stderr);
        int c = 0;
        while ((c = std::getchar()) != '\n' && c != EOF) {
        }
    }
};

// 45,037,092 —— 字节数按千分位排版，长数字不再难读
std::string h5e_group(uint64_t v) {
    const std::string s = std::to_string(v);
    std::string out;
    out.reserve(s.size() + s.size() / 3);
    for (size_t i = 0; i < s.size(); i++) {
        if (i && (s.size() - i) % 3 == 0) out += ',';
        out += s[i];
    }
    return out;
}

// 耗时：用整数毫秒拼成“0.47 秒”，不依赖浮点格式化（结果确定，也无浮点误差）
std::string h5e_seconds(long long ms) {
    char buf[32];
    std::snprintf(buf, sizeof buf, "%lld.%02lld 秒", ms / 1000, ms % 1000 / 10);
    return buf;
}

// 路径类型：Windows 用宽字符串（原生 UTF-16），其他平台用字节串（UTF-8）。
// 这里刻意不用 <filesystem>：单是 path + file_size 就会把 locale/iostream 整套
// facet、异常运行时和 demangler 拉进静态链接，实测多出 880 KB（1.13 MB vs 0.25 MB），
// 而我们需要/只需要“拿着一份路径传给 _wfopen”。
#if defined(_WIN32)
using h5e_path = std::wstring;
#else
using h5e_path = std::string;
#endif

// path -> UTF-8 字节（宽字符直转，emoji 这类代理对也不会被截断）
std::string h5e_path_utf8(const h5e_path& p) {
#if defined(_WIN32)
    if (p.empty()) return {};
    const int need = ::WideCharToMultiByte(CP_UTF8, 0, p.c_str(), (int)p.size(),
                                           nullptr, 0, nullptr, nullptr);
    if (need <= 0) return {};
    std::string s((size_t)need, '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, p.c_str(), (int)p.size(), s.data(), need,
                          nullptr, nullptr);
    return s;
#else
    return p;
#endif
}

// Windows 用 _wfopen 直接给宽路径（绕开 ACP），其他平台用 fopen
std::FILE* h5e_fopen(const h5e_path& p, bool for_write) {
#if defined(_WIN32)
    return ::_wfopen(p.c_str(), for_write ? L"wb" : L"rb");
#else
    return std::fopen(p.c_str(), for_write ? "wb" : "rb");
#endif
}

// 整个文件一次读入（空文件同样返回空向量，与旧实现语义一致）
std::vector<uint8_t> h5e_read_all(const h5e_path& path) {
    std::FILE* f = h5e_fopen(path, false);
    if (!f) return {};
    std::vector<uint8_t> b;
    // 尽力按文件大小预留一次；管道/设备/超大文件上 fseek 会失败，跳过即可
    if (std::fseek(f, 0, SEEK_END) == 0) {
        const long hint = std::ftell(f);
        std::rewind(f);
        if (hint > 0) b.reserve((size_t)hint);
    }
    uint8_t chunk[64 * 1024];
    size_t n = 0;
    while ((n = std::fread(chunk, 1, sizeof chunk, f)) > 0)
        b.insert(b.end(), chunk, chunk + n);
    std::fclose(f);
    return b;
}

// 写文件；close 的返回值也要看——缓冲落盘失败只会在这里暴露
bool h5e_write_all(const h5e_path& path, const uint8_t* data, size_t len) {
    std::FILE* f = h5e_fopen(path, true);
    if (!f) return false;
    bool ok = (len == 0) || (std::fwrite(data, 1, len, f) == len);
    if (std::fclose(f) != 0) ok = false;
    return ok;
}

}  // namespace

#if defined(_WIN32)
int wmain(int argc, wchar_t** argv)
#else
int main(int argc, char** argv)
#endif
{
    const H5eConsole console;                // UTF-8 代码页 + ANSI，仅终端下生效
    const H5ePainter paint{console.color()};
    const H5ePauseOnExit pause_on_exit{console, paint};  // 双击时窗口不一闪而过
    const auto t0 = std::chrono::steady_clock::now();
    const char* ver = cctv_h5e_version();
    const std::string prog = h5e_path_utf8(argv[0]);

    if (argc < 3) {
        h5e_note(paint, h5e_sgr_red, "错误",
                 "参数不足：至少需要 <输入文件.ts> 与 <输出文件.ts> 两个参数");
        std::fprintf(stderr, "\n");
        std::fprintf(stderr, "  %scctv_h5e_decrypt · 纯 C++ hls_h5e TS 解密工具%s\n",
                     paint(h5e_sgr_bold), paint(h5e_sgr_reset));
        std::fprintf(stderr,
                     "  ────────────────────────────────────────────────\n");
        h5e_note(paint, h5e_sgr_plain, "版本", ver);
        h5e_note(paint, h5e_sgr_plain, "用法",
                 (prog + " <输入文件.ts> <输出文件.ts> [--pid 0x100]").c_str());
        h5e_note(paint, h5e_sgr_plain, "参数", "--pid <十六进制>   指定视频 PID，默认 0x100");
        h5e_note(paint, h5e_sgr_plain, "示例", "dec.exe 加密.ts 解密.ts");
        h5e_note(paint, h5e_sgr_plain, "    ", "dec.exe 加密.ts 解密.ts --pid 0x1fff");
        return 1;
    }
    uint16_t vpid = 0x100;
    for (int i = 3; i < argc; i++) {
        if (h5e_path_utf8(argv[i]) != "--pid") continue;
        if (i + 1 >= argc) {
            h5e_note(paint, h5e_sgr_yellow, "警告", "--pid 后缺少取值，已回退到默认 0x100");
            break;
        }
        const std::string val = h5e_path_utf8(argv[++i]);
        char* end = nullptr;
        const unsigned long n = std::strtoul(val.c_str(), &end, 0);
        if (end == val.c_str() || *end != '\0') {
            h5e_note(paint, h5e_sgr_yellow, "警告",
                     ("--pid 取值 \"" + val + "\" 无法解析，已回退到默认 0x100").c_str());
            continue;
        }
        vpid = (uint16_t)n;
        if (n > 0x1FFFu) {
            char msg[160];
            std::snprintf(msg, sizeof msg,
                          "--pid 0x%lX 超出 13 位 PID 范围（0x0000-0x1FFF），不会命中任何分包", n);
            h5e_note(paint, h5e_sgr_yellow, "警告", msg);
        }
    }
    const h5e_path in_path(argv[1]);
    const h5e_path out_path(argv[2]);
    const auto enc = h5e_read_all(in_path);
    if (enc.empty()) {
        h5e_note(paint, h5e_sgr_red, "错误",
                 ("无法读取输入文件：" + h5e_path_utf8(in_path)).c_str());
        h5e_note(paint, h5e_sgr_dim, "提示", "请确认文件存在、不是目录，且当前用户有读取权限");
        return 1;
    }
    uint8_t* out = nullptr;
    size_t out_len = 0;
    const int rc = cctv_h5e_decrypt_ts_alloc(enc.data(), enc.size(), &out, &out_len, vpid);
    if (rc != 0 || !out) {
        char msg[80];
        std::snprintf(msg, sizeof msg, "解密失败（返回码 rc=%d）", rc);
        h5e_note(paint, h5e_sgr_red, "错误", msg);
        return 1;
    }
    if (!h5e_write_all(out_path, out, out_len)) {
        cctv_h5e_free(out);
        h5e_note(paint, h5e_sgr_red, "错误",
                 ("无法写入输出文件：" + h5e_path_utf8(out_path)).c_str());
        h5e_note(paint, h5e_sgr_dim, "提示", "请确认目标目录存在、不是只读，且磁盘空间充足");
        return 1;
    }
    cctv_h5e_free(out);

    const long long ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                             std::chrono::steady_clock::now() - t0)
                             .count();
    char detail[128];
    std::snprintf(detail, sizeof detail, "视频 PID 0x%03X · 耗时 %s", (unsigned)vpid,
                  h5e_seconds(ms).c_str());
    h5e_note(paint, h5e_sgr_green, "完成",
             (h5e_group(out_len) + " 字节 → " + h5e_path_utf8(out_path)).c_str());
    h5e_note(paint, h5e_sgr_dim, "详情", detail);
    return 0;
}
#endif
