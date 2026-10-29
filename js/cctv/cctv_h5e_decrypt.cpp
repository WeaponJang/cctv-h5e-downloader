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
//   大文件            -> 两遍流式处理：先扫视频 PES 起点当分块边界，再按约 64 MB
//                        分块“读入 → 原地解密 → 追加写 part”；内存峰值只与单块和
//                        分块索引有关（百兆级），不再随文件大小线性增长
//   输出              -> 只写 <输出路径>.part，全部块写完且字节数与输入一致后才
//                        原子替换目标文件；中途失败只删掉 .part，目标文件不动
//   参数不足          -> 错误 + 用法面板，返回 1
//   输入读不到/为空   -> 错误 + 提示，返回 1
//   解密失败          -> 错误 + 提示（不产生半成品），返回 1
//   输出写不了        -> 错误 + 提示，返回 1
//   成功              -> 完成（字节数 → 输出路径）+ 详情（视频 PID、块数、NAL、耗时），返回 0
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
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#if !defined(_WIN32)
#  include <sys/types.h>  // off_t
#  include <unistd.h>     // isatty
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

// ===== 64 位文件定位/取长 =====
// 旧实现用 fseek/ftell（Windows 的 long 只有 32 位），超过 2 GB 的输入连长度都
// 取不到；分块必须能按偏移随机定位，所以统一走 64 位接口。
int64_t h5e_file_size(std::FILE* f) {
#if defined(_WIN32)
    if (::_fseeki64(f, 0, SEEK_END) != 0) return -1;
    const int64_t n = ::_ftelli64(f);
    if (::_fseeki64(f, 0, SEEK_SET) != 0) return -1;
    return n;
#else
    if (::fseeko(f, 0, SEEK_END) != 0) return -1;
    const int64_t n = (int64_t)::ftello(f);
    if (::fseeko(f, 0, SEEK_SET) != 0) return -1;
    return n;
#endif
}

bool h5e_seek(std::FILE* f, int64_t off) {
#if defined(_WIN32)
    return ::_fseeki64(f, off, SEEK_SET) == 0;
#else
    return ::fseeko(f, (off_t)off, SEEK_SET) == 0;
#endif
}

// 分阶段输出：part 与目标同目录，最后的替换才是同卷 rename
h5e_path h5e_part_path(const h5e_path& out) {
#if defined(_WIN32)
    return out + L".part";
#else
    return out + ".part";
#endif
}

bool h5e_remove(const h5e_path& p) {
#if defined(_WIN32)
    return ::_wremove(p.c_str()) == 0;
#else
    return std::remove(p.c_str()) == 0;
#endif
}

// 原子替换：part 已经完整落盘（长度校验过）后才调用；失败时目标保持原样。
// rename 在同一卷内是原子的，而 part 就建在目标所在目录，天然满足同卷。
bool h5e_replace(const h5e_path& part, const h5e_path& dst) {
#if defined(_WIN32)
    return ::MoveFileExW(part.c_str(), dst.c_str(),
                         MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != 0;
#else
    return std::rename(part.c_str(), dst.c_str()) == 0;
#endif
}

// ===== 分块解密 =====
// 阶段返回码：0 成功，负数是失败发生在哪一步（用来选提示文案）
enum {
    kH5eStageOk = 0,
    kH5eStageRead = -1,
    kH5eStageWrite = -2,
    kH5eStageDecrypt = -3,
};

struct H5eDecryptStats {
    uint64_t bytes = 0;    // 已写出的字节数
    uint64_t nals = 0;     // 交给解密器的 NAL 数
    uint64_t chunks = 0;   // 分块数
};

// 视频 PES 起点（PID 命中且 PUSI 置位）。分块只能切在这里：切在包中间或 PES
// 中间，解密器会拿到半截 PES，输出就和“整文件一次处理”不一致了。
// 顺序读一遍，索引只存 64 位偏移（每帧 8 字节），扫描缓冲固定 1.5 MB 左右。
std::vector<int64_t> h5e_scan_pes_starts(std::FILE* f, uint16_t vpid, bool* read_ok) {
    constexpr size_t kBlock = 188 * 8192;  // 188 的整数倍，缓冲里始终是整包
    std::vector<int64_t> starts;
    std::vector<uint8_t> buf(kBlock);
    size_t have = 0;
    int64_t base = 0;  // buf[0] 在文件里的绝对偏移
    if (read_ok) *read_ok = true;
    for (;;) {
        const size_t got = std::fread(buf.data() + have, 1, kBlock - have, f);
        if (got == 0) {
            if (read_ok && std::ferror(f)) *read_ok = false;
            break;
        }
        have += got;
        const size_t pkts = have / 188;
        for (size_t i = 0; i < pkts; i++) {
            const uint8_t* p = buf.data() + i * 188;
            if (p[0] != 0x47) continue;                        // 失步包直接跳过
            if ((((p[1] & 0x1F) << 8) | p[2]) != vpid) continue;
            if ((p[1] & 0x40) == 0) continue;                  // 不是 PES 起点
            starts.push_back(base + (int64_t)(i * 188));
        }
        const size_t used = pkts * 188;
        have -= used;
        std::memmove(buf.data(), buf.data() + used, have);
        base += (int64_t)used;
    }
    return starts;  // 文件尾不足 188 字节的残包凑不成包，只能丢弃
}

// 按 PES 边界分块解密：每块“读入 → 原地解密 → 追加写 part”，
// Session 全程复用（type25 决定 new_mode，丢掉它后面所有块都解不动）。
// 内存 = 单块（约 64 MB，遇到跨块的超长 PES 会更大）+ 分块索引。
int h5e_decrypt_stream(std::FILE* in, std::FILE* out, int64_t total,
                       const std::vector<int64_t>& pes_starts, uint16_t vpid,
                       H5eDecryptStats* st) {
    constexpr int64_t kChunkBytes = 64LL << 20;
    cctv_h5e_session* s = cctv_h5e_session_create();
    if (!s) return kH5eStageDecrypt;
    std::vector<uint8_t> chunk;
    chunk.reserve((size_t)kChunkBytes);
    int stage = kH5eStageOk;
    size_t next = 0;    // pes_starts 游标，只增不减
    int64_t begin = 0;  // 本块起点：首块 0，之后都是 PES 起点
    while (begin < total) {
        const int64_t want = begin + kChunkBytes;
        while (next < pes_starts.size() && pes_starts[next] < want) next++;
        const int64_t end = next < pes_starts.size() ? pes_starts[next] : total;
        const size_t len = (size_t)(end - begin);
        chunk.resize(len);
        if (!h5e_seek(in, begin) || std::fread(chunk.data(), 1, len, in) != len) {
            stage = kH5eStageRead;
            break;
        }
        // 原地解密：长度由 AF 填充吸收，块内字节数不变
        const int nals = cctv_h5e_decrypt_ts(s, chunk.data(), len, vpid);
        if (nals < 0) {
            stage = kH5eStageDecrypt;
            break;
        }
        if (std::fwrite(chunk.data(), 1, len, out) != len) {
            stage = kH5eStageWrite;
            break;
        }
        if (st) {
            st->bytes += len;
            st->nals += (uint64_t)nals;
            st->chunks++;
        }
        begin = end;
    }
    cctv_h5e_session_destroy(s);
    return stage;
}

// 没有任何视频 PES：解密器不会改动一个字节，按固定块原样搬运即可——
// 结果与旧行为（输出等于输入）一致，又不会把整个文件读进内存。
int h5e_copy_stream(std::FILE* in, std::FILE* out, int64_t total, H5eDecryptStats* st) {
    constexpr int64_t kBlock = 1LL << 20;
    std::vector<uint8_t> buf((size_t)kBlock);
    if (!h5e_seek(in, 0)) return kH5eStageRead;
    for (int64_t done = 0; done < total;) {
        const int64_t left = total - done;
        const size_t want = (size_t)(left < kBlock ? left : kBlock);
        if (std::fread(buf.data(), 1, want, in) != want) return kH5eStageRead;
        if (std::fwrite(buf.data(), 1, want, out) != want) return kH5eStageWrite;
        done += (int64_t)want;
        if (st) {
            st->bytes += want;
            st->chunks++;
        }
    }
    return kH5eStageOk;
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
        h5e_note(paint, h5e_sgr_plain, "    ", "dec.exe 加密.ts 解密.ts --pid 0x100");
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
    const h5e_path part_path = h5e_part_path(out_path);

    std::FILE* fin = h5e_fopen(in_path, false);
    const int64_t in_size = fin ? h5e_file_size(fin) : -1;
    if (!fin || in_size < 0) {
        if (fin) std::fclose(fin);
        h5e_note(paint, h5e_sgr_red, "错误",
                 ("无法读取输入文件：" + h5e_path_utf8(in_path)).c_str());
        h5e_note(paint, h5e_sgr_dim, "提示", "请确认文件存在、不是目录，且当前用户有读取权限");
        return 1;
    }
    if (in_size == 0) {
        std::fclose(fin);
        h5e_note(paint, h5e_sgr_red, "错误",
                 ("输入文件为空：" + h5e_path_utf8(in_path)).c_str());
        h5e_note(paint, h5e_sgr_dim, "提示", "请确认拿到的是完整的加密 TS，而不是还没下载完的空壳");
        return 1;
    }

    // 先扫一遍视频 PES 起点当分块边界（顺序读，只存偏移）
    bool scan_ok = true;
    const std::vector<int64_t> pes_starts = h5e_scan_pes_starts(fin, vpid, &scan_ok);
    if (!scan_ok) {
        std::fclose(fin);
        h5e_note(paint, h5e_sgr_red, "错误",
                 ("读取输入文件失败：" + h5e_path_utf8(in_path)).c_str());
        h5e_note(paint, h5e_sgr_dim, "提示", "请确认文件没有被截断或占用，磁盘可以正常读取");
        return 1;
    }

    // 全程只写 part：目标文件在成功前一个字节都不动
    std::FILE* fpart = h5e_fopen(part_path, true);
    if (!fpart) {
        std::fclose(fin);
        h5e_note(paint, h5e_sgr_red, "错误",
                 ("无法写入输出文件：" + h5e_path_utf8(part_path)).c_str());
        h5e_note(paint, h5e_sgr_dim, "提示", "请确认目标目录存在、不是只读，且磁盘空间充足");
        return 1;
    }

    H5eDecryptStats stats;
    int stage = pes_starts.empty()
                    ? h5e_copy_stream(fin, fpart, in_size, &stats)
                    : h5e_decrypt_stream(fin, fpart, in_size, pes_starts, vpid, &stats);
    // close 的返回值也要看——缓冲落盘失败只会在这里暴露
    const bool flushed = (std::fclose(fpart) == 0);
    std::fclose(fin);  // 先放开输入：<输入> 与 <输出> 是同一个文件时才能替掉
    if (stage == kH5eStageOk && !flushed) stage = kH5eStageWrite;

    if (stage != kH5eStageOk) {
        h5e_remove(part_path);
        if (stage == kH5eStageRead) {
            h5e_note(paint, h5e_sgr_red, "错误",
                     ("读取输入文件失败：" + h5e_path_utf8(in_path)).c_str());
            h5e_note(paint, h5e_sgr_dim, "提示", "请确认文件没有被截断或占用，磁盘可以正常读取");
        } else if (stage == kH5eStageWrite) {
            h5e_note(paint, h5e_sgr_red, "错误",
                     ("无法写入输出文件：" + h5e_path_utf8(part_path)).c_str());
            h5e_note(paint, h5e_sgr_dim, "提示", "临时文件已删除，目标文件未被改动；请检查磁盘空间与目录权限");
        } else {
            h5e_note(paint, h5e_sgr_red, "错误", "解密失败（原生 h5e 返回异常）");
            h5e_note(paint, h5e_sgr_dim, "提示", "请确认输入确实是 hls_h5e 加密的 TS，且 --pid 指向视频流");
        }
        return 1;
    }
    if (stats.bytes != (uint64_t)in_size) {
        h5e_remove(part_path);
        char msg[128];
        std::snprintf(msg, sizeof msg, "解密结果长度异常（%llu / %llu 字节）",
                      (unsigned long long)stats.bytes, (unsigned long long)in_size);
        h5e_note(paint, h5e_sgr_red, "错误", msg);
        h5e_note(paint, h5e_sgr_dim, "提示", "临时文件已删除，目标文件未被改动");
        return 1;
    }

    // 只有到这里才动目标文件：同目录 rename，失败时目标保持原样
    if (!h5e_replace(part_path, out_path)) {
        std::string msg = "无法替换输出文件";
#if defined(_WIN32)
        msg += "（Win32 错误 " + std::to_string((unsigned long)::GetLastError()) + "）";
#endif
        msg += "：";
        msg += h5e_path_utf8(out_path);
        h5e_remove(part_path);
        h5e_note(paint, h5e_sgr_red, "错误", msg.c_str());
        h5e_note(paint, h5e_sgr_dim, "提示",
                 "临时文件已删除，目标文件未被改动；请确认目标没有被其他程序占用、目录可写");
        return 1;
    }

    const long long ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                             std::chrono::steady_clock::now() - t0)
                             .count();
    char detail[160];
    std::snprintf(detail, sizeof detail, "视频 PID 0x%03X · %llu 块 · %llu NAL · 耗时 %s",
                  (unsigned)vpid, (unsigned long long)stats.chunks,
                  (unsigned long long)stats.nals, h5e_seconds(ms).c_str());
    h5e_note(paint, h5e_sgr_green, "完成",
             (h5e_group(stats.bytes) + " 字节 → " + h5e_path_utf8(out_path)).c_str());
    h5e_note(paint, h5e_sgr_dim, "详情", detail);
    if (pes_starts.empty()) {
        char warn[160];
        std::snprintf(warn, sizeof warn,
                      "未找到视频 PES（PID 0x%03X），输入已原样复制，未解密任何 NAL",
                      (unsigned)vpid);
        h5e_note(paint, h5e_sgr_dim, "提示", warn);
    }
    return 0;
}
#endif
