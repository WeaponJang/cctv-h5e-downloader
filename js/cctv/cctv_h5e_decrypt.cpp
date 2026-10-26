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
// 行为说明（与 hpp 内 CLI 完全一致）:
//   参数不足          -> 打印 usage，返回 1
//   输入读不到/为空   -> "cannot read <in>"，返回 1
//   解密失败          -> "decrypt failed rc=<n>"，返回 1
//   输出写不了        -> "cannot write <out>"，返回 1
//   成功              -> stderr 打印 "ok: <n> bytes -> <out> (<ver>)"，返回 0
// =============================================================================

#define CCTV_H5E_IMPLEMENTATION
#include "cctv_h5e_decrypt.hpp"

#include <fstream>

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

// 整个文件一次读入（与 hpp 内 h5e_read_all 等价，空文件同样返回空向量）。
std::vector<uint8_t> h5e_read_all(const char* path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return {};
    f.seekg(0, std::ios::end);
    std::streamoff n = f.tellg();
    f.seekg(0);
    if (n <= 0) return {};
    std::vector<uint8_t> b((size_t)n);
    f.read(reinterpret_cast<char*>(b.data()), n);
    return b;
}

}  // namespace

// ===== 程序入口（原样取自 hpp 的 CCTV_H5E_CLI 段） =====
#if !defined(CCTV_H5E_NO_CLI)
int main(int argc, char** argv) {
    const char* ver = cctv_h5e_version();
    if (argc < 3) {
        std::fprintf(stderr,
            "cctv_h5e_decrypt — pure C++ hls_h5e TS decrypt\n"
            "  %s\n"
            "Usage: %s <enc.ts> <out.ts> [--pid 0x100]\n",
            ver, argv[0]);
        return 1;
    }
    uint16_t vpid = 0x100;
    for (int i = 3; i < argc; i++) {
        if (std::string(argv[i]) == "--pid" && i + 1 < argc)
            vpid = (uint16_t)std::strtoul(argv[++i], nullptr, 0);
    }
    auto enc = h5e_read_all(argv[1]);
    if (enc.empty()) {
        std::fprintf(stderr, "cannot read %s\n", argv[1]);
        return 1;
    }
    uint8_t* out = nullptr;
    size_t out_len = 0;
    int rc = cctv_h5e_decrypt_ts_alloc(enc.data(), enc.size(), &out, &out_len, vpid);
    if (rc != 0 || !out) {
        std::fprintf(stderr, "decrypt failed rc=%d\n", rc);
        return 1;
    }
    std::ofstream of(argv[2], std::ios::binary);
    if (!of) {
        cctv_h5e_free(out);
        std::fprintf(stderr, "cannot write %s\n", argv[2]);
        return 1;
    }
    of.write(reinterpret_cast<char*>(out), (std::streamsize)out_len);
    cctv_h5e_free(out);
    std::fprintf(stderr, "ok: %zu bytes -> %s (%s)\n", out_len, argv[2], ver);
    return 0;
}
#endif
