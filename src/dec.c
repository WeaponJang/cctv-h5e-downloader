// =============================================================================
// dec.c
// CCTV hls_h5e（新模式）MPEG-TS 解密命令行工具 —— 纯 C23，无第三方依赖
// =============================================================================
//
// 本文件自带一份完整解密引擎（与 cctv_h5e.h 中的实现等价、互不 include）。
// 修改解密逻辑时两处需同步。
//
// 算法移植自 cctv_h5e_decrypt.hpp：
//   - F5/F1 闭式步长；type1 G 变换 + 多族帧头翻转掩码；type5 TEA-16
//   - EPB（00 00 03）网格对齐 + 03 丢弃；classic 网格回退
//   - MPEG-TS PES 重建 + AF 填充
//
// 编译：
//   windres version.rc -O coff -o dec_exe.res -DNDEBUG
//   gcc -std=c23 -Os -s -DNDEBUG -o dec.exe dec.c dec_exe.res -lshell32
//
// 用法：
//   dec.exe <加密.ts> <输出.ts> [--pid 0x100]
//
// 源码为 UTF-8（无 BOM）；命令行用 CommandLineToArgvW 取宽字符，文件用宽字符
// API 读写，因此任意语言版本的 Windows 下中文提示不乱码、中文路径可正常读写。
//
// 仅供研究与逆向工程学习使用，风险自负。
// =============================================================================
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <wchar.h>

#if !defined(_WIN32)
/* 本工具依赖 Windows 宽字符命令行/文件 API。 */
int main(void) {
    fputs("dec.exe 仅支持 Windows\n", stderr);
    return 1;
}
#else

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <shellapi.h> /* CommandLineToArgvW（链接需 -lshell32） */

#define H5E_VERSION "cctv_h5e pure C23 F5/F1+EPB+AF 2.0.0.0"

/* 会话句柄（结构定义见本段末尾） */
typedef struct cctv_h5e_session cctv_h5e_session;

#if defined(__GNUC__) || defined(__clang__)
#  define H5E_UNUSED __attribute__((unused))
#else
#  define H5E_UNUSED
#endif

#define H5E_GRID_TAIL_GUARD 17u   /* 网格单元起点至少要剩这么多字节 */
#define H5E_TYPE1_MIN_LEN   129u  /* type1 低于此长度原样透传（不解密也不丢 EPB） */

/* 与原版 cctv_h5e_decrypt.hpp 保持逐字节一致的两处取样（已实测 30MB 语料 0 字节差）。
 * 与官方 worker（仓库里的 输出测试.ts）相比会差 9422 字节，原因只有两条：
 *   1) EPB 03 丢弃用“按解密前位置无条件丢”，而 worker 仅当两字节仍是 00 00 才丢；
 *   2) type5 尾单元余量按 17 字节卡，worker 实测 11~16 即可进入（故少数 8 字节密文保持未解）。
 * 如需改为 worker 精确行为：把三处 h5e_drop_epb_03 的 false 改为 true，
 * 并把 h5e_decrypt_type5_new 里的 H5E_GRID_TAIL_GUARD 换成 11。 */

/* >>>>>>>>>>>>>>>>>>>>>> ENGINE BEGIN >>>>>>>>>>>>>>>>>>>>>> */

/* ---- TEA-16：小端 32 位字，delta = 0x9E3779B9 ---- */
static H5E_UNUSED void h5e_tea_encrypt_block(uint8_t out[8], const uint8_t in[8],
                                            const uint8_t key[16]) {
    uint32_t v0, v1, k0, k1, k2, k3;
    memcpy(&v0, in, 4);
    memcpy(&v1, in + 4, 4);
    memcpy(&k0, key, 4);
    memcpy(&k1, key + 4, 4);
    memcpy(&k2, key + 8, 4);
    memcpy(&k3, key + 12, 4);
    uint32_t sum = 0;
    const uint32_t delta = 0x9E3779B9u;
    for (int i = 0; i < 16; i++) {
        sum += delta;
        v0 += (((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1));
        v1 += (((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3));
    }
    memcpy(out, &v0, 4);
    memcpy(out + 4, &v1, 4);
}

static void h5e_tea_decrypt_block(uint8_t out[8], const uint8_t in[8], const uint8_t key[16]) {
    uint32_t v0, v1, k0, k1, k2, k3;
    memcpy(&v0, in, 4);
    memcpy(&v1, in + 4, 4);
    memcpy(&k0, key, 4);
    memcpy(&k1, key + 4, 4);
    memcpy(&k2, key + 8, 4);
    memcpy(&k3, key + 12, 4);
    const uint32_t delta = 0x9E3779B9u;
    uint32_t sum = delta * 16u;
    for (int i = 0; i < 16; i++) {
        v1 -= (((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3));
        v0 -= (((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1));
        sum -= delta;
    }
    memcpy(out, &v0, 4);
    memcpy(out + 4, &v1, 4);
}

/* RBSP → EBSP 位置映射（跳过 EPB 的 0x03）。worker 的 key 与网格单元都按 RBSP
 * 编号，因此跨 EPB 的单元/密钥窗口必须经此映射回填到原始 EBSP 偏移。 */
static int h5e_build_rbsp_map(const uint8_t *nal, size_t len, size_t **out_map, size_t *out_n) {
    *out_map = NULL;
    *out_n = 0;
    if (len == 0) return 0;
    size_t *r2e = (size_t *)malloc(len * sizeof(size_t));
    if (!r2e) return -1;
    size_t n = 0;
    for (size_t i = 0; i < len;) {
        if (i + 2 < len && nal[i] == 0 && nal[i + 1] == 0 && nal[i + 2] == 3) {
            r2e[n++] = i;
            r2e[n++] = i + 1;
            i += 3;
        } else {
            r2e[n++] = i;
            i++;
        }
    }
    *out_map = r2e;
    *out_n = n;
    return 0;
}

/* 收集 EPB 位置（00 00 03 的起点）。 */
static int h5e_collect_epb(const uint8_t *nal, size_t len, size_t **out_pos, size_t *out_n) {
    *out_pos = NULL;
    *out_n = 0;
    if (!nal || len < 3) return 0;
    size_t cap = len / 3 + 1;
    size_t *epbs = (size_t *)malloc(cap * sizeof(size_t));
    if (!epbs) return -1;
    size_t n = 0;
    for (size_t i = 0; i + 2 < len; i++) {
        if (nal[i] == 0 && nal[i + 1] == 0 && nal[i + 2] == 3) epbs[n++] = i;
    }
    *out_pos = epbs;
    *out_n = n;
    return 0;
}

/* 按记录位置（从后往前）丢掉 EPB 的 0x03，返回新长度。
 * worker 是按解密前的位置丢：某个单元改写了前两个 00 也照样删第三字节，
 * 故 require_intact=false 才是与 worker 一致的行为。 */
static size_t h5e_drop_epb_03(uint8_t *nal, size_t len, const size_t *epbs, size_t n,
                              bool require_intact) {
    if (!nal) return len;
    size_t nlen = len;
    for (size_t i = n; i-- > 0;) {
        size_t e = epbs[i];
        if (e + 2 >= nlen) continue;
        if (require_intact && !(nal[e] == 0 && nal[e + 1] == 0 && nal[e + 2] == 3)) continue;
        memmove(nal + e + 2, nal + e + 3, nlen - (e + 3));
        nlen--;
    }
    return nlen;
}

/* ---- type5 新模式：key@RBSP[5:21]，start=64，步长 S，EPB 感知 ---- */
static size_t h5e_decrypt_type5_new(uint8_t *nal, size_t len, uint32_t stride) {
    if (!nal || len < 21 || stride < 8) return len;
    size_t *epbs = NULL, *r2e = NULL;
    size_t nep = 0, nr = 0;
    if (h5e_collect_epb(nal, len, &epbs, &nep) != 0) return len;
    if (h5e_build_rbsp_map(nal, len, &r2e, &nr) != 0) {
        free(epbs);
        return len;
    }
    if (nr < 21) {
        free(epbs);
        free(r2e);
        return len;
    }
    /* TEA 密钥在 RBSP[5:21]；该窗口内的 EPB 会挪动原始 EBSP 字节，
     * 直接按 EBSP 取会毁掉所有单元。 */
    uint8_t key[16];
    for (size_t b = 0; b < 16; b++) key[b] = nal[r2e[5 + b]];
    uint8_t tmp[8];
    bool any_cell = false;
    for (size_t k = 0;; k++) {
        size_t o = 64 + k * (size_t)stride;
        if (o + H5E_GRID_TAIL_GUARD > nr || o + 8 > nr) break;
        for (size_t b = 0; b < 8; b++) tmp[b] = nal[r2e[o + b]];
        h5e_tea_decrypt_block(tmp, tmp, key);
        for (size_t b = 0; b < 8; b++) nal[r2e[o + b]] = tmp[b];
        any_cell = true;
    }
    /* EPB 丢弃属于网格处理：一个单元都放不下的 NAL 原样透传。 */
    size_t out_len = len;
    if (nep != 0 && any_cell) out_len = h5e_drop_epb_03(nal, len, epbs, nep, false);
    free(epbs);
    free(r2e);
    return out_len;
}

/* ---- F5 / F1 步长 ---- */
static const uint16_t h5e_type5_f5_base[6] = {160, 192, 224, 256, 288, 320};

/* key16：nal+5 处的 16 字节 TEA 密钥（F5 只用前 6 字节）。 */
static uint32_t h5e_type5_stride_f5(const uint8_t *key16) {
    uint32_t le = (uint32_t)key16[0] | ((uint32_t)key16[1] << 8) |
                  ((uint32_t)key16[2] << 16) | ((uint32_t)key16[3] << 24);
    unsigned idx = (unsigned)(le % 6u);
    return (uint32_t)h5e_type5_f5_base[idx] | (uint32_t)key16[idx];
}

/* 便捷版：直接给 NAL（header+RBSP），需 len >= 21。 */
static uint32_t h5e_type5_stride_from_nal(const uint8_t *nal, size_t len) {
    if (!nal || len < 21) return 0;
    size_t *r2e = NULL;
    size_t nr = 0;
    if (h5e_build_rbsp_map(nal, len, &r2e, &nr) != 0) return 0;
    if (nr < 11) {
        free(r2e);
        return 0;
    }
    uint8_t key[6];
    for (size_t b = 0; b < 6; b++) key[b] = nal[r2e[5 + b]];
    free(r2e);
    return h5e_type5_stride_f5(key);
}

/* type1 F1：BASE/选择与 F5 相同，key = RBSP[1..6]。 */
static uint32_t h5e_type1_stride_from_nal(const uint8_t *nal, size_t len) {
    if (!nal || len < 7) return 0;
    size_t *r2e = NULL;
    size_t nr = 0;
    if (h5e_build_rbsp_map(nal, len, &r2e, &nr) != 0) return 0;
    if (nr < 7) {
        free(r2e);
        return 0;
    }
    uint8_t key[6];
    for (size_t b = 0; b < 6; b++) key[b] = nal[r2e[1 + b]];
    free(r2e);
    return h5e_type5_stride_f5(key);
}

/* ---- type1 G 变换 + 帧头翻转掩码 ---- */
static int h5e_type1_fbit(uint32_t W) {
    const int w0 = (W >> 0) & 1;
    const int w8 = (W >> 8) & 1;
    const int w15 = (W >> 15) & 1;
    const int w19 = (W >> 19) & 1;
    const int w25 = (W >> 25) & 1;
    const int w30 = (W >> 30) & 1;
    const int w31 = (W >> 31) & 1;
    const int t = w0 | w8;
    return (w31 ^ w15 ^ t ^ (w8 & w19) ^ (w25 & (w0 ^ w19)) ^ (w0 & (1 ^ w8) & w30) ^
            ((1 ^ w0) & w19 & w30) ^ (w25 & w30 & (w8 ^ w19))) & 1;
}

static bool h5e_type1_is_B_step(int s) {
    return s == 2 || s == 8 || s == 9 || s == 10;
}

/* 需要翻转 Fbit 的步集合（bit s 置位 = 翻转第 s 步）。 */
static uint16_t h5e_type1_flip_mask_from_header(const uint8_t hdr[3]) {
    const uint8_t b0 = hdr[0], b1 = hdr[1], b2 = hdr[2];
    uint16_t m = 0;
    if (b0 == 0x01 && b1 == 0xA8) {
        if ((b2 >> 7) & 1) m = (uint16_t)(m | (1u << 0));
        if ((b2 >> 6) & 1) m = (uint16_t)(m | (1u << 1));
        if (1 ^ ((b2 >> 5) & 1)) m = (uint16_t)(m | (1u << 2));
        if ((b2 >> 4) & 1) m = (uint16_t)(m | (1u << 3));
        if ((b2 >> 3) & 1) m = (uint16_t)(m | (1u << 4));
        if ((b2 >> 1) & 1) m = (uint16_t)(m | (1u << 6));
        if ((b2 >> 0) & 1) m = (uint16_t)(m | (1u << 7));
        m = (uint16_t)(m | (1u << 9));
        m = (uint16_t)(m | (1u << 12));
        return m;
    }
    if (b0 == 0x61) {
        if ((b2 >> 1) & 1) m = (uint16_t)(m | (1u << 0));
        if ((b2 >> 0) & 1) m = (uint16_t)(m | (1u << 1));
        if (1 ^ ((b2 >> 5) & 1)) m = (uint16_t)(m | (1u << 2));
        if ((b2 >> 3) & 1) m = (uint16_t)(m | (1u << 4));
        if ((b2 >> 2) & 1) m = (uint16_t)(m | (1u << 5));
        if ((b2 >> 1) & 1) m = (uint16_t)(m | (1u << 6));
        if ((b2 >> 0) & 1) m = (uint16_t)(m | (1u << 7));
        if ((b2 >> 3) & 1) m = (uint16_t)(m | (1u << 14));
        if ((b2 >> 2) & 1) m = (uint16_t)(m | (1u << 15));
        return m;
    }
    /* 分片头族：nal_type=1 且 b1 高半字节为 0x9，再按 b1[2] 分两个子族：
     *   9c..9f (b1[2]=1)：s2=b0[0]^b2[5]，s9..s12/s14=b0[0]，s13=1，s15=b1[0]
     *   9a/9b  (b1[2]=0)：s2=~b2[5]，    s9..s12/s14=1，    s13=0，s15=b1[0] */
    if ((b0 & 0x1f) == 1 && (b1 & 0xf0) == 0x90) {
        const int t = (b1 >> 2) & 1;
        if ((b2 >> 7) & 1) m = (uint16_t)(m | (1u << 0));
        if ((b2 >> 6) & 1) m = (uint16_t)(m | (1u << 1));
        int s2 = ((b0 >> 0) & 1) ^ ((b2 >> 5) & 1);
        if (!t) s2 = 1 ^ ((b2 >> 5) & 1);
        if (s2) m = (uint16_t)(m | (1u << 2));
        if ((b2 >> 4) & 1) m = (uint16_t)(m | (1u << 3));
        if ((b2 >> 3) & 1) m = (uint16_t)(m | (1u << 4));
        if ((b2 >> 2) & 1) m = (uint16_t)(m | (1u << 5));
        if ((b2 >> 1) & 1) m = (uint16_t)(m | (1u << 6));
        if ((b2 >> 0) & 1) m = (uint16_t)(m | (1u << 7));
        if (t) {
            if ((b0 >> 0) & 1) {
                m = (uint16_t)(m | (1u << 9) | (1u << 10) | (1u << 11) | (1u << 12) | (1u << 14));
            }
            m = (uint16_t)(m | (1u << 13));
        } else {
            m = (uint16_t)(m | (1u << 9) | (1u << 10) | (1u << 11) | (1u << 12) | (1u << 14));
        }
        if ((b1 >> 0) & 1) m = (uint16_t)(m | (1u << 15));
        return m;
    }
    /* SD 450 档族（`41 88 b2`）：b2[0..2] 驱动 s7/s6/s5，9/10/12 固定置位，s14 恒清零。 */
    if (b0 == 0x41 && b1 == 0x88) {
        if ((b2 >> 7) & 1) m = (uint16_t)(m | (1u << 0));
        if ((b2 >> 6) & 1) m = (uint16_t)(m | (1u << 1));
        if (1 ^ ((b2 >> 5) & 1)) m = (uint16_t)(m | (1u << 2));
        if ((b2 >> 4) & 1) m = (uint16_t)(m | (1u << 3));
        if ((b2 >> 3) & 1) m = (uint16_t)(m | (1u << 4));
        if ((b2 >> 2) & 1) m = (uint16_t)(m | (1u << 5));
        if ((b2 >> 1) & 1) m = (uint16_t)(m | (1u << 6));
        if ((b2 >> 0) & 1) m = (uint16_t)(m | (1u << 7));
        m = (uint16_t)(m | (1u << 9) | (1u << 10) | (1u << 12));
        if ((b1 >> 0) & 1) m = (uint16_t)(m | (1u << 15));
        return m;
    }
    /* 未知族：不翻转（等价于 61e020 核心）。 */
    return 0;
}

static uint16_t h5e_type1_G_flips(uint16_t X, uint16_t Y, uint16_t flip_mask) {
    uint32_t W = (uint32_t)X | ((uint32_t)Y << 16);
    uint16_t P1 = 0;
    for (int s = 0; s < 16; s++) {
        int fv = h5e_type1_fbit(W) ^ ((flip_mask >> s) & 1);
        int b = fv ^ (h5e_type1_is_B_step(s) ? 1 : 0);
        P1 = (uint16_t)(P1 | (b << (15 - s)));
        W = ((W << 1) | (uint32_t)b) & 0xFFFFFFFFu;
    }
    return P1;
}

static void h5e_type1_decrypt_block_nal(uint8_t blk[4], const uint8_t nal_hdr[3]) {
    const uint16_t X = (uint16_t)(blk[0] | (blk[1] << 8));
    const uint16_t Y = (uint16_t)(blk[2] | (blk[3] << 8));
    const uint16_t P1 = h5e_type1_G_flips(X, Y, h5e_type1_flip_mask_from_header(nal_hdr));
    blk[0] = (uint8_t)(P1 & 0xFF);
    blk[1] = (uint8_t)((P1 >> 8) & 0xFF);
    blk[2] = (uint8_t)(X & 0xFF);
    blk[3] = (uint8_t)((X >> 8) & 0xFF);
}

/* ---- type1 新模式网格：start / stride / guard 由会话给出 ---- */
static size_t h5e_decrypt_type1_new(uint8_t *nal, size_t len, uint32_t stride, size_t start,
                                    size_t guard) {
    if (!nal || stride < 4 || len < H5E_TYPE1_MIN_LEN) return len;
    const uint8_t hdr[3] = {nal[0], nal[1], nal[2]};
    size_t *epbs = NULL, *r2e = NULL;
    size_t nep = 0, nr = 0;
    if (h5e_collect_epb(nal, len, &epbs, &nep) != 0) return len;
    if (h5e_build_rbsp_map(nal, len, &r2e, &nr) != 0) {
        free(epbs);
        return len;
    }
    for (size_t k = 0;; k++) {
        size_t o = start + k * (size_t)stride;
        if (o + guard > nr || o + 4 > nr) break;
        uint8_t blk[4] = {nal[r2e[o]], nal[r2e[o + 1]], nal[r2e[o + 2]], nal[r2e[o + 3]]};
        h5e_type1_decrypt_block_nal(blk, hdr);
        nal[r2e[o]] = blk[0];
        nal[r2e[o + 1]] = blk[1];
        nal[r2e[o + 2]] = blk[2];
        nal[r2e[o + 3]] = blk[3];
    }
    size_t out_len = len;
    if (nep != 0) out_len = h5e_drop_epb_03(nal, len, epbs, nep, false);
    free(epbs);
    free(r2e);
    return out_len;
}

/* ---- classic 网格（type25 有 01 06 但没有 01 09）：start=32/stride=80/8 字节 TEA 单元，
 * 密钥 @ RBSP[16:32]；尾单元要求还剩完整一个 stride。 */
static size_t h5e_decrypt_classic_grid(uint8_t *nal, size_t len) {
    if (!nal || len < H5E_TYPE1_MIN_LEN) return len;
    size_t *epbs = NULL, *r2e = NULL;
    size_t nep = 0, nr = 0;
    if (h5e_collect_epb(nal, len, &epbs, &nep) != 0) return len;
    if (h5e_build_rbsp_map(nal, len, &r2e, &nr) != 0) {
        free(epbs);
        return len;
    }
    if (nr < H5E_TYPE1_MIN_LEN) {
        free(epbs);
        free(r2e);
        return len;
    }
    uint8_t key[16];
    for (size_t b = 0; b < 16; b++) key[b] = nal[r2e[16 + b]];
    bool any_cell = false;
    for (size_t k = 0;; k++) {
        size_t o = 32 + k * 80;
        if (o + 80 > nr) break;
        uint8_t blk[8];
        for (size_t b = 0; b < 8; b++) blk[b] = nal[r2e[o + b]];
        h5e_tea_decrypt_block(blk, blk, key);
        for (size_t b = 0; b < 8; b++) nal[r2e[o + b]] = blk[b];
        any_cell = true;
    }
    /* 连一个 classic 单元（32+80）都放不下的 NAL 原样透传：此时丢 EPB 只会让
     * 长度变短却没有解密任何内容。 */
    size_t out_len = len;
    if (nep != 0 && any_cell) out_len = h5e_drop_epb_03(nal, len, epbs, nep, false);
    free(epbs);
    free(r2e);
    return out_len;
}

/* ---- 会话 ---- */
struct cctv_h5e_session {
    bool new_mode;       /* type25 magic 01 09 → 新模式；01 06 → classic */
    bool should_decrypt; /* 播放器层开关：type25 payload[0]==1 */
    size_t type1_start;
    size_t type1_guard;
    size_t type1_min_len;
};

static void h5e_session_init(cctv_h5e_session *s) {
    s->new_mode = false;
    s->should_decrypt = false;
    s->type1_start = 64;
    s->type1_guard = H5E_GRID_TAIL_GUARD;
    s->type1_min_len = H5E_TYPE1_MIN_LEN;
}

static void h5e_session_on_nal(cctv_h5e_session *s, uint8_t *nal, size_t *io_len) {
    if (!s || !nal || !io_len || *io_len < 1) return;
    const size_t len = *io_len;
    const int ntype = nal[0] & 0x1f;
    if (ntype == 25) {
        s->should_decrypt = (len >= 2 && nal[1] == 1);
        /* magic 决定单元布局，并且可以中途双向切换（老流先 01 06 classic，
         * 下个分片切到 01 09 新模式）：01 09 → 新模式网格；01 06 → classic 网格。 */
        if (len >= 4 && nal[2] == 0x01) {
            if (nal[3] == 0x09) s->new_mode = true;
            else if (nal[3] == 0x06) s->new_mode = false;
        }
        return;
    }
    if ((ntype != 1 && ntype != 5) || !s->should_decrypt) return;
    if (!s->new_mode) {
        *io_len = h5e_decrypt_classic_grid(nal, len);
        return;
    }
    if (ntype == 5) {
        uint32_t S = h5e_type5_stride_from_nal(nal, len);
        if (S >= 8) *io_len = h5e_decrypt_type5_new(nal, len, S);
        return;
    }
    if (ntype == 1) {
        if (len < s->type1_min_len) return;
        uint32_t S = h5e_type1_stride_from_nal(nal, len);
        if (S == 0) S = 511u;
        *io_len = h5e_decrypt_type1_new(nal, len, S, s->type1_start, s->type1_guard);
    }
}

/* ---- MPEG-TS ---- */

/* 把一个 TS 包的 AF 撑大、从 payload 里抢 need 字节；返回实际抢到的字节数。 */
static size_t h5e_expand_af_steal(uint8_t *data, size_t len, size_t pkt_off, size_t need) {
    if (!data || need == 0 || pkt_off + 188 > len) return 0;
    int afc = (data[pkt_off + 3] & 0x30) >> 4;
    if (afc == 1) {
        /* 只有 payload → 新建 AF，af_len = need - 1。 */
        if (need < 1) return 0;
        size_t af_len = need - 1;
        if (af_len > 182) af_len = 182;
        size_t steal = 1 + af_len;
        uint8_t old_payload[184];
        memcpy(old_payload, data + pkt_off + 4, 184);
        data[pkt_off + 3] = (uint8_t)((data[pkt_off + 3] & 0xCF) | 0x30); /* afc=3 */
        data[pkt_off + 4] = (uint8_t)af_len;
        if (af_len > 0) {
            data[pkt_off + 5] = 0x00; /* flags */
            for (size_t i = 1; i < af_len; i++) data[pkt_off + 5 + i] = 0xFF;
        }
        size_t new_pl = 184 - steal;
        memcpy(data + pkt_off + 5 + af_len, old_payload, new_pl);
        return steal;
    }
    if (afc == 2 || afc == 3) {
        size_t af_len = data[pkt_off + 4];
        size_t pi = 5 + af_len;
        if (pi >= 188) return 0;
        size_t old_payload_len = 188 - pi;
        size_t add = need < old_payload_len ? need : old_payload_len;
        if (add == 0) return 0;
        if (af_len + add > 182) {
            add = 182 - af_len;
            if (add == 0) return 0;
        }
        size_t new_af_len = af_len + add;
        uint8_t old_payload[184];
        memcpy(old_payload, data + pkt_off + pi, old_payload_len);
        /* 用 0xFF 延长 AF 体 */
        for (size_t i = 0; i < add; i++) data[pkt_off + 5 + af_len + i] = 0xFF;
        data[pkt_off + 4] = (uint8_t)new_af_len;
        size_t new_pl = old_payload_len - add;
        memcpy(data + pkt_off + 5 + new_af_len, old_payload, new_pl);
        if (new_pl == 0) data[pkt_off + 3] = (uint8_t)((data[pkt_off + 3] & 0xCF) | 0x20); /* afc=2 */
        else data[pkt_off + 3] = (uint8_t)((data[pkt_off + 3] & 0xCF) | 0x30);            /* afc=3 */
        return add;
    }
    return 0;
}

typedef struct {
    size_t pkt_off; /* 包在 TS 缓冲内的偏移 */
    size_t pi;      /* 包内 payload 起点 */
    size_t pl;      /* 包内 payload 长度 */
} h5e_span;

typedef struct {
    size_t pos; /* ES 内 start code 位置 */
    size_t sc;  /* start code 长度：3 或 4 */
} h5e_sc;

typedef struct {
    cctv_h5e_session *session;
    uint8_t *pes;      /* 累积的 PES 字节 */
    uint8_t *out;      /* 重建后的 PES */
    h5e_span *spans;
    h5e_sc *starts;
    size_t pes_n, out_n, spans_n, starts_n;
    size_t nal_count;
} h5e_ts_ctx;

/* 处理一个完整 PES：切 NAL → 解密 → 重建 → 回写 TS 各包 payload。 */
static void h5e_flush_pes(uint8_t *data, size_t len, h5e_ts_ctx *ctx) {
    if (ctx->pes_n == 0) return;
    uint8_t *pes = ctx->pes;
    const size_t pes_n = ctx->pes_n;

    size_t base_skip = 0;
    if (pes_n >= 9 && pes[0] == 0 && pes[1] == 0 && pes[2] == 1) base_skip = 9 + pes[8];
    if (base_skip > pes_n) {
        ctx->pes_n = 0;
        ctx->spans_n = 0;
        return;
    }

    memcpy(ctx->out, pes, base_skip); /* PES 头原样保留 */
    size_t out_n = base_skip;

    const size_t es_off = base_skip;
    const size_t es_n = pes_n - es_off;
    const uint8_t *es = pes + es_off;

    /* 扫描 ES 内的 NAL start code（先 4 字节，再 3 字节） */
    size_t ns = 0;
    for (size_t i = 0; i + 3 < es_n;) {
        if (i + 4 <= es_n && es[i] == 0 && es[i + 1] == 0 && es[i + 2] == 0 && es[i + 3] == 1) {
            ctx->starts[ns].pos = i;
            ctx->starts[ns].sc = 4;
            ns++;
            i += 4;
        } else if (es[i] == 0 && es[i + 1] == 0 && es[i + 2] == 1) {
            ctx->starts[ns].pos = i;
            ctx->starts[ns].sc = 3;
            ns++;
            i += 3;
        } else {
            i++;
        }
    }
    ctx->starts_n = ns;

    size_t cursor = 0;
    for (size_t idx = 0; idx < ns; idx++) {
        const size_t pos = ctx->starts[idx].pos;
        const size_t sc = ctx->starts[idx].sc;
        const size_t end = (idx + 1 < ns) ? ctx->starts[idx + 1].pos : es_n;
        if (cursor < pos) {
            memcpy(ctx->out + out_n, es + cursor, pos - cursor);
            out_n += pos - cursor;
        }
        memcpy(ctx->out + out_n, es + pos, sc);
        out_n += sc;
        if (pos + sc >= end) {
            cursor = end;
            continue;
        }
        /* 就地解密：解密只做收缩（丢 EPB 的 03），因此可以直接改 PES 缓冲。 */
        uint8_t *nal = (uint8_t *)es + pos + sc;
        size_t nlen = end - (pos + sc);
        size_t io = nlen;
        h5e_session_on_nal(ctx->session, nal, &io);
        ctx->nal_count++;
        memcpy(ctx->out + out_n, nal, io);
        out_n += io;
        cursor = end;
    }
    if (cursor < es_n) {
        memcpy(ctx->out + out_n, es + cursor, es_n - cursor);
        out_n += es_n - cursor;
    }

    /* 长度缩短 → 从后往前撑 AF 把差额补回来 */
    size_t capacity = 0;
    for (size_t i = 0; i < ctx->spans_n; i++) capacity += ctx->spans[i].pl;
    if (capacity > out_n) {
        size_t remaining = capacity - out_n;
        for (size_t i = ctx->spans_n; i-- > 0 && remaining > 0;) {
            size_t got = h5e_expand_af_steal(data, len, ctx->spans[i].pkt_off, remaining);
            remaining -= got;
        }
        /* AF 变了 → 按包头重算各包 payload 区间 */
        size_t nn = 0;
        for (size_t i = 0; i < ctx->spans_n; i++) {
            const size_t pkt_off = ctx->spans[i].pkt_off;
            int afc = (data[pkt_off + 3] & 0x30) >> 4;
            if (afc == 0 || afc == 2) continue;
            size_t pi = (afc == 1) ? 4 : (size_t)(5 + data[pkt_off + 4]);
            if (pi >= 188) continue;
            ctx->spans[nn].pkt_off = pkt_off;
            ctx->spans[nn].pi = pi;
            ctx->spans[nn].pl = 188 - pi;
            nn++;
        }
        ctx->spans_n = nn;
    }

    size_t off = 0;
    for (size_t i = 0; i < ctx->spans_n; i++) {
        const size_t pkt_off = ctx->spans[i].pkt_off;
        const size_t pi = ctx->spans[i].pi;
        const size_t pl = ctx->spans[i].pl;
        size_t chunk = (off < out_n) ? (out_n - off) : 0;
        if (chunk > pl) chunk = pl;
        if (chunk > 0) memcpy(data + pkt_off + pi, ctx->out + off, chunk);
        if (chunk < pl) {
            /* 残留（AF 吸收不足时才出现）用 0xFF 填满 */
            memset(data + pkt_off + pi + chunk, 0xFF, pl - chunk);
        }
        off += pl;
    }

    ctx->pes_n = 0;
    ctx->spans_n = 0;
    ctx->out_n = 0;
}

/* 原地解密 TS 缓冲中的全部视频 NAL，返回经过会话的 NAL 数。 */
static size_t h5e_decrypt_ts_inplace(uint8_t *data, size_t len, cctv_h5e_session *session,
                                     uint16_t vpid) {
    if (!data || len < 188) return 0;

    h5e_ts_ctx ctx;
    memset(&ctx, 0, sizeof ctx);
    ctx.session = session;
    ctx.pes = (uint8_t *)malloc(len);
    ctx.out = (uint8_t *)malloc(len);
    ctx.spans = (h5e_span *)malloc((len / 188 + 1) * sizeof(h5e_span));
    ctx.starts = (h5e_sc *)malloc((len / 3 + 2) * sizeof(h5e_sc));
    if (!ctx.pes || !ctx.out || !ctx.spans || !ctx.starts) {
        free(ctx.pes);
        free(ctx.out);
        free(ctx.spans);
        free(ctx.starts);
        return 0;
    }

    for (size_t off = 0; off + 188 <= len; off += 188) {
        if (data[off] != 0x47) continue;
        uint16_t pid = (uint16_t)(((data[off + 1] & 0x1f) << 8) | data[off + 2]);
        if (pid != vpid) continue;
        bool pusi = (data[off + 1] & 0x40) != 0;
        int afc = (data[off + 3] & 0x30) >> 4;
        if (afc == 0 || afc == 2) continue;
        size_t pi = (afc == 1) ? 4 : (size_t)(5 + data[off + 4]);
        if (pi >= 188) continue;
        size_t payload_len = 188 - pi;
        if (pusi) h5e_flush_pes(data, len, &ctx);
        memcpy(ctx.pes + ctx.pes_n, data + off + pi, payload_len);
        ctx.pes_n += payload_len;
        ctx.spans[ctx.spans_n].pkt_off = off;
        ctx.spans[ctx.spans_n].pi = pi;
        ctx.spans[ctx.spans_n].pl = payload_len;
        ctx.spans_n++;
    }
    h5e_flush_pes(data, len, &ctx);

    const size_t nal_count = ctx.nal_count;
    free(ctx.pes);
    free(ctx.out);
    free(ctx.spans);
    free(ctx.starts);
    return nal_count;
}

/* <<<<<<<<<<<<<<<<<<<<<< ENGINE END <<<<<<<<<<<<<<<<<<<<<< */

/* ============================ 文件级读写（宽字符） ============================ */

static int dec_read_whole_w(const wchar_t *path, uint8_t **out, size_t *out_len) {
    *out = NULL;
    *out_len = 0;
    if (!path) return -1;
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return -1;
    LARGE_INTEGER sz;
    if (!GetFileSizeEx(h, &sz) || sz.QuadPart < 0) {
        CloseHandle(h);
        return -1;
    }
    const size_t n = (size_t)sz.QuadPart;
    uint8_t *buf = (uint8_t *)malloc(n ? n : 1);
    if (!buf) {
        CloseHandle(h);
        return -1;
    }
    size_t got = 0;
    while (got < n) {
        DWORD want = (DWORD)((n - got) > 0x10000000u ? 0x10000000u : (n - got));
        DWORD read = 0;
        if (!ReadFile(h, buf + got, want, &read, NULL) || read == 0) {
            free(buf);
            CloseHandle(h);
            return -1;
        }
        got += read;
    }
    CloseHandle(h);
    *out = buf;
    *out_len = n;
    return 0;
}

static int dec_write_whole_w(const wchar_t *path, const uint8_t *data, size_t len) {
    if (!path) return -1;
    HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return -1;
    size_t put = 0;
    while (put < len) {
        DWORD want = (DWORD)((len - put) > 0x10000000u ? 0x10000000u : (len - put));
        DWORD wrote = 0;
        if (!WriteFile(h, data + put, want, &wrote, NULL) || wrote == 0) {
            CloseHandle(h);
            return -1;
        }
        put += wrote;
    }
    CloseHandle(h);
    return 0;
}

/* 整文件：读 → 解密 → 写。返回 >=0 为写出字节数；-1 参数错、-2 读失败、-3 解密失败、-4 写失败。 */
static long long dec_decrypt_file_w(const wchar_t *in_path, const wchar_t *out_path, unsigned vpid,
                                    size_t *bytes_written) {
    if (bytes_written) *bytes_written = 0;
    if (!in_path || !out_path) return -1;
    uint8_t *buf = NULL;
    size_t n = 0;
    if (dec_read_whole_w(in_path, &buf, &n) != 0) return -2;
    cctv_h5e_session session;
    h5e_session_init(&session);
    if (n >= 188) h5e_decrypt_ts_inplace(buf, n, &session, (uint16_t)vpid);
    if (n != 0 && dec_write_whole_w(out_path, buf, n) != 0) {
        free(buf);
        return -4;
    }
    free(buf);
    if (bytes_written) *bytes_written = n;
    return (long long)n;
}

/* 宽字符 → UTF-8（用于打印中文路径） */
static char *dec_utf8_from_wide(const wchar_t *w) {
    if (!w) return NULL;
    int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, NULL, 0, NULL, NULL);
    if (n <= 0) return NULL;
    char *s = (char *)malloc((size_t)n);
    if (!s) return NULL;
    if (WideCharToMultiByte(CP_UTF8, 0, w, -1, s, n, NULL, NULL) <= 0) {
        free(s);
        return NULL;
    }
    return s;
}

/* ============================ 命令行入口 ============================ */

int main(void) {
    /* 控制台按 UTF-8 输出，配合 UTF-8 源码字串，中文提示在任何语言版本下都不乱码 */
    SetConsoleOutputCP(CP_UTF8);

    int argc = 0;
    wchar_t **argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv || argc < 3) {
        fprintf(stderr,
                "cctv_h5e_decrypt — 纯 C23 hls_h5e MPEG-TS 解密\n"
                "  %s\n"
                "用法: dec.exe <加密.ts> <输出.ts> [--pid 0x100]\n",
                H5E_VERSION);
        if (argv) LocalFree(argv);
        return 1;
    }

    unsigned vpid = 0x100;
    for (int i = 3; i < argc; i++) {
        if (wcscmp(argv[i], L"--pid") == 0 && i + 1 < argc)
            vpid = (unsigned)wcstoul(argv[++i], NULL, 0);
    }

    size_t written = 0;
    long long rc = dec_decrypt_file_w(argv[1], argv[2], vpid, &written);
    if (rc >= 0) {
        char *out = dec_utf8_from_wide(argv[2]);
        fprintf(stderr, "ok: %zu bytes -> %s (%s)\n", written, out ? out : "?", H5E_VERSION);
        free(out);
        LocalFree(argv);
        return 0;
    }

    const char *msg = "未知错误";
    switch ((int)rc) {
        case -1: msg = "参数错误"; break;
        case -2: msg = "无法读取输入文件"; break;
        case -3: msg = "解密失败"; break;
        case -4: msg = "无法写出输出文件"; break;
        default: break;
    }
    fprintf(stderr, "decrypt failed rc=%lld (%s)\n", rc, msg);
    LocalFree(argv);
    return 1;
}

#endif /* _WIN32 */
