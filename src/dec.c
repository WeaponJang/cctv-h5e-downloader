/* ============================================================================
 * dec_opt.c —— dec.c 的字节等价优化版（CCTV hls_h5e 新模式 MPEG-TS 解密 CLI）
 * ============================================================================
 *
 * 与 dec.c 的关系：本文件是 dec.c 的字节级等价优化实现——对任意输入 TS，解密
 * 输出与 dec.c 逐字节相同；命令行参数、返回码、stderr 文案、<输出>.part +
 * 原子替换语义、分块与 PES 对齐规则、所有错误路径也全部一致。
 * dec.c 保留作为基准参照实现，两者修改解密算法时必须同步。
 *
 * 用法：dec_opt.exe <加密.ts> <输出.ts> [--pid 0x100]
 * 编译：gcc -std=c23 -Os -s -flto -ffunction-sections -fdata-sections
 *              -Wl,--gc-sections -DNDEBUG -o dec_opt.exe dec_opt.c -lshell32
 *
 * 内存：切点取视频 PES 起点，峰值内存与文件总大小无关（目标 32MB/块）。
 * 安全：输出先写 <输出>.part，成功后才原子替换；失败不动目标、不动输入。
 * ========================================================================== */
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <wchar.h>

#if !defined(_WIN32)
/* 非 Windows 平台没有宽字符命令行/文件 API，直接提示退出 */
int main(void) {
    fputs("dec_opt.exe 仅支持 Windows\n", stderr);
    return 1;
}
#else

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <shellapi.h> /* CommandLineToArgvW：取宽字符命令行，链接需 -lshell32 */

#define H5E_VERSION "cctv_h5e pure C23 F5/F1+EPB+AF 2.0.0.0"

/* 会话句柄：状态结构定义见引擎段末尾 */
typedef struct cctv_h5e_session cctv_h5e_session;

#if defined(__GNUC__) || defined(__clang__)
#  define H5E_UNUSED __attribute__((unused))
#else
#  define H5E_UNUSED
#endif

#define H5E_GRID_TAIL_GUARD 17u   /* 网格单元起点处至少要剩余这么多字节（跟随播放器判定） */
#define H5E_TYPE1_MIN_LEN   129u  /* 短于该长度的 type1 原样透传（不网格解密、不丢 EPB） */

/* 解析密钥窗口时的有界前缀长度：只需覆盖 RBSP[0..31] 对应的 EBSP 字节。
 * 最坏情况（00 00 03 反复）下第 31 个 RBSP 字节落在偏移 48 之前，64 留足余量。 */
#define H5E_PREFIX_WINDOW   64u


/* ============================ 解密引擎开始 ============================ */

/* TEA-16：8 字节分组、小端 32 位字、delta = 0x9E3779B9、16 轮。
 * 加密版只在自查时用来验证解密，CLI 路径不调用。 */
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

/* TEA-16 解密：轮序与轮数和加密一致，sum 从 delta*16 递减回 0。 */
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

/* 收集 NAL 中所有 EPB（00 00 03）的起点偏移，供网格解密后统一丢弃 0x03。
 * 用 memchr 批量找 0x00（内部是字宽/SIMD 实现），再验证后两个字节；
 * 命中后跳 3 字节——00 00 03 的第二、三个字节不可能再是 EPB 起点。
 * 返回 0 成功；-1 为内存不足。 */
static int h5e_collect_epb(const uint8_t *nal, size_t len, size_t **out_pos, size_t *out_n) {
    *out_pos = NULL;
    *out_n = 0;
    if (!nal || len < 3) return 0;
    size_t cap = len / 3 + 1;
    size_t *epbs = (size_t *)malloc(cap * sizeof(size_t));
    if (!epbs) return -1;
    size_t n = 0;
    size_t i = 0;
    const size_t limit = len - 2; /* 候选起点 i 必须满足 i + 2 < len */
    while (i < limit) {
        const uint8_t *p = (const uint8_t *)memchr(nal + i, 0, limit - i);
        if (!p) break;
        size_t e = (size_t)(p - nal);
        if (nal[e + 1] == 0 && nal[e + 2] == 3) {
            epbs[n++] = e;
            i = e + 3;
        } else {
            i = e + 1;
        }
    }
    *out_pos = epbs;
    *out_n = n;
    return 0;
}

/* 按记录好的位置丢掉 EPB 的第三个字节 0x03，返回删除后的长度。
 * 删掉的字节集合与 dec.c 一致（每个 epbs[i] + 2），只是把逆序逐次 memmove 换成
 * 前向按段批量搬运：读游标 r 到下一个删除点之间的整段一次搬完，整体 O(n)。
 * dec.c 的 require_intact 恒为 false（播放器按解密前的位置盲删），故不再保留。 */
static size_t h5e_drop_epb_03(uint8_t *nal, size_t len, const size_t *epbs, size_t n) {
    if (!nal || n == 0) return len;
    size_t w = 0; /* 写游标 */
    size_t r = 0; /* 读游标（未搬运的起点） */
    for (size_t i = 0; i < n; i++) {
        const size_t del = epbs[i] + 2;
        if (del >= len) continue; /* 与 dec.c 的 "e + 2 >= nlen" 保护对应（实际不可达） */
        if (del < r) continue;    /* 防御：EPB 间距 >= 3，实际不会触发 */
        memmove(nal + w, nal + r, del - r);
        w += del - r;
        r = del + 1;
    }
    if (r < len) {
        memmove(nal + w, nal + r, len - r);
        w += len - r;
    }
    return w;
}

/* RBSP 下标 → EBSP 偏移（取代 dec.c 的 r2e[] 整表）。
 * 游标 k 只前进不回退：k = max{ m : epbs[m] + 2 - m <= r }，则 e = r + k。
 * epbs 严格升序且间距 >= 3，该式对 k 单调，所以线性推进就能拿到最大值，
 * 结果与 dec.c 的 r2e[r] 逐值相同。 */
typedef struct {
    const size_t *epbs; /* 升序 EPB 起点（EBSP 坐标） */
    size_t nep;
    size_t k; /* 已越过的 EPB 数 */
} h5e_rbsp_map;

static void h5e_rbsp_map_init(h5e_rbsp_map *m, const size_t *epbs, size_t nep) {
    m->epbs = epbs;
    m->nep = nep;
    m->k = 0;
}

/* 前置条件：调用方保证 r 单调不减，且 r < nr（RBSP 总长）。 */
static size_t h5e_rbsp_at(h5e_rbsp_map *m, size_t r) {
    while (m->k < m->nep && m->epbs[m->k] + 2 - m->k <= r) m->k++;
    return r + m->k;
}

/* 有界前缀解析：把 RBSP[start .. start+n) 的字节取到 out，只看前 64 字节。
 * 返回 0 成功；1 表示窗口内确定不了（调用方须回退到 h5e_gather_rbsp_full）。
 * EPB 的前两个 0x00 仍算 RBSP 字节，只跳过第三个字节 0x03——
 * 即 dec.c 里“先填 i、i+1，再 i += 3”的等价写法。 */
static int h5e_gather_rbsp_prefix(const uint8_t *nal, size_t len, size_t start, uint8_t *out,
                                  size_t n) {
    const size_t wlen = (len < (size_t)H5E_PREFIX_WINDOW) ? len : (size_t)H5E_PREFIX_WINDOW;
    size_t r = 0, e = 0, got = 0;
    while (e < wlen && got < n) {
        if (e + 2 < wlen && nal[e] == 0 && nal[e + 1] == 0 && nal[e + 2] == 3) {
            for (int t = 0; t < 2 && got < n; t++) {
                if (r >= start) out[got++] = nal[e + t];
                r++;
            }
            e += 3; /* 跳过 EPB 的 03：RBSP 下标不前进 */
            continue;
        }
        if (r >= start) out[got++] = nal[e];
        r++;
        e++;
    }
    return (got == n) ? 0 : 1;
}

/* 全量回退路径：结果与 dec.c 的 r2e[] 完全等价，只在前缀窗口不够时才走。
 * 返回 0 成功；1 表示下标越界或内存不足（对应 dec.c 返回 0 的情形）。 */
static int h5e_gather_rbsp_full(const uint8_t *nal, size_t len, size_t start, uint8_t *out,
                                size_t n) {
    size_t *epbs = NULL, nep = 0;
    if (h5e_collect_epb(nal, len, &epbs, &nep) != 0) return 1;
    const size_t nr = len - nep;
    if (start + n > nr) {
        free(epbs);
        return 1;
    }
    h5e_rbsp_map m;
    h5e_rbsp_map_init(&m, epbs, nep);
    for (size_t b = 0; b < n; b++) out[b] = nal[h5e_rbsp_at(&m, start + b)];
    free(epbs);
    return 0;
}

/* 步长闭式解：直接由密钥字节算出网格间隔，不做查表拟合 */
static const uint16_t h5e_type5_f5_base[6] = {160, 192, 224, 256, 288, 320};

/* F5 步长：把密钥前 4 字节当小端 32 位数，模 6 选中 BASE 档位，
 * 再或上同下标的密钥字节——所以间隔总是落在 160..320 这 6 个档位里。
 * key16 只需前 6 字节有效。 */
static uint32_t h5e_type5_stride_f5(const uint8_t *key16) {
    uint32_t le = (uint32_t)key16[0] | ((uint32_t)key16[1] << 8) |
                  ((uint32_t)key16[2] << 16) | ((uint32_t)key16[3] << 24);
    unsigned idx = (unsigned)(le % 6u);
    return (uint32_t)h5e_type5_f5_base[idx] | (uint32_t)key16[idx];
}

/* 从 type5 NAL 取密钥（RBSP[5:11] 共 6 字节）算 F5 步长。
 * 只读 6 字节，因此先走有界前缀，窗口不够时回退全量；
 * 两条路径取到的字节相同，步长自然相同。取不到时返回 0。 */
static uint32_t h5e_type5_stride_from_nal(const uint8_t *nal, size_t len) {
    if (!nal || len < 21) return 0;
    uint8_t key[6];
    if (h5e_gather_rbsp_prefix(nal, len, 5, key, 6) != 0 &&
        h5e_gather_rbsp_full(nal, len, 5, key, 6) != 0) {
        return 0; /* 对应 dec.c 的 nr < 11 或建表失败 */
    }
    return h5e_type5_stride_f5(key);
}

/* type1 的 F1 步长：档位选择规则与 F5 相同，只是密钥改成 RBSP[1:7]。 */
static uint32_t h5e_type1_stride_from_nal(const uint8_t *nal, size_t len) {
    if (!nal || len < 7) return 0;
    uint8_t key[6];
    if (h5e_gather_rbsp_prefix(nal, len, 1, key, 6) != 0 &&
        h5e_gather_rbsp_full(nal, len, 1, key, 6) != 0) {
        return 0; /* 对应 dec.c 的 nr < 7 或建表失败 */
    }
    return h5e_type5_stride_f5(key);
}

/* type1 的 G 变换：16 步移位寄存器运算，每步由 fbit 反馈产生一个输出位；
 * 帧头所属的“族”决定其中若干步的反馈位要取反（翻转掩码）。 */
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

/* 按 NAL 帧头 3 字节判定所属族，返回翻转掩码（bit s = 1 表示第 s 步的反馈位取反）。
 * 已知族：01 a8 xx、61 xx xx、分片头 0x9c..0x9f、分片头 0x9a/0x9b、41 88 xx；
 * 未知族返回 0（退化为最朴素的 61e020 核心）。 */
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
     *   9c..9f（b1[2]=1）：s2 = b0[0]^b2[5]，s9..s12/s14 = b0[0]，s13 = 1，s15 = b1[0]
     *   9a/9b（b1[2]=0）：s2 = ~b2[5]，   s9..s12/s14 = 1，   s13 = 0，s15 = b1[0] */
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
    /* SD 450 档族（帧头 41 88 b2）：b2 各位置位依次对应 s0..s7，其中 s2 取反；
     * 9/10/12 固定置位，s14 永远清零。 */
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
    /* 未知帧头族：不翻转任何步 */
    return 0;
}

/* G 变换主体：W = Y:X 拼成 32 位寄存器，跑 16 步。
 * 每步输出位 = fbit ^ 翻转位 ^（该步属于 B 步集合时再取反），
 * 输出按 s=0 对应最高位拼成 P1，寄存器左移并把输出位回填。
 * X/Y 是小端读出的两个 16 位单元，P1 即解密后的前 2 字节。 */
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

/* type1 新模式网格：起始下标、间隔、尾部余量都由会话给出（默认 64 / F1 步长 / 17）。
 * 单元只 4 字节，尾部仍要求留足 guard 字节；字节一律经映射表按 RBSP 取。
 * 与 type5 的差别：只要存在 EPB 就丢 03，不看有没有解过单元。
 * 返回处理后的 NAL 长度。 */
static size_t h5e_decrypt_type1_new(uint8_t *nal, size_t len, uint32_t stride, size_t start,
                                    size_t guard) {
    if (!nal || stride < 4 || len < H5E_TYPE1_MIN_LEN) return len;
    /* 帧头在循环前快照，翻转掩码是它的纯函数，提出来只算一次；
     * 没有任何单元能写到 RBSP[0..2]（start >= 32），所以提前算安全。 */
    const uint8_t hdr[3] = {nal[0], nal[1], nal[2]};
    const uint16_t flip_mask = h5e_type1_flip_mask_from_header(hdr);
    size_t *epbs = NULL, nep = 0;
    if (h5e_collect_epb(nal, len, &epbs, &nep) != 0) return len;
    const size_t nr = len - nep; /* 与 dec.c 的 nr 完全相同 */
    h5e_rbsp_map m;
    h5e_rbsp_map_init(&m, epbs, nep);
    for (size_t k = 0;; k++) {
        const size_t o = start + k * (size_t)stride;
        if (o + guard > nr || o + 4 > nr) break;
        size_t off[4];
        for (size_t b = 0; b < 4; b++) off[b] = h5e_rbsp_at(&m, o + b);
        const uint16_t X = (uint16_t)(nal[off[0]] | (nal[off[1]] << 8));
        const uint16_t Y = (uint16_t)(nal[off[2]] | (nal[off[3]] << 8));
        const uint16_t P1 = h5e_type1_G_flips(X, Y, flip_mask);
        nal[off[0]] = (uint8_t)(P1 & 0xFF);
        nal[off[1]] = (uint8_t)((P1 >> 8) & 0xFF);
        nal[off[2]] = (uint8_t)(X & 0xFF);
        nal[off[3]] = (uint8_t)((X >> 8) & 0xFF);
    }
    /* type1 与 type5/classic 不对称：只要存在 EPB 就丢，没有“至少解过一个单元”的条件。 */
    size_t out_len = len;
    if (nep != 0) out_len = h5e_drop_epb_03(nal, len, epbs, nep);
    free(epbs);
    return out_len;
}

/* type5 新模式网格：TEA 密钥取 RBSP[5:21]，单元从 RBSP[64] 开始、间隔 stride，
 * 每个单元 8 字节。密钥与单元都按 RBSP 编号，因此 EPB 必须靠映射表换算。
 * 至少解过一个单元才丢 EPB 03。返回处理后的 NAL 长度。 */
static size_t h5e_decrypt_type5_new(uint8_t *nal, size_t len, uint32_t stride) {
    if (!nal || len < 21 || stride < 8) return len;
    size_t *epbs = NULL, nep = 0;
    if (h5e_collect_epb(nal, len, &epbs, &nep) != 0) return len;
    const size_t nr = len - nep;
    if (nr < 21) {
        free(epbs);
        return len;
    }
    /* 密钥窗口内若有 EPB，EBSP 与 RBSP 的偏移就错开了，
     * 必须经映射表取字节，否则密钥错、后面所有单元全解错。 */
    h5e_rbsp_map m;
    h5e_rbsp_map_init(&m, epbs, nep);
    uint8_t key[16];
    for (size_t b = 0; b < 16; b++) key[b] = nal[h5e_rbsp_at(&m, 5 + b)];
    uint8_t tmp[8];
    bool any_cell = false;
    for (size_t k = 0;; k++) {
        const size_t o = 64 + k * (size_t)stride;
        if (o + H5E_GRID_TAIL_GUARD > nr || o + 8 > nr) break;
        size_t off[8];
        for (size_t b = 0; b < 8; b++) off[b] = h5e_rbsp_at(&m, o + b);
        for (size_t b = 0; b < 8; b++) tmp[b] = nal[off[b]];
        h5e_tea_decrypt_block(tmp, tmp, key);
        for (size_t b = 0; b < 8; b++) nal[off[b]] = tmp[b];
        any_cell = true;
    }
    /* 丢 EPB 03 属于网格处理：一个单元都没解过的 NAL 原样透传 */
    size_t out_len = len;
    if (nep != 0 && any_cell) out_len = h5e_drop_epb_03(nal, len, epbs, nep);
    free(epbs);
    return out_len;
}

/* classic 网格（老流：type25 出现的是 01 06 而不是 01 09）：起点 32、间隔 80、
 * 每单元 8 字节 TEA-16，密钥取 RBSP[16:32]；尾单元要求还剩一整个 stride。
 * 至少解过一个单元才丢 EPB 03。返回处理后的 NAL 长度。 */
static size_t h5e_decrypt_classic_grid(uint8_t *nal, size_t len) {
    if (!nal || len < H5E_TYPE1_MIN_LEN) return len;
    size_t *epbs = NULL, nep = 0;
    if (h5e_collect_epb(nal, len, &epbs, &nep) != 0) return len;
    const size_t nr = len - nep;
    if (nr < H5E_TYPE1_MIN_LEN) {
        free(epbs);
        return len;
    }
    h5e_rbsp_map m;
    h5e_rbsp_map_init(&m, epbs, nep);
    uint8_t key[16];
    for (size_t b = 0; b < 16; b++) key[b] = nal[h5e_rbsp_at(&m, 16 + b)];
    bool any_cell = false;
    for (size_t k = 0;; k++) {
        const size_t o = 32 + k * (size_t)80;
        if (o + 80 > nr) break;
        size_t off[8];
        for (size_t b = 0; b < 8; b++) off[b] = h5e_rbsp_at(&m, o + b);
        uint8_t blk[8];
        for (size_t b = 0; b < 8; b++) blk[b] = nal[off[b]];
        h5e_tea_decrypt_block(blk, blk, key);
        for (size_t b = 0; b < 8; b++) nal[off[b]] = blk[b];
        any_cell = true;
    }
    /* 连一个 classic 单元（32+80）都放不下的 NAL 原样透传：
     * 此时丢 EPB 只会让长度变短，却没解出任何内容。 */
    size_t out_len = len;
    if (nep != 0 && any_cell) out_len = h5e_drop_epb_03(nal, len, epbs, nep);
    free(epbs);
    return out_len;
}

/* 会话：跨 NAL、跨分块保留的解密状态 */
struct cctv_h5e_session {
    bool new_mode;       /* 网格布局：true = 新模式（type25 魔数 01 09），false = classic（01 06） */
    bool should_decrypt; /* 是否解密：看 type25 的 payload[0] 是不是 1 */
    size_t type1_start;  /* type1 新模式网格的起始 RBSP 下标 */
    size_t type1_guard;  /* type1 网格的尾部判定余量 */
    size_t type1_min_len;/* 短于该长度的 type1 不解密 */
};

/* 会话初始状态：classic 布局、不解密 type1/type5，等 type25 把开关打开 */
static void h5e_session_init(cctv_h5e_session *s) {
    s->new_mode = false;
    s->should_decrypt = false;
    s->type1_start = 64;
    s->type1_guard = H5E_GRID_TAIL_GUARD;
    s->type1_min_len = H5E_TYPE1_MIN_LEN;
}

/* 单条 NAL 的分派入口：type25 只更新会话状态（开关 + 网格布局）；
 * type1/type5 在开关打开时按当前布局解密，并把新长度写回 *io_len。 */
static void h5e_session_on_nal(cctv_h5e_session *s, uint8_t *nal, size_t *io_len) {
    if (!s || !nal || !io_len || *io_len < 1) return;
    const size_t len = *io_len;
    const int ntype = nal[0] & 0x1f;
    if (ntype == 25) {
        s->should_decrypt = (len >= 2 && nal[1] == 1);
        /* 魔数决定网格布局，且允许中途双向切换（老流先 01 06 classic，
         * 后续分片再切到 01 09 新模式）：01 09 → 新模式；01 06 → classic。 */
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

/* MPEG-TS 层：PES 重组、AF 填充与 payload 回写 */

/* 把单个 TS 包的 AF 撑大，从 payload 尾部抢走 need 字节（用 0xFF 填）。
 * 本来只有 payload 的包新建 AF（afc 1→3），已有 AF 的包则延长 AF 体。
 * 返回实际抢到的字节数。 */
static size_t h5e_expand_af_steal(uint8_t *data, size_t len, size_t pkt_off, size_t need) {
    if (!data || need == 0 || pkt_off + 188 > len) return 0;
    int afc = (data[pkt_off + 3] & 0x30) >> 4;
    if (afc == 1) {
        /* 无 AF：新建 AF，占用 1（长度字节）+ af_len 字节 */
        if (need < 1) return 0;
        size_t af_len = need - 1;
        if (af_len > 182) af_len = 182;
        size_t steal = 1 + af_len;
        uint8_t old_payload[184];
        memcpy(old_payload, data + pkt_off + 4, 184);
        data[pkt_off + 3] = (uint8_t)((data[pkt_off + 3] & 0xCF) | 0x30); /* afc=3：AF + payload */
        data[pkt_off + 4] = (uint8_t)af_len;
        if (af_len > 0) {
            data[pkt_off + 5] = 0x00; /* AF flags：无随机接入点、无 PCR */
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
        /* 新腾出的空间填 0xFF（TS 标准的 AF 保留值） */
        for (size_t i = 0; i < add; i++) data[pkt_off + 5 + af_len + i] = 0xFF;
        data[pkt_off + 4] = (uint8_t)new_af_len;
        size_t new_pl = old_payload_len - add;
        memcpy(data + pkt_off + 5 + new_af_len, old_payload, new_pl);
        if (new_pl == 0) data[pkt_off + 3] = (uint8_t)((data[pkt_off + 3] & 0xCF) | 0x20); /* 只剩 AF：afc=2 */
        else data[pkt_off + 3] = (uint8_t)((data[pkt_off + 3] & 0xCF) | 0x30);            /* 还有 payload：afc=3 */
        return add;
    }
    return 0;
}

/* 一个 TS 包在缓冲里的 payload 区间，用于把重组后的 PES 按原顺序散写回去。 */
typedef struct {
    size_t pkt_off; /* 包起始在 TS 缓冲内的偏移 */
    size_t pi;      /* 包内 payload 起始（afc=1 时 4，否则 5 + AF 长度） */
    size_t pl;      /* 包内 payload 字节数 */
} h5e_span;

/* ES 内找到的一处 NAL start code。 */
typedef struct {
    size_t pos; /* start code 在 ES 内的偏移 */
    size_t sc;  /* start code 长度：3（00 00 01）或 4（00 00 00 01） */
} h5e_sc;

/* 缓冲按需扩容：*cap 是当前元素容量，elem 是单元素字节数，need 是所需元素数。
 * 容量从 64 起按 2 倍递增；缓冲只在单个 PES 规模内增长，与块大小无关。
 * 返回 0 成功；-1 为溢出或内存不足，此时原缓冲仍然有效。 */
static int h5e_reserve(void **buf, size_t *cap, size_t need, size_t elem) {
    if (need <= *cap) return 0;
    size_t ncap = *cap ? *cap : 64;
    while (ncap < need) {
        if (ncap > SIZE_MAX / 2) {
            ncap = need;
            break;
        }
        ncap <<= 1;
    }
    if (elem == 0 || ncap > SIZE_MAX / elem) return -1;
    void *p = realloc(*buf, ncap * elem);
    if (!p) return -1;
    *buf = p;
    *cap = ncap;
    return 0;
}

/* 处理 PES 的工作区：所有缓冲都按需增长并跨 PES 复用，不逐块释放。 */
typedef struct {
    cctv_h5e_session *session; /* 跨 PES、跨块复用的解密状态 */
    uint8_t *pes;              /* 累积的 PES 字节，同时也存放重建结果（省掉单独的 out 缓冲） */
    h5e_span *spans;           /* 该 PES 各包 payload 区间 */
    h5e_sc *starts;            /* 该 PES 内的 NAL start code 列表 */
    size_t pes_n, pes_cap;
    size_t spans_n, spans_cap;
    size_t starts_n, starts_cap;
    size_t nal_count; /* 经过会话的 NAL 数，用于判断是否真的解到了东西 */
    bool oom;         /* 扩容失败标记：上层据此区分“内存不足”与“没有 NAL” */
} h5e_ts_ctx;

/* 处理一个完整 PES，分四个阶段：跳过 PES 头 → 扫 NAL start code → 逐条解密并
 * 原地重建 → 撑 AF 补差额后散写回各包 payload。
 * 与 dec.c 的结构差别：重建结果直接写在 ctx->pes 内（写游标恒不越过读游标），
 * 省掉 ctx->out；写入的字节序列与 dec.c 完全一致。 */
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

    const size_t es_off = base_skip;
    const size_t es_n = pes_n - es_off;
    uint8_t *es = pes + es_off;

    /* 扫描 ES 内的 NAL start code：memchr 找 0x00，再判 4 字节 / 3 字节；
     * 优先次序与推进方式与 dec.c 的逐字节版一致 */
    size_t ns = 0;
    for (size_t i = 0; i + 3 < es_n;) {
        const uint8_t *p = (const uint8_t *)memchr(es + i, 0, (es_n - 3) - i);
        if (!p) break;
        const size_t j = (size_t)(p - es);
        size_t sc = 0;
        if (j + 4 <= es_n && es[j + 1] == 0 && es[j + 2] == 0 && es[j + 3] == 1) {
            sc = 4;
        } else if (es[j + 1] == 0 && es[j + 2] == 1) {
            sc = 3;
        }
        if (sc == 0) {
            i = j + 1;
            continue;
        }
        if (h5e_reserve((void **)&ctx->starts, &ctx->starts_cap, ns + 1, sizeof(h5e_sc)) != 0) {
            ctx->oom = true;
            ctx->pes_n = 0;
            ctx->spans_n = 0;
            ctx->starts_n = 0;
            return;
        }
        ctx->starts[ns].pos = j;
        ctx->starts[ns].sc = sc;
        ns++;
        i = j + sc;
    }
    ctx->starts_n = ns;

    /* 原地重建：out_n 是 pes 内的写游标，恒不越过“已消费的读位置” */
    size_t out_n = base_skip;

    size_t cursor = 0;
    for (size_t idx = 0; idx < ns; idx++) {
        const size_t pos = ctx->starts[idx].pos;
        const size_t sc = ctx->starts[idx].sc;
        const size_t end = (idx + 1 < ns) ? ctx->starts[idx + 1].pos : es_n;
        if (cursor < pos) {
            memmove(pes + out_n, es + cursor, pos - cursor);
            out_n += pos - cursor;
        }
        memmove(pes + out_n, es + pos, sc);
        out_n += sc;
        if (pos + sc >= end) {
            cursor = end;
            continue;
        }
        /* 就地解密：解密只会丢 EPB 的 03（收缩），所以直接改 PES 缓冲安全 */
        uint8_t *nal = es + pos + sc;
        size_t nlen = end - (pos + sc);
        size_t io = nlen;
        h5e_session_on_nal(ctx->session, nal, &io);
        ctx->nal_count++;
        memmove(pes + out_n, nal, io);
        out_n += io;
        cursor = end;
    }
    if (cursor < es_n) {
        memmove(pes + out_n, es + cursor, es_n - cursor);
        out_n += es_n - cursor;
    }

    /* 解密后变短了：从最后一个包往前逐个撑 AF，把差额吃回来；
     * capacity 取 AF 扩展前各包 payload 之和。 */
    size_t capacity = 0;
    for (size_t i = 0; i < ctx->spans_n; i++) capacity += ctx->spans[i].pl;
    if (capacity > out_n) {
        size_t remaining = capacity - out_n;
        for (size_t i = ctx->spans_n; i-- > 0 && remaining > 0;) {
            size_t got = h5e_expand_af_steal(data, len, ctx->spans[i].pkt_off, remaining);
            remaining -= got;
        }
        /* AF 长度变了，按新包头重算各包 payload 区间（无 payload 的包直接丢弃） */
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
        if (chunk > 0) memcpy(data + pkt_off + pi, pes + off, chunk);
        if (chunk < pl) {
            /* AF 吸收不下的残留尾部用 0xFF 填满 */
            memset(data + pkt_off + pi + chunk, 0xFF, pl - chunk);
        }
        off += pl;
    }

    ctx->pes_n = 0;
    ctx->spans_n = 0;
}

/* 原地解密一个 TS 缓冲里指定 PID 的全部视频 NAL。
 * 做法：按 188 字节遍历 TS 包，把同一个 PES 的 payload 依次攒起来，
 * 遇到 PUSI（新 PES 的起点）就先把上一个 PES 冲掉。
 * 返回 >= 0 为经过会话的 NAL 数；-1 为内存不足。 */
static long long h5e_decrypt_ts_inplace(uint8_t *data, size_t len, cctv_h5e_session *session,
                                        uint16_t vpid) {
    if (!data || len < 188) return 0;

    h5e_ts_ctx ctx;
    memset(&ctx, 0, sizeof ctx);
    ctx.session = session;

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
        if (h5e_reserve((void **)&ctx.pes, &ctx.pes_cap, ctx.pes_n + payload_len, 1) != 0 ||
            h5e_reserve((void **)&ctx.spans, &ctx.spans_cap, ctx.spans_n + 1, sizeof(h5e_span)) != 0) {
            ctx.oom = true;
            break;
        }
        memcpy(ctx.pes + ctx.pes_n, data + off + pi, payload_len);
        ctx.pes_n += payload_len;
        ctx.spans[ctx.spans_n].pkt_off = off;
        ctx.spans[ctx.spans_n].pi = pi;
        ctx.spans[ctx.spans_n].pl = payload_len;
        ctx.spans_n++;
    }
    if (!ctx.oom) h5e_flush_pes(data, len, &ctx);

    const size_t nal_count = ctx.nal_count;
    const bool oom = ctx.oom;
    free(ctx.pes);
    free(ctx.spans);
    free(ctx.starts);
    return oom ? -1 : (long long)nal_count;
}

/* ============================ 解密引擎结束 ============================ */

/* ====================== 文件级读写（宽字符 API） ====================== */

/* 分块流式解密：切点取视频 PES 起点，每块解完立即写回。
 * 块大小是目标值而非硬上限（尾块、超长 PES 会多补一片）；会话跨块复用，
 * 结果与整文件一次性处理一致，峰值内存与文件总大小无关。
 * 块大小、补给粒度、对齐与切点规则与 dec.c 完全一致。 */
#define DEC_CHUNK_BYTES ((size_t)32 * 1024 * 1024) /* 目标块大小 */
#define DEC_READ_SLICE  ((size_t)4 * 1024 * 1024)  /* 单次补给粒度 */

/* 把文件指针移到 off（用 size_t 偏移，避开 LONG 只有 32 位） */
static bool dec_seek(HANDLE h, size_t off) {
    LARGE_INTEGER li;
    li.QuadPart = (LONGLONG)off;
    return SetFilePointerEx(h, li, NULL, FILE_BEGIN) != 0;
}

/* 在 off 处读 n 字节到 buf；按 256MB 分片调 ReadFile，避开 DWORD 长度上限 */
static bool dec_read_at(HANDLE h, size_t off, uint8_t *buf, size_t n) {
    if (!dec_seek(h, off)) return false;
    size_t got = 0;
    while (got < n) {
        DWORD want = (DWORD)((n - got) > 0x10000000u ? 0x10000000u : (n - got));
        DWORD read = 0;
        if (!ReadFile(h, buf + got, want, &read, NULL) || read == 0) return false;
        got += read;
    }
    return true;
}

/* 在 off 处写 n 字节；分片规则与 dec_read_at 相同 */
static bool dec_write_at(HANDLE h, size_t off, const uint8_t *data, size_t n) {
    if (!dec_seek(h, off)) return false;
    size_t put = 0;
    while (put < n) {
        DWORD want = (DWORD)((n - put) > 0x10000000u ? 0x10000000u : (n - put));
        DWORD wrote = 0;
        if (!WriteFile(h, data + put, want, &wrote, NULL) || wrote == 0) return false;
        put += wrote;
    }
    return true;
}

/* 前置声明：宽字符转 UTF-8，供错误提示打印路径用 */
static char *dec_utf8_from_wide(const wchar_t *w);

/* 生成临时路径 <输出>.part：与目标同目录，后续改名才是同卷原子重命名 */
static wchar_t *dec_temp_path(const wchar_t *out_path) {
    const size_t len = wcslen(out_path);
    if (len == 0 || len > 32000) return NULL;
    wchar_t *p = (wchar_t *)malloc((len + 8) * sizeof(wchar_t));
    if (!p) return NULL;
    memcpy(p, out_path, (len + 1) * sizeof(wchar_t));
    memcpy(p + len, L".part", 6 * sizeof(wchar_t));
    return p;
}

/* 判断一个 TS 包是否为指定视频 PID 的 PES 起点：同步字节 + PID 匹配 + PUSI 置位 */
static bool dec_is_video_pes_start(const uint8_t *pkt, uint16_t vpid) {
    if (pkt[0] != 0x47) return false;
    if ((uint16_t)(((pkt[1] & 0x1f) << 8) | pkt[2]) != vpid) return false;
    return (pkt[1] & 0x40) != 0;
}

/* 扫描缓冲里的视频 PES 起点，给出首个与最后一个的偏移。
 * 块切点用最后一个起点：这样下一块从完整 PES 开头，跨块不会把 PES 切开。 */
static bool dec_scan_video_pes(const uint8_t *data, size_t len, uint16_t vpid, size_t *first,
                               size_t *last) {
    bool found = false;
    size_t f = 0, l = 0;
    for (size_t off = 0; off + 188 <= len; off += 188) {
        if (!dec_is_video_pes_start(data + off, vpid)) continue;
        if (!found) f = off;
        l = off;
        found = true;
    }
    if (found) {
        if (first) *first = f;
        if (last) *last = l;
    }
    return found;
}

/* 读 → 分块解密 → 写，直到文件尾。
 * 返回 >= 0：写出的字节数；-1 参数错；-2 读失败；-3 解密失败（内存不足或
 * 一个视频 NAL 都没解到）；-4 写失败或最终替换失败。 */
static long long dec_decrypt_file_w(const wchar_t *in_path, const wchar_t *out_path, unsigned vpid,
                                    size_t *bytes_written) {
    if (bytes_written) *bytes_written = 0;
    if (!in_path || !out_path) return -1;

    HANDLE hin = CreateFileW(in_path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                             OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hin == INVALID_HANDLE_VALUE) return -2;

    LARGE_INTEGER sz;
    if (!GetFileSizeEx(hin, &sz) || sz.QuadPart < 0) {
        CloseHandle(hin);
        return -2;
    }
    const size_t total = (size_t)sz.QuadPart;

    /* 先写 <输出>.part，成功后再原子替换：中途失败不会毁掉已存在的目标，
     * 输入输出同路径时也不会把原文件改坏（代价是需要额外一份磁盘空间）。 */
    wchar_t *tmp_path = dec_temp_path(out_path);
    if (!tmp_path) {
        CloseHandle(hin);
        return -4;
    }
    HANDLE hout = CreateFileW(tmp_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, NULL);
    if (hout == INVALID_HANDLE_VALUE) {
        free(tmp_path);
        CloseHandle(hin);
        return -4;
    }

    cctv_h5e_session session;
    h5e_session_init(&session);

    uint8_t *buf = NULL;
    size_t cap = 0;  /* buf 的容量 */
    size_t n = 0;    /* buf 中待处理的字节数 */
    size_t base = 0; /* buf[0] 对应的文件偏移 */
    size_t nal_total = 0;
    bool pes_aligned = false; /* 只有 buf[0] 对齐到视频 PES 起点时才解密 */
    bool extra = false;       /* 块内找不到切点时，再多读一片后重试 */
    int rc = 0;

    for (;;) {
        /* 1. 补给：读满目标块（extra 时多读一片），或一直读到文件尾 */
        size_t target = extra ? n + DEC_READ_SLICE : DEC_CHUNK_BYTES;
        extra = false;
        while (n < target && base + n < total) {
            size_t want = target - n;
            if (want > DEC_READ_SLICE) want = DEC_READ_SLICE;
            if (want > total - base - n) want = total - base - n;
            if (h5e_reserve((void **)&buf, &cap, n + want, 1) != 0) {
                rc = -3;
                goto done;
            }
            if (!dec_read_at(hin, base + n, buf + n, want)) {
                rc = -2;
                goto done;
            }
            n += want;
        }
        const bool eof = (base + n >= total);

        size_t first = 0, last = 0;
        const bool found = dec_scan_video_pes(buf, n, (uint16_t)vpid, &first, &last);

        /* 2. 对齐：把 buf[0] 挪到首个视频 PES 起点，否则这块没法解密 */
        if (!pes_aligned) {
            if (found && first > 0) {
                /* 前导的非视频包（PAT/PMT/音频等）原样写出，只跳它们本身，
                 * 然后回到循环开头重新对齐 */
                if (!dec_write_at(hout, base, buf, first)) {
                    rc = -4;
                    goto done;
                }
                base += first;
                n -= first;
                memmove(buf, buf + first, n);
                pes_aligned = true;
                continue;
            }
            if (!found && !eof) {
                extra = true;
                continue;
            }
            pes_aligned = (found && first == 0);
            if (!pes_aligned) {
                /* 直到文件尾都没见到视频 PES：剩下的原样写出（随后按解密失败处理） */
                if (n > 0 && !dec_write_at(hout, base, buf, n)) {
                    rc = -4;
                    goto done;
                }
                base += n;
                n = 0;
                break;
            }
        }

        /* 3. 切点：取块内最后一个视频 PES 起点，保证下一块从完整 PES 开始 */
        size_t chunk_len;
        if (last > 0) {
            chunk_len = last;
        } else if (eof) {
            chunk_len = n; /* 尾块：整段交付，含末尾不足 188 字节的残片 */
        } else {
            /* 整块只含一个 PES 起点（超长 PES）：再补一片重试，让切点落在 PES 边界 */
            extra = true;
            continue;
        }

        /* 4. 解密并顺序写回；会话跨块复用，等价于一次性处理整个文件 */
        if (pes_aligned && chunk_len > 0) {
            const long long nc = h5e_decrypt_ts_inplace(buf, chunk_len, &session, (uint16_t)vpid);
            if (nc < 0) {
                rc = -3;
                goto done;
            }
            nal_total += (size_t)nc;
        }
        if (chunk_len > 0 && !dec_write_at(hout, base, buf, chunk_len)) {
            rc = -4;
            goto done;
        }

        base += chunk_len;
        n -= chunk_len;
        if (n > 0) memmove(buf, buf + chunk_len, n);
        if (n == 0 && eof) break;
    }

    /* 一个视频 NAL 都没经过会话：多半是 PID 不对或根本不是 TS。
     * 这种情况按失败处理，绝不产出“看着成功其实是原文”的副本。 */
    if (nal_total == 0) {
        rc = -3;
        goto done;
    }

done:
    free(buf);
    if (rc == 0 && !FlushFileBuffers(hout)) rc = -4;
    CloseHandle(hout);
    CloseHandle(hin);
    if (rc == 0 && !MoveFileExW(tmp_path, out_path, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        /* 替换失败（目标被占用、只读等）：成品留在 .part 里，方便手动改名 */
        rc = -4;
        char *keep = dec_utf8_from_wide(tmp_path);
        fprintf(stderr, "replace failed, 成品保留在: %s\n", keep ? keep : "?");
        free(keep);
    } else if (rc != 0) {
        DeleteFileW(tmp_path); /* 失败只删自己的临时文件，目标与输入都不碰 */
    }
    free(tmp_path);
    if (rc != 0) return rc;
    if (bytes_written) *bytes_written = base;
    return (long long)base;
}

/* 宽字符路径转 UTF-8，只为把中文路径打印到控制台 */
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

/* ============================== 命令行入口 ============================== */

int main(void) {
    /* 控制台切到 UTF-8：源码字串本身是 UTF-8，这样中文提示在任何语言的 Windows 下都不乱码 */
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

    /* 只认 --pid（其余参数忽略），默认 0x100 是 CCTV 视频流的常见 PID */
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
        case -3: msg = "解密失败（内存不足 / 未找到视频 PES / PID 不对）"; break;
        case -4: msg = "无法写出输出文件（磁盘空间不足或目标被占用）"; break;
        default: break;
    }
    fprintf(stderr, "decrypt failed rc=%lld (%s)\n", rc, msg);
    LocalFree(argv);
    return 1;
}

#endif /* _WIN32 */
