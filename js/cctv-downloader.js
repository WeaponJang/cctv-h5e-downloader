/**
 * CCTV 视频下载器
 * 支持未加密流直接下载 + 加密流整文件解密
 */
const { spawn, execSync } = require('child_process');
const path = require('path');
const fs = require('fs');
const https = require('https');
const http = require('http');
const { URL } = require('url');
const { httpGet, sanitizeFilename, fetchBinary } = require('./cctv-parser.js');
const TSMerger = require('./tsmerger.js');

const USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';
const packageDir = path.join(path.dirname(process.execPath), 'package.nw');

/**
 * 查找 ffmpeg 路径
 */
function findFFmpeg() {
    const nwjsDir = path.dirname(process.execPath);
    const candidates = [
        path.join(packageDir, 'ffmpeg.exe'),
        path.join(nwjsDir, 'ffmpeg.exe'),
        'ffmpeg'
    ];
    for (const candidate of candidates) {
        try {
            if (path.isAbsolute(candidate) && fs.existsSync(candidate)) return candidate;
        } catch (e) { }
    }
    return 'ffmpeg';
}

/**
 * 解析 m3u8 播放列表，获取所有 TS 片段 URL
 */
function parseM3u8Segments(m3u8Text, baseUrl) {
    const lines = m3u8Text.split(/\r?\n/).map(l => l.trim()).filter(l => l);
    const segments = [];
    for (const line of lines) {
        if (line.startsWith('#')) continue;
        if (!line) continue;
        let url = line;
        if (!url.startsWith('http')) {
            try {
                url = new URL(url, baseUrl).href;
            } catch (e) {
                url = baseUrl.replace(/\/[^\/]*$/, '/') + url;
            }
        }
        segments.push(url);
    }
    return segments;
}

/**
 * 普通文件下载 (带进度回调)
 */
function downloadFile(url, destPath, options = {}) {
    return new Promise((resolve, reject) => {
        const parsedUrl = new URL(url);
        const isHttps = parsedUrl.protocol === 'https:';
        const mod = isHttps ? https : http;

        const reqOptions = {
            hostname: parsedUrl.hostname,
            port: parsedUrl.port || (isHttps ? 443 : 80),
            path: parsedUrl.pathname + parsedUrl.search,
            method: 'GET',
            headers: {
                'User-Agent': options.userAgent || USER_AGENT,
                'Accept': '*/*',
                'Accept-Encoding': 'identity',
                'Referer': 'https://www.cctv.com/',
                ...(options.headers || {})
            },
            timeout: options.timeout || 120000
        };

        const req = mod.request(reqOptions, (res) => {
            if ([301, 302, 303, 307].includes(res.statusCode)) {
                const location = res.headers.location;
                if (location) {
                    resolve(downloadFile(location, destPath, options));
                    return;
                }
            }
            if (res.statusCode < 200 || res.statusCode >= 300) {
                fs.unlink(destPath, () => { });
                reject(new Error(`HTTP ${res.statusCode} for ${url}`));
                return;
            }

            const totalSize = parseInt(res.headers['content-length'] || '0', 10);
            let downloadedSize = 0;
            const fileStream = fs.createWriteStream(destPath);

            res.on('data', (chunk) => {
                downloadedSize += chunk.length;
                if (options.onProgress && totalSize > 0) {
                    options.onProgress(downloadedSize, totalSize);
                }
            });

            res.pipe(fileStream);

            fileStream.on('finish', () => {
                fileStream.close();
                resolve(destPath);
            });
            fileStream.on('error', (err) => {
                fs.unlink(destPath, () => { });
                reject(err);
            });
        });

        req.on('error', reject);
        req.on('timeout', () => {
            req.destroy();
            reject(new Error(`Download timeout: ${url}`));
        });
        req.end();
    });
}

/**
 * 下载 m3u8 / tsindex 片段
 * 新策略: 先下载各片段为临时文件，再用 TSMerger 做协议级智能合并
 */
async function downloadM3U8(quality, outputFile, apiData, options = {}) {
    const onProgress = options.onProgress || (() => { });
    const onLog = options.onLog || (() => { });

    // ---------- 1. 解析片段 URL ----------
    let segments = [];

    // 策略1: 尝试下载 m3u8 获取片段列表
    try {
        onLog('尝试下载 m3u8 索引...');
        const m3u8Content = await httpGet(quality.url);
        if (m3u8Content.body.includes('#EXTM3U')) {
            const parsed = parseM3u8Segments(m3u8Content.body, quality.url);
            if (parsed.length > 0) {
                segments = parsed;
                onLog(`m3u8 解析成功: ${segments.length} 个片段`);
            }
        }
    } catch (e) {
        onLog(`m3u8 直接下载失败: ${e.message}, 尝试 tsindex 模式`);
    }

    // 策略2: tsindex.ts 模式 (根据总时长估算片段数)
    if (segments.length === 0) {
        const totalSec = Number(apiData?.video?.totalLength || 0);
        if (totalSec > 0) {
            const maxIndex = Math.max(0, Math.ceil(totalSec / 10) - 1);
            onLog(`使用 tsindex 模式, 总时长 ${totalSec}s, 预估 ${maxIndex + 1} 个片段`);
            let urlStr = quality.url.split('?')[0];
            const baseUrl = urlStr.replace(/[^\/]+$/, '');
            for (let i = 0; i <= maxIndex; i++) {
                segments.push(baseUrl + i + '.ts');
            }
            onLog(`生成 ${segments.length} 个 ts 片段 URL`);
        }
    }

    if (segments.length === 0) {
        throw new Error('无法获取片段列表 (m3u8 和 tsindex 均失败)');
    }

    // ---------- 2. 下载片段到临时目录 ----------
    const tempDir = outputFile + '.seg_tmp';
    if (!fs.existsSync(tempDir)) {
        fs.mkdirSync(tempDir, { recursive: true });
    }

    const segFiles = [];
    let failed = 0;
    const total = segments.length;

    for (let i = 0; i < total; i++) {
        const segPath = path.join(tempDir, `seg_${String(i).padStart(6, '0')}.ts`);
        try {
            const buf = await fetchBinary(segments[i]);
            fs.writeFileSync(segPath, buf);
            segFiles.push(segPath);
        } catch (e) {
            failed++;
            onLog(`片段 ${i} 失败: ${e.message}`);
        }
        onProgress(i + 1, total);
    }

    if (segFiles.length === 0) {
        try { fs.rmSync(tempDir, { recursive: true, force: true }); } catch (e) { }
        throw new Error('所有片段下载均失败');
    }
    if (failed > 0) {
        onLog(`共 ${failed} 个片段下载失败，继续合并可用片段 (${segFiles.length}/${total})`);
    }

    // ---------- 3. 使用 TSMerger 智能合并 ----------
    onLog(`开始 TS 协议级合并 (${segFiles.length} 个片段)...`);
    const merger = new TSMerger();
    const ok = await merger.merge(segFiles, outputFile, options.cancellationRequested);

    // ---------- 4. 清理临时文件 ----------
    try { fs.rmSync(tempDir, { recursive: true, force: true }); } catch (e) { }
    onLog('已清理临时片段文件');

    if (!ok) {
        throw new Error('TSMerger 合并失败或已取消');
    }

    onLog(`合并完成: ${path.basename(outputFile)}`);
    return outputFile;
}

/**
 * 调用 dec.exe 解密整文件
 */
function runDec(inFile, outFile, onLog) {
    return new Promise((resolve, reject) => {
        // 兼容两个路径: package.nw/dec.exe 和 package.nw/js/cctv/dec.exe
        let decPath = path.join(packageDir, 'dec.exe');
        if (!fs.existsSync(decPath)) {
            decPath = path.join(packageDir, 'js', 'cctv', 'dec.exe');
        }

        if (!fs.existsSync(decPath)) {
            return reject(new Error(`dec.exe 未找到: ${decPath}`));
        }

        onLog && onLog(`执行: dec.exe ${path.basename(inFile)} → ${path.basename(outFile)}`);

        const proc = spawn(decPath, [inFile, outFile], {
            cwd: path.dirname(outFile)
        });

        let stderr = '';
        proc.stderr.on('data', d => { stderr += d.toString(); });
        proc.stdout.on('data', d => {
            const msg = d.toString().trim();
            if (msg && onLog) onLog(`[dec] ${msg}`);
        });

        proc.on('close', code => {
            if (code === 0 && fs.existsSync(outFile)) {
                const size = (fs.statSync(outFile).size / 1024 / 1024).toFixed(1);
                onLog && onLog(`dec.exe 解密完成 (${size}MB)`);
                resolve(outFile);
            } else {
                reject(new Error(`dec.exe 退出码 ${code}: ${stderr.slice(-300)}`));
            }
        });

        proc.on('error', reject);
    });
}

/**
 * 调用 ffmpeg 转容器
 */
function runFfmpeg(args, options = {}) {
    return new Promise((resolve, reject) => {
        const ffPath = findFFmpeg();
        const onLog = options.onLog || (() => { });
        const onProgress = options.onProgress || (() => { });

        onLog(`执行: ${path.basename(ffPath)} ${args.join(' ')}`);

        const proc = spawn(ffPath, args, { windowsHide: true });

        let stderr = '';
        proc.stderr.on('data', d => {
            const text = d.toString();
            stderr += text;
            const m = text.match(/time=(\d+:\d+:\d+\.\d+)/);
            if (m) onProgress(-1, -1, m[1]);
        });

        proc.on('close', code => {
            if (code === 0) resolve();
            else reject(new Error(`ffmpeg 退出码 ${code}: ${stderr.slice(-300)}`));
        });

        proc.on('error', reject);
    });
}

/**
 * 主下载入口
 * @param {object} quality - 清晰度对象 { name, url, source, bitrate, ... }
 * @param {object} videoInfo - parseCCTVVideo 返回的视频信息
 * @param {string} saveDir - 保存目录
 * @param {object} callbacks - 回调函数集合
 */
async function downloadVideo(quality, videoInfo, saveDir, callbacks = {}) {
    const { onProgress, onLog, onComplete, onError } = callbacks;
    const log = onLog || (() => { });
    const progress = onProgress || (() => { });

    try {
        if (!fs.existsSync(saveDir)) {
            fs.mkdirSync(saveDir, { recursive: true });
        }

        const safeTitle = sanitizeFilename(videoInfo.title || 'video').substring(0, 80);
        const safeQName = sanitizeFilename(quality.name);

        const isEncrypted = quality.source === 'bitrate-select' || quality.name.includes('h5e-');

        const tsFile = path.join(saveDir, `${safeTitle}_${safeQName}.ts`);
        const m2tsFile = path.join(saveDir, `${safeTitle}_${safeQName}.m2ts`);
        const mp4File = path.join(saveDir, `${safeTitle}_${safeQName}.mp4`);

        // 避免文件名重复
        let finalMp4 = mp4File;
        let counter = 1;
        while (fs.existsSync(finalMp4)) {
            finalMp4 = path.join(saveDir, `${safeTitle}_${safeQName}_${counter}.mp4`);
            counter++;
        }

        log(`开始下载 [${quality.name}]: ${quality.url}`);
        log(`类型: ${isEncrypted ? '加密流 (h5e)' : '未加密流 (hls)'}`);

        // 第1步: 下载 TS 片段并协议级合并 (m3u8 或 tsindex)
        progress(0, 100);
        await downloadM3U8(quality, tsFile, videoInfo.rawApiData, {
            onProgress: (current, total) => {
                if (total > 0) progress(current, total);
            },
            onLog: log,
            cancellationRequested: callbacks.cancellationRequested
        });

        if (isEncrypted) {
            // 第2步: dec.exe 解密 ts → m2ts
            progress(92, 100);
            log('正在调用 dec.exe 解密...');
            await runDec(tsFile, m2tsFile, log);

            // 第3步: ffmpeg m2ts → mp4
            progress(96, 100);
            log('正在 ffmpeg 转 MP4...');
            await runFfmpeg(['-i', m2tsFile, '-c', 'copy', '-copyts', '-start_at_zero', '-y', finalMp4], {
                onLog: log,
                onProgress: progress
            });

            log(`完成: ${finalMp4}`);

            // 清理中间文件
            try { fs.unlinkSync(tsFile); } catch (e) { }
            try { fs.unlinkSync(m2tsFile); } catch (e) { }
            log('已清理中间文件 (.ts / .m2ts)');
        } else {
            // 未加密: 直接 ffmpeg 转 mp4
            progress(95, 100);
            log('正在 ffmpeg 转 MP4...');
            await runFfmpeg(['-i', tsFile, '-c', 'copy', '-copyts', '-start_at_zero', '-y', finalMp4], {
                onLog: log,
                onProgress: progress
            });

            log(`完成: ${finalMp4}`);
            try { fs.unlinkSync(tsFile); } catch (e) { }
        }

        log('下载完成！');
        onComplete && onComplete(finalMp4);
        return finalMp4;

    } catch (err) {
        log('下载出错: ' + err.message);
        onError && onError(err);
        throw err;
    }
}

module.exports = {
    downloadVideo,
    downloadFile,
    runDec,
    runFfmpeg,
    findFFmpeg
};
