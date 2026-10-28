/**
 * TSMerger - MPEG-TS 智能合并器（NW.js / Node.js 版）
 * 移植自 C++ 的 tsmerger.cpp
 */
const fs = require('fs');
const path = require('path');

const TS_PACKET_SIZE = 188;
const SYNC_BYTE = 0x47;

// 连续性计数器状态（per PID）
class TSMerger {
  constructor() {
    this.reset();
  }

  reset() {
    // 用 Map 代替 C++ 的定长数组（PID 最大 0x1FFF）
    this.continuityCounters = new Map(); // pid -> lastCounter
    this.continuityOffsets = new Map();  // pid -> offsetForPid
    this.pmtPid = 0;
    this.pmtIdentified = false;
  }

  isCancellationRequested(cancelFn) {
    return typeof cancelFn === 'function' && cancelFn();
  }

  /**
   * 合并多个 TS 文件
   * @param {string[]} inputFiles 输入文件路径数组
   * @param {string} outputFile 输出文件路径
   * @param {() => boolean} [cancellationRequested] 取消回调
   * @returns {Promise<boolean>}
   */
  async merge(inputFiles, outputFile, cancellationRequested) {
    console.log(`开始合并TS文件，输入文件数: ${inputFiles.length} 输出文件: ${outputFile}`);

    if (!inputFiles || inputFiles.length === 0) {
      console.warn('没有输入文件可合并');
      return false;
    }

    this.reset();

    const outputDir = path.dirname(outputFile);
    if (!fs.existsSync(outputDir)) {
      if (!this._mkdirp(outputDir)) {
        console.error(`无法创建输出目录: ${outputDir}`);
        return false;
      }
    }

    const tempOutputFile = outputFile + '.merge_tmp';
    const backupOutputFile = outputFile + '.merge_backup';

    // 清理旧临时文件
    if (fs.existsSync(tempOutputFile)) {
      try { fs.unlinkSync(tempOutputFile); }
      catch (e) {
        console.error(`无法清理旧的临时合并输出文件: ${tempOutputFile}`, e);
        return false;
      }
    }

    let outfile;
    try {
      outfile = fs.openSync(tempOutputFile, 'w');
    } catch (e) {
      console.error(`无法打开临时输出文件: ${tempOutputFile}`, e);
      return false;
    }
    console.log(`临时输出文件已打开: ${tempOutputFile}`);

    try {
      for (let i = 0; i < inputFiles.length; i++) {
        if (this.isCancellationRequested(cancellationRequested)) {
          console.log('TS合并已取消，停止处理后续文件');
          fs.closeSync(outfile);
          this._safeUnlink(tempOutputFile);
          return false;
        }

        console.log(`处理第 ${i + 1}/${inputFiles.length} 个文件: ${inputFiles[i]}`);
        const ok = this.processFile(inputFiles[i], outfile, i === 0, cancellationRequested);
        if (!ok) {
          console.error(`处理文件失败: ${inputFiles[i]}`);
          fs.closeSync(outfile);
          this._safeUnlink(tempOutputFile);
          return false;
        }
        console.log(`第 ${i + 1} 个文件处理完成`);
      }
    } finally {
      if (outfile !== undefined) {
        try { fs.closeSync(outfile); } catch (_) {}
      }
    }

    if (this.isCancellationRequested(cancellationRequested)) {
      console.log('TS合并已取消，停止发布输出文件');
      this._safeUnlink(tempOutputFile);
      return false;
    }

    // ---- 事务式发布（备份 + 原子重命名）----
    const hadExistingOutput = fs.existsSync(outputFile);
    let movedExistingOutputToBackup = false;

    if (hadExistingOutput) {
      if (fs.existsSync(backupOutputFile)) {
        try { fs.unlinkSync(backupOutputFile); }
        catch (e) {
          console.error(`无法清理旧的合并备份文件: ${backupOutputFile}`, e);
          this._safeUnlink(tempOutputFile);
          return false;
        }
      }
      try {
        fs.renameSync(outputFile, backupOutputFile);
        movedExistingOutputToBackup = true;
      } catch (e) {
        console.error(`无法备份现有输出文件: ${outputFile} -> ${backupOutputFile}`, e);
        this._safeUnlink(tempOutputFile);
        return false;
      }
    }

    try {
      fs.renameSync(tempOutputFile, outputFile);
    } catch (e) {
      console.error(`无法发布合并输出文件: ${tempOutputFile} -> ${outputFile}`, e);
      if (movedExistingOutputToBackup) {
        try { fs.renameSync(backupOutputFile, outputFile); }
        catch (e2) { console.error(`恢复原始输出文件失败`, e2); }
      }
      this._safeUnlink(tempOutputFile);
      return false;
    }

    if (movedExistingOutputToBackup && fs.existsSync(backupOutputFile)) {
      this._safeUnlink(backupOutputFile, true);
    }

    console.log(`所有文件合并完成，输出文件: ${outputFile}`);
    if (!this.pmtIdentified) {
      console.warn('合并完成，但未识别到PMT');
    } else {
      console.log(`PMT识别成功，PID: ${this.pmtPid}`);
    }
    return true;
  }

  /**
   * 处理单个输入文件，写入 outfile（fd）
   */
  processFile(filename, outfile, isFirstFile, cancellationRequested) {
    console.log(`处理TS文件: ${filename} 是否为第一个文件: ${isFirstFile}`);

    if (this.isCancellationRequested(cancellationRequested)) {
      console.log(`TS文件处理前检测到取消请求: ${filename}`);
      return false;
    }

    this.continuityOffsets = new Map(); // 每个文件重置偏移

    let stat;
    try { stat = fs.statSync(filename); }
    catch (e) { console.error(`无法打开输入文件: ${filename}`, e); return false; }

    const fileSize = stat.size;
    console.log(`文件大小: ${fileSize} 字节`);

    if (fileSize === 0) {
      console.error(`文件大小为0，无法处理: ${filename}`);
      return false;
    }
    if (fileSize % TS_PACKET_SIZE !== 0) {
      console.warn(`文件大小不是TS包的整数倍: ${filename} 大小: ${fileSize}`);
      // 与 C++ 版一致：不 return false，继续处理
    }

    // 分块流式读取（避免大文件整体读入内存）
    const CHUNK = TS_PACKET_SIZE * 22000; // ~4MB，与解密模块扫描粒度一致
    const buffer = Buffer.alloc(CHUNK);
    let fileOffset = 0;
    let packetCount = 0, skippedCount = 0, invalidCount = 0, validPacketCount = 0;

    let fd;
    try { fd = fs.openSync(filename, 'r'); }
    catch (e) { console.error(`无法打开输入文件: ${filename}`, e); return false; }

    try {
      while (fileOffset < fileSize) {
        if (this.isCancellationRequested(cancellationRequested)) {
          console.log(`TS文件处理过程中收到取消请求: ${filename}`);
          return false;
        }

        const toRead = Math.min(CHUNK, fileSize - fileOffset);
        const bytesRead = fs.readSync(fd, buffer, 0, toRead, fileOffset);
        if (bytesRead <= 0) break;

        // 按整包截断，剩余不足一包的部分随下一块读取（文件大小非整包时尾包会被跳过，与C++循环条件一致）
        const wholePackets = Math.floor(bytesRead / TS_PACKET_SIZE);

        for (let p = 0; p < wholePackets; p++) {
          const i = p * TS_PACKET_SIZE; // buffer 内偏移
          if (!this.validatePacket(buffer, i)) {
            invalidCount++;
            continue;
          }
          validPacketCount++;

          const pid = ((buffer[i + 1] & 0x1F) << 8) | buffer[i + 2];

          if (isFirstFile) {
            if (pid === 0 && !this.pmtIdentified) {
              this.identifyPMTPID(buffer, i);
            }
            if (!this.normalizeContinuityCounter(buffer, i)) {
              console.error(`TS包adaptation_field_control无效: ${filename} 偏移: ${fileOffset + i}`);
              return false;
            }
            if (fs.writeSync(outfile, buffer, i, TS_PACKET_SIZE) !== TS_PACKET_SIZE) {
              console.error(`写入输出文件失败`);
              return false;
            }
            packetCount++;
          } else {
            if (pid === 0 || (this.pmtIdentified && pid === this.pmtPid)) {
              skippedCount++;
              continue; // 跳过后续分片的 PAT/PMT
            }
            if (!this.normalizeContinuityCounter(buffer, i)) {
              console.error(`TS包adaptation_field_control无效: ${filename} 偏移: ${fileOffset + i}`);
              return false;
            }
            if (fs.writeSync(outfile, buffer, i, TS_PACKET_SIZE) !== TS_PACKET_SIZE) {
              console.error(`写入输出文件失败`);
              return false;
            }
            packetCount++;
          }
        }

        // 处理跨块剩余的不完整包尾部：将其回退，与下一块拼合
        const leftover = bytesRead - wholePackets * TS_PACKET_SIZE;
        fileOffset += wholePackets * TS_PACKET_SIZE;
        if (leftover > 0 && fileOffset < fileSize) {
          // 把尾部字节提前拷回 buffer 开头，再从文件补读
          buffer.copy(buffer, 0, wholePackets * TS_PACKET_SIZE, bytesRead);
          const extra = fs.readSync(fd, buffer, leftover, Math.min(TS_PACKET_SIZE * 100, fileSize - fileOffset), fileOffset);
          // 简化处理：直接按整包推进，尾部残包因不满足整包条件自然被丢弃（与 C++ 行为一致）
          fileOffset += extra;
        }
      }
    } finally {
      try { fs.closeSync(fd); } catch (_) {}
    }

    if (invalidCount > 0) console.warn(`跳过 ${invalidCount} 个无效TS包`);
    if (skippedCount > 0) console.log(`跳过 ${skippedCount} 个PAT/PMT包`);
    if (validPacketCount === 0) {
      console.error(`文件未产生任何有效TS包，无法继续合并: ${filename} 文件大小: ${fileSize} 无效包数: ${invalidCount}`);
      return false;
    }

    console.log(`文件处理完成: ${filename} 有效包数: ${packetCount}`);
    return true;
  }

  /**
   * 重写连续性计数器，保证跨分片连续
   */
  normalizeContinuityCounter(data, offset) {
    const pid = ((data[offset + 1] & 0x1F) << 8) | data[offset + 2];
    const adaptationFieldControl = (data[offset + 3] >> 4) & 0x03;

    if (adaptationFieldControl === 0) return false;

    const hasPayload = adaptationFieldControl === 1 || adaptationFieldControl === 3;
    const hasAdaptation = adaptationFieldControl === 2 || adaptationFieldControl === 3;
    const discontinuity = hasAdaptation && data[offset + 4] > 0 &&
                          (data[offset + 5] & 0x80) !== 0;

    const inputCounter = data[offset + 3] & 0x0F;

    let lastCounter = this.continuityCounters.get(pid);
    let offsetForPid = this.continuityOffsets.get(pid);

    if (lastCounter === undefined) lastCounter = -1;
    if (offsetForPid === undefined) offsetForPid = -1;

    if (pid === 0x1FFF || discontinuity) {
      this.continuityCounters.set(pid, inputCounter);
      this.continuityOffsets.set(pid, 0);
      return true;
    }

    if (offsetForPid < 0) {
      const expectedCounter = lastCounter < 0 ? inputCounter
                            : hasPayload ? (lastCounter + 1) & 0x0F
                            : lastCounter;
      offsetForPid = (expectedCounter - inputCounter + 16) & 0x0F;
      this.continuityOffsets.set(pid, offsetForPid);
    }

    const outputCounter = (inputCounter + offsetForPid) & 0x0F;
    data[offset + 3] = (data[offset + 3] & 0xF0) | outputCounter;
    this.continuityCounters.set(pid, outputCounter);
    return true;
  }

  /**
   * 校验同步字节
   */
  validatePacket(data, offset) {
    if (data[offset] !== SYNC_BYTE) {
      console.log(`TS包同步字节错误，偏移: ${offset}`);
      return false;
    }
    return true;
  }

  /**
   * 从 PAT 包识别 PMT PID（修正版：读取第15-16字节）
   */
  identifyPMTPID(data, offset) {
    if (data.length >= offset + 20) {
      this.pmtPid = ((data[offset + 15] & 0x1F) << 8) | data[offset + 16];
      this.pmtIdentified = true;
      console.log(`识别到PMT PID: ${this.pmtPid}`);
    } else {
      console.warn('无法识别PMT PID: 数据长度不足');
    }
  }

  // ---------- 工具函数 ----------
  _mkdirp(dir) {
    try {
      fs.mkdirSync(dir, { recursive: true });
      return true;
    } catch (e) { return false; }
  }

  _safeUnlink(file, warnOnly = false) {
    if (!fs.existsSync(file)) return;
    try { fs.unlinkSync(file); }
    catch (e) {
      const msg = `清理文件失败: ${file}`;
      if (warnOnly) console.warn(msg, e);
      else console.warn(msg.replace('清理', '清理' + (warnOnly ? '' : '')), e);
    }
  }
}

module.exports = TSMerger;
