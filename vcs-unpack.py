#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
版本控制泄露数据解压器 (vcs-unpack)
=====================================
CTF 中遇到 .git / .svn / .hg 源码泄露时，往往能直接下载到压缩过的数据文件，
但它们是二进制格式，打开是乱码。本工具自动识别格式并还原出原始文本。

支持的格式:
  1. Mercurial revlog   .hg/store/data/xxx.i     (64字节头 + zlib)
  2. Mercurial revlog   .hg/store/data/xxx.d     (纯 zlib 数据段)
  3. Git object         .git/objects/ab/cdef...  (zlib)
  4. SVN pristine       .svn/pristine/xx/xxx.svn-base (可能带文本头)
  5. 裸 zlib / gzip / 未压缩文本 (兜底)

用法:
  python vcs-unpack.py <文件路径>              # 解压单个文件
  python vcs-unpack.py <目录>                  # 递归解压目录下所有可疑文件
  python vcs-unpack.py <文件> -o out.txt       # 输出到指定文件
"""

import sys
import os
import zlib
import gzip
import binascii

# ---------- 颜色输出（Windows 终端也支持 ANSI） ----------
def _c(code, s):
    return f"\033[{code}m{s}\033[0m"

def ok(s):   return _c("32", s)   # 绿
def info(s): return _c("36", s)   # 青
def warn(s): return _c("33", s)   # 黄
def err(s):  return _c("31", s)   # 红
def dim(s):  return _c("90", s)   # 灰


def is_text(data: bytes, threshold=0.85):
    """粗略判断字节串是不是可读文本"""
    if not data:
        return False
    # 统计可打印字符比例
    printable = sum(1 for b in data if 9 <= b <= 13 or 32 <= b <= 126 or b >= 128)
    return printable / len(data) >= threshold


def try_decompress(data: bytes):
    """
    依次尝试各种解压方式，返回 (结果字节, 说明) 或 (None, 失败原因)
    """
    # 1. 直接就是文本（svn 的 .svn-base 常见）
    if is_text(data):
        return data, "未压缩（本身就是文本）"

    # 2. gzip（1f 8b）
    if data[:2] == b"\x1f\x8b":
        try:
            return gzip.decompress(data), "gzip"
        except Exception as e:
            pass

    # 3. 找 zlib 魔数 78 01 / 78 9c / 78 da，从该位置开始解
    for magic in (b"\x78\x9c", b"\x78\x01", b"\x78\xda"):
        idx = data.find(magic)
        if idx >= 0:
            try:
                return zlib.decompress(data[idx:]), f"zlib (偏移 {idx}, 魔数 {magic.hex()})"
            except Exception:
                pass

    # 4. 直接尝试 zlib（有些场景整体就是压缩流）
    try:
        return zlib.decompress(data), "zlib (整文件)"
    except Exception:
        pass

    return None, "无法识别/解压失败"


def unpack_file(path: str, out_path: str = None, quiet=False):
    """解压单个文件，返回 (是否成功, 结果文本)"""
    with open(path, "rb") as f:
        raw = f.read()

    if not quiet:
        print(info(f"[*] 文件: {path}  ({len(raw)} 字节)"))

    # --- 针对 Mercurial revlog .i 的特殊处理：先跳过 64 字节头再解 ---
    fname = os.path.basename(path).lower()
    result, how = None, None
    if fname.endswith(".i") and len(raw) > 64:
        try:
            result = zlib.decompress(raw[64:])
            how = "Mercurial revlog v1 (跳过 64 字节头)"
        except Exception:
            result, how = try_decompress(raw)
    else:
        result, how = try_decompress(raw)

    if result is None:
        if not quiet:
            print(warn(f"[!] 解压失败: {how}"))
        return False, None

    if not quiet:
        print(ok(f"[+] 解压成功: {how}"))

    text = result.decode("utf-8", errors="replace")
    if out_path:
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(text)
        if not quiet:
            print(ok(f"[+] 已写入: {out_path}"))
    return True, text


def scan_dir(root: str, out_dir: str = None):
    """递归扫描目录，自动处理 .i / .d / svn-base / git objects"""
    targets = []
    skip_names = {"fncache", "requires", "branch", "dirstate", "undo.branch",
                  "undo.desc", "undo.dirstate", "wcache", "phaseroots", "obsstore"}
    for dirpath, dirnames, filenames in os.walk(root):
        for fn in filenames:
            low = fn.lower()
            p = os.path.join(dirpath, fn)
            if low.endswith((".i", ".d", ".svn-base")) or fn in skip_names:
                targets.append(p)
            elif ".git" in p.replace("\\", "/") and "objects" in p.replace("\\", "/") and len(fn) in (38, 62):
                targets.append(p)  # git object 文件名是 38/62 位十六进制

    if not targets:
        print(warn("[!] 没找到可解压的数据文件"))
        return

    print(info(f"[*] 发现 {len(targets)} 个候选文件\n"))
    hit = 0
    for p in targets:
        op = None
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
            rel = os.path.relpath(p, root).replace(os.sep, "_")
            op = os.path.join(out_dir, rel + ".txt")
        success, text = unpack_file(p, op)
        if success:
            hit += 1
            print("-" * 50)
            print(text[:2000])
            if len(text) > 2000:
                print(dim(f"...(共 {len(text)} 字符，已截断)"))
            print("-" * 50)
        print()

    print(ok(f"[+] 完成：{hit}/{len(targets)} 个成功解压"))


def main():
    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help"):
        print(__doc__)
        return

    out_path = None
    if "-o" in args:
        i = args.index("-o")
        out_path = args[i + 1]
        args = args[:i] + args[i + 2:]

    target = args[0]
    if os.path.isdir(target):
        scan_dir(target, out_path)
    elif os.path.isfile(target):
        success, text = unpack_file(target, out_path)
        if success and not out_path:
            print("-" * 50)
            print(text)
            print("-" * 50)
    else:
        print(err(f"[!] 路径不存在: {target}"))


if __name__ == "__main__":
    main()
