# vcs-unpack — 版本控制泄露数据解压器

CTF 中遇到 `.git` / `.svn` / `.hg` 源码泄露时，往往能直接通过目录扫描或工具下载到**压缩过的数据文件**：它们表面上是二进制乱码，实际上是 zlib / gzip 压缩后的原始文本（源码、配置、甚至 flag）。本工具自动识别格式并把它们还原成人类可读的文本。

> 一句话：把"乱码文件"变成"源码文件"。

---

## ✨ 功能特性

- **自动识别格式**，无需手动判断是 Git、SVN 还是 Mercurial
- **支持多种压缩兜底**：zlib（含魔数偏移查找）、gzip、未压缩文本
- **目录递归扫描**：一键处理整个下载下来的 `.git` / `.svn` / `.hg` 目录
- **单文件解压**：也可以只解压某一个可疑文件
- **无第三方依赖**：只用 Python 标准库，开箱即用
- **彩色终端输出**，Windows / Linux / macOS 均支持

---

## 📦 支持的格式

| 格式                     | 典型路径                            | 处理方式                |
| ---------------------- | ------------------------------- | ------------------- |
| Mercurial revlog `*.i` | `.hg/store/data/xxx.i`          | 跳过 64 字节头 + zlib 解压 |
| Mercurial revlog `*.d` | `.hg/store/data/xxx.d`          | 纯 zlib 数据段解压        |
| Git object             | `.git/objects/ab/cdef...`       | zlib 解压（含类型/长度头）    |
| SVN pristine           | `.svn/pristine/xx/xxx.svn-base` | 可能为纯文本，或带文本头        |
| 裸 zlib / gzip / 文本     | 任意                              | 自动探测兜底              |

---

## 🔧 环境要求

- Python 3.6 及以上（仅用到标准库：`sys`、`os`、`zlib`、`gzip`、`binascii`）
- **无需 `pip install` 任何额外包**

验证：

```bash
python --version
```

---

## 🚀 使用方法

### 1. 解压单个文件

```bash
python vcs-unpack.py path/to/some_file
```

结果会直接打印到终端。

### 2. 解压并输出到指定文件

```bash
python vcs-unpack.py .git/objects/ab/cdef1234... -o out.txt
```

### 3. 递归扫描整个目录（最常用）

把通过工具下载下来的 VCS 目录丢给它，自动找出并解压所有可疑文件：

```bash
python vcs-unpack.py .git
python vcs-unpack.py .svn
python vcs-unpack.py .hg
```

### 4. 解压目录并统一输出到另一个目录

```bash
python vcs-unpack.py .git -o ./decoded
```

> 输出文件名形如 `objects_ab_cdef....txt`，按原相对路径扁平化命名，方便逐个查看。

### 查看帮助

```bash
python vcs-unpack.py -h
```

---

## 🧭 典型 CTF 实战流程

本工具**负责"解压"这一步**。在这之前，你通常需要先把泄露的版本库目录下载到本地：

```bash
# 1. 用 git-dumper 把目标站的 .git 目录拖下来
git-dumper http://target.com/.git/ ./leaked_git

# 2. 用本工具还原其中的对象文件
python vcs-unpack.py ./leaked_git -o ./decoded

# 3. 在 ./decoded 里 grep flag、源码、配置文件
grep -r "flag" ./decoded
```

SVN 泄露可配合 `dvcs-ripper`（`rip-svn.pl`），Mercurial 泄露可配合 `dvcs-ripper`（`rip-hg.pl`），下载完成后再用本工具解压 `.svn-base` 与 `.i` / `.d` 文件。

---

## ⚠️ 注意事项

- 目录扫描时会**跳过** Mercurial 的一些元数据文件（`fncache`、`requires`、`branch`、`dirstate` 等），它们不是 revlog 数据。
- 解压成功的文本默认只**预览前 2000 字符**（终端打印时截断），完整内容会写入 `-o` 指定的文件。
- 如果文件本身已经是明文（例如某些 `.svn-base`），工具会原样输出，不报错。
- 输出使用 `UTF-8` 解码，`errors="replace"` 兜底，遇到非 UTF-8 编码（如 GBK）的文本可能会显示替换字符 `�`，属正常现象。

---

## 📄 License

自用 CTF 小工具，可自由修改与分享。
